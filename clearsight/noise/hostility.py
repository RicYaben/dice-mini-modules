import logging

from dice.internal.modules import new_registry
from dice.shared.repository import SearchResult, TRepo
from dice.shared.models import Fingerprint
from dice.experimental import query
from dice.sdk import Module, Flags, flag
from tdigest import TDigest

def cut(res: SearchResult, col: str, t: int, minimum: int = 0) -> int:
    digest = TDigest()
    for r in res:
        r.update(r["col"])
    thresh = digest.percentile(t)
    if thresh < minimum:
        thresh = minimum
    req = digest.percentile(thresh)
    return req

class TFlags(Flags):
    percentile: int = flag(95, "percentile to set threshold on the number of objects returned to consider a service hostile")
    minimum: int = flag(5, "minimum number of objects over the percentile")

def iec104_run(repo: TRepo, flags: TFlags, logger: logging.Logger) -> None:
    q = """
    SELECT
        host,
        protocol,
        port,
        COUNT(DISTINCT ioa) AS cioas36
    FROM (
        SELECT
            f.host,
            f.protocol,
            f.port,
            json_extract(ioa.value, '$') AS ioa
        FROM fingerprint f
        -- explode asdus[]
        CROSS JOIN json_each(json_extract(f.data, '$.asdus')) AS asdus
        -- explode asdus[].IOAs[]
        CROSS JOIN json_each(json_extract(asdus.value, '$.IOAs')) AS ioa
        WHERE f.protocol = 'iec104'
        AND json_extract(asdus.value, '$.TypeID') = 36
    )
    GROUP BY host, protocol, port
    """

    res = repo.search(q)
    req = cut(res, "cioas36", flags.percentile, flags.minimum)

    for r in repo.search(q):
        if len(r["cioas36"]) > req:
            repo.tag(r["ip"], "tarpit", "IEC-104 tarpit")

def modbus_run(repo: TRepo, flags: TFlags, logger: logging.Logger) -> None:
    q = query(Fingerprint, protocol="modbus")
    res = repo.search(q)
    req = cut(res, "objects", flags.percentile, flags.minimum)

    for r in res:
        if len(r["objects"]) > req:
            repo.tag(r["ip"], "tarpit", "Modbus tarpit")

ttag = (
    "tarpit",
    "Determines whether a service is a tarpit by picking lengthy connections with abnormally large amounts of data",
)

tarpit_reg = new_registry("tarpit").register(
    Module("t", "modbus", run_fn=modbus_run, flags=TFlags)
    .add_tag(*ttag)
).register(
    Module("t", "iec104", run_fn=iec104_run, flags=TFlags)
    .add_tag(*ttag)
)

hostility_reg = new_registry("hostility").add_group(tarpit_reg)
