from dice.module import Module, new_module, new_registry
from dice.config import TAGGER

from tdigest import TDigest


def is_timeout(fp) -> bool:
    return fp["probe_status"] == "io-timeout" and fp["data"]


def iec_tarpit(mod: Module) -> None:
    "Calculate the distribution of IOAs and return when crosses the 95prc"

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
        FROM fingerprints f
        -- explode asdus[]
        CROSS JOIN json_each(json_extract(f.data, '$.asdus')) AS asdus
        -- explode asdus[].IOAs[]
        CROSS JOIN json_each(json_extract(asdus.value, '$.IOAs')) AS ioa
        WHERE f.protocol = 'iec104'
        AND json_extract(asdus.value, '$.TypeID') = 36
    )
    GROUP BY host, protocol, port
    """

    digest = TDigest()
    for r in mod.repo().query(q):
        digest.update(r["cioas36"])

    threshold = digest.percentile(95)

    def ev(fp) -> None:
        # If it timed out and the number of IOAs with type 36 (M_ME_TF_1), a measured value with timestamp
        # is very large, then flag this
        if fp["cioas36"] > threshold:
            tag = mod.make_fp_tag(fp, "tarpit", "too many IOAs")
            mod.store(tag)
    mod.itemize(q, ev, orient="rows")


def modbus_tarpit(mod: Module) -> None:
    "Too many objects in the mei response"

    q = """
        WITH extracted AS (
        SELECT
            f.host,
            f.protocol,
            f.port,
            CAST(json_extract(f.data, '$.objects') AS JSON) AS objects,
            CAST(json_extract(f.data, '$.more_follows') AS BOOLEAN) AS more_follows
        FROM fingerprints f
        WHERE f.protocol = 'modbus'
    )
    SELECT DISTINCT(host), protocol, port, COUNT(*) AS count
    FROM extracted
    WHERE more_follows = TRUE
    GROUP BY host, protocol, port, objects
    ORDER BY count DESC
    """

    digest = TDigest()
    for r in mod.repo().query(q):
        digest.update(r["count"])
    threshold = digest.percentile(95)
    # 5 is the minimum required objects in the
    # mei response
    MIN_REQUIRED = 5
    if threshold < MIN_REQUIRED:
        threshold = MIN_REQUIRED

    def ev(fp) -> None:
        if fp["count"] > threshold:
            tag = mod.make_tag(fp, "tarpit", "too many objects. More follows")
            mod.store(tag)
    mod.itemize(q, ev, orient="rows")

def tarpit_init(mod: Module) -> None:
    mod.register_tag(
        "tarpit",
        "Determines whether a service is a tarpit by picking lengthy connections with abnormally large amounts of data",
    )

tarpit_reg = new_registry("tarpit").add(
    new_module(TAGGER, "modbus", modbus_tarpit, tarpit_init),
    new_module(TAGGER, "iec104", iec_tarpit, tarpit_init)
)

hostility_reg = new_registry("hostility").add_group(tarpit_reg)
