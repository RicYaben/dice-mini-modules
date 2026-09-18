import math

from dice.sdk import Module
from dice.shared.models import Fingerprint, Record
from dice.shared.repository import TRepo
from sqlalchemy import distinct, func
from sqlmodel import exists, literal_column, select
from tdigest import TDigest


def bloated_q(threshold: int | None = None):
    f = Fingerprint
    r = Record

    pcount = func.count(distinct(r.port)).label("pcount")
    ports = func.group_concat(distinct(r.port)).label("ports")

    has_fingerprint = exists(select(1).where(f.record_id == r.id))

    stmt = (
        select(
            r.host,
            pcount,
            ports,
        )
        .select_from(r)
        .where(has_fingerprint)
        .group_by(r.host)
        .order_by(pcount.desc())
    )

    if threshold is not None:
        stmt = stmt.having(pcount > literal_column(str(threshold)))

    return stmt


def model_host_ports(ports) -> TDigest:
    digest = TDigest()
    for r in ports:
        digest.update(r["pcount"])
    return digest


def bloated_tag(repo: TRepo, *args, **kwargs) -> None:
    ports = repo.search(str(bloated_q()))
    model = model_host_ports(ports)

    # need to round, this normally will be between 1 and 5
    threshold = int(math.ceil(model.percentile(75)))
    print(f"Threshold: {threshold}")

    q = bloated_q(threshold)
    for r in repo.search(str(q)):
        repo.tag(r["host"], "bloated", f"has {r.pcount} services")


def bloated_module() -> Module:
    return Module(
        "t",
        "bloated",
        run_fn=bloated_tag,
    ).add_tag("bloated", "Gaussian distribution of the number of ports")
