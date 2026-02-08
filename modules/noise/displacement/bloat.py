from dice.module import Module, new_module
from dice.config import TAGGER

from tdigest import TDigest
import math

def bloated_q(threshold: int | None = None) -> str:
    limit_clause = ""
    if threshold:
        # having more services than the threshold
        limit_clause = f"HAVING COUNT(DISTINCT f.port) > {threshold}"
    return """
    SELECT
        f.host,
        COUNT(DISTINCT f.port) AS fpcount,
        COUNT(DISTINCT z.port) AS zpcount,
        LIST(DISTINCT f.port) as fports,
        LIST(DISTINCT z.port) as zports,
    FROM fingerprints AS f
    LEFT JOIN records_zgrab2 AS z
        ON f.host = z.ip
    GROUP BY f.host
    {clause}
    ORDER BY zports DESC
    """.format(clause=limit_clause)

def model_host_ports(ports) -> TDigest: 
    digest = TDigest()
    for r in ports:
        digest.update(r["fpcount"])
    return digest

def bloated_tag(mod: Module) -> None:
    repo = mod.repo()
    ports = repo.query(bloated_q())

    model = model_host_ports(ports)
    # need to round, this normally will be between 1 and 5
    threshold =  int(math.ceil(model.percentile(75)))
    print(f"Threshold: {threshold}")
    
    q = bloated_q(threshold)
    mod.itemize(q, lambda x: mod.store(mod.make_tag(str(x.host), "bloated", f"has {x.zpcount} services")), orient="tuples")

def bloated_init(mod: Module) -> None:
    mod.register_tag("bloated", "Gaussian distribution of the number of ports")

def make_bloated_module() -> Module:
    return new_module(TAGGER, "bloated", bloated_tag, bloated_init)