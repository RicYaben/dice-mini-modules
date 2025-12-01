from dice.query import query_serv_ports
from dice.module import Module, new_module
from dice.config import TAGGER

from tdigest import TDigest
import pandas as pd

def model_host_ports(ports) -> TDigest: 
    digest = TDigest()
    for r in ports:
        digest.update(r["fpcount"])
    return digest

def bloated_tag(mod: Module) -> None:
    repo = mod.repo()
    ports = repo.query(query_serv_ports())

    model = model_host_ports(ports)
    threshold =  model.percentile(95)
    def h(df: pd.DataFrame) -> None:
        tags = []
        for r in df.itertuples(index=False):
            tags.append(mod.make_tag(str(r.ip), "bloated"))
        mod.save(*tags)
    mod.with_pbar(h, query_serv_ports(zpcount__gt=threshold))

def bloated_init(mod: Module) -> None:
    mod.register_tag("bloated", "Gaussian distribution of the number of ports")

def make_bloated_module() -> Module:
    return new_module(TAGGER, "bloated", bloated_tag, bloated_init)