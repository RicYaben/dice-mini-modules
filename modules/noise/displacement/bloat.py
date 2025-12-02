from dice.query import query_serv_ports
from dice.module import Module, new_module
from dice.config import TAGGER

from tdigest import TDigest
import math

def model_host_ports(ports) -> TDigest: 
    digest = TDigest()
    for r in ports:
        digest.update(r["fpcount"])
    return digest

def bloated_tag(mod: Module) -> None:
    repo = mod.repo()
    ports = repo.query(query_serv_ports())

    model = model_host_ports(ports)
    # need to round, this normally will be between 1 and 5
    threshold =  int(math.ceil(model.percentile(95)))
    
    q = query_serv_ports(threshold)
    mod.itemize(q, lambda x: mod.store(mod.make_tag(str(x.host), "bloated", f"{x.zpcount} ports open")), orient="tuples")

def bloated_init(mod: Module) -> None:
    mod.register_tag("bloated", "Gaussian distribution of the number of ports")

def make_bloated_module() -> Module:
    return new_module(TAGGER, "bloated", bloated_tag, bloated_init)