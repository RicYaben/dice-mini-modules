from dice.module import Module, new_module
from dice.config import CLASSIFIER
from dice.query import query_db

def ethernetip_cls_init(mod: Module) -> None: 
    mod.register_label(
        "anonymous-connection",
        "allows unauthenticatied clients to communicate"
    )

def ethernetip_cls_handler(mod: Module) -> None:
    q =query_db("fingerprints", protocol="ethernetip")
    mod.itemize(q, lambda x: mod.make_label(str(x.id), "anonymous-connection"))

def make_classifier() -> Module:
    return new_module(CLASSIFIER, "ethernetip", ethernetip_cls_handler, ethernetip_cls_init)