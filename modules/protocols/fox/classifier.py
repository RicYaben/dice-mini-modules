from dice.module import Module, new_module
from dice.config import CLASSIFIER
from dice.query import query_db

def fox_cls_init(mod: Module) -> None:
    mod.register_label(
        "anonymous-connection",
        "allows unauthenticatied clients to communicate"
    )

def fox_cls_handler(mod: Module) -> None:
    q = query_db("fingerprints", protocol="fox")
    mod.itemize(q, lambda x: mod.store(mod.make_label(str(x.id), "anonymous-connection")), orient="tuples")

def make_classifier() -> Module:
    return new_module(CLASSIFIER, "fox", fox_cls_handler, fox_cls_init)