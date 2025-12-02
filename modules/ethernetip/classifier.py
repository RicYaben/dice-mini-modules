from dice.module import Module, new_module
from dice.config import CLASSIFIER
from dice.query import query_db

def ethernetip_cls_init(mod: Module) -> None: 
    mod.register_label(
        "anonymous-connection",
        "allows unauthenticatied clients to communicate"
    )

def ethernetip_cls_handler(mod: Module) -> None:
    def handle(row):
        items = row.get("data_items", []) 
        if isinstance(items, list):
            for it in items:
                if "vendor_name" in it:
                    mod.store(mod.make_label(row["id"], "anonymous-connection"))

    q =query_db("fingerprints", protocol="ethernetip")
    mod.itemize(q, handle, orient="rows")

def make_classifier() -> Module:
    return new_module(CLASSIFIER, "ethernetip", ethernetip_cls_handler, ethernetip_cls_init)