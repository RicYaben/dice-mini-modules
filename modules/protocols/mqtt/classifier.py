from dice.module import Module, new_module
from dice.config import CLASSIFIER
from dice.query import query_db
import pandas as pd

def mqtt_cls_init(mod: Module) -> None:
    mod.register_label(
        "anonymous-connection",
        "allows unauthenticated clients to associate",
    )
    mod.register_label(
        "self-signed-certificate",
        "allows anonymous clients to connect using a self-signed certificate"
    )
    mod.register_label(
        "read-topics",
        "allows anonymous clients subscribing to arbitrary topics"
    )
    mod.register_label(
        "internal-topics",
        "allows anonymous clients subscribing to internal topics"
    )

def mqtt_cls_handler(mod: Module) -> None:
    def handler(row: pd.Series):
        fid = row["id"]
        if topics := row.get("data_topics", []):
            mod.store(mod.make_label(fid, "read-topics"))

            for t, _ in topics:
                if t.startswith("$SYS/"):
                    mod.store(mod.make_label(fid, "internal-topics"))
                    break

    q = query_db("fingerprints", protocol="mqtt")
    mod.itemize(q, handler, orient="rows")

def make_classifier() -> Module:
    return new_module(CLASSIFIER, "mqtt", mqtt_cls_handler, mqtt_cls_init)