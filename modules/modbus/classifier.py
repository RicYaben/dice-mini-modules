from dice.module import Module, new_module
from dice.config import CLASSIFIER
from dice.query import query_db
import pandas as pd

def modbus_cls_init(mod: Module) -> None:
    mod.register_label(
        "anonymous-connection",
        "allows unauthenticatied clients to communicate"
    )

def modbus_cls_handler(mod: Module) -> None:
    cols = ["data_vendor", "data_product_code", "data_revision"]
    def handler(df: pd.DataFrame) -> None:
        mask = df[cols].notna() & (df[cols] != "")
        mask = mask.any(axis=1)

        for fp in df[mask].itertuples(index=False):
            mod.store(mod.make_label(str(fp.id), "anonymous-connection"))
            
    q = query_db("fingerprints", protocol="modbus")
    mod.itemize(q, handler, orient="dataframe")

def make_classifier() -> Module:
    return new_module(CLASSIFIER, "modbus", modbus_cls_handler, modbus_cls_init)