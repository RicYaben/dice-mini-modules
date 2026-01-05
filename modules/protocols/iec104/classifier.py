from dice.module import Module, new_module
from dice.config import CLASSIFIER
from dice.query import query_db
import pandas as pd

def iec104_cls_init(mod: Module) -> None:
    mod.register_label(
        "anonymous-connection",
        "allows unauthenticatied clients to communicate"
    )

def iec104_cls_handler(mod: Module) -> None:
    def handler(df: pd.DataFrame):
        for fp in df[df["data_asdus"].notna()].itertuples(index=False):
            mod.store(mod.make_label(str(fp.id), "anonymous-connection"))

    q = query_db("fingerprints", protocol="iec104")
    mod.itemize(q, handler, orient="dataframe")


def make_classifier() -> Module:
    return new_module(CLASSIFIER, "iec104", iec104_cls_handler, iec104_cls_init)