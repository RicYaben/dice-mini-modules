from dice.module import Module, new_module
from dice.config import CLASSIFIER
from dice.query import query_db
import pandas as pd

def dicom_cls_init(mod: Module) -> None:
    mod.register_label(
        "anonymous-association",
        "allows unauthenticated clients to associate",
    )
    mod.register_label(
        "echo-response",
        "allows unauthenticated clients to send ECHO requests"
    )

def dicom_cls_handler(mod: Module) -> None:
    def handler(row: pd.Series):
        fid = row["id"]
        if row["data_uid"] or row["data_version"]:
            mod.store(mod.make_label(fid, "anonymous-association"))
        if row["data_echo"]:
            mod.store(mod.make_label(fid, "echo-response"))

    q = query_db("fingerprints", protocol="DICOM")
    mod.itemize(q, handler, orient="rows")

def make_classifier() -> Module:
    return new_module(CLASSIFIER, "DICOM", dicom_cls_handler, dicom_cls_init)