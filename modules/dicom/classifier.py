from dice.module import Module, new_module
from dice.config import CLASSIFIER
from dice.query import query_db

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
    q = query_db("fingerprints", protocol="dicom")
    def handler(row):
        fid = str(row.id)
        if row.get("data_uid") or row.get("data_version"):
            mod.store(mod.make_label(fid, "anonymous-connection"))
        if row.get("data_echo"):
            mod.store(mod.make_label(fid, "echo-response"))

    mod.itemize(q, handler, orient="tuples")

def make_classifier() -> Module:
    return new_module(CLASSIFIER, "dicom", dicom_cls_handler, dicom_cls_init)