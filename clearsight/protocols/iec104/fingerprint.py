from dice.modules import Module, new_module, make_fp_handler
from dice.helpers import get_record_field
from dice.config import FINGERPRINTER
import pandas as pd

def fingerprint(row: pd.Series) -> dict | None:
    sdt = get_record_field(row, "startdt")
    tfr = get_record_field(row, "testfr")
    asdus = get_record_field(row, "interrogation", [])
    if len(asdus):
        return dict(
            asdus=asdus,
            sdt=sdt,
            tfr=tfr
        )

iec104_fp_handler = make_fp_handler(fingerprint, "iec104")

def make_fingerprinter() -> Module:
    return new_module(FINGERPRINTER, "iec104", iec104_fp_handler)