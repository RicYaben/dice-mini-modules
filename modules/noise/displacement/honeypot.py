import pandas as pd

from dice.module import Module, new_module, new_registry, ModuleHandler
from dice.query import query_db
from dice.config import TAGGER

def conpot_iec104(df: pd.DataFrame) -> pd.DataFrame:
    def in_tid_cas(tid: int, cas: list[int]):
        """Filter function for TypeID, Cause, and CA"""
        def filt(asdu: dict):
            t = asdu.get("TypeID")
            cot = asdu.get("Cause")
            ca = asdu.get("CA")
            return (tid == t) and (cot == 7) and (ca in cas)
        return filt

    def all_asdus(asdus: list[dict], tid: int, cas: list[int]):
        c = list(filter(in_tid_cas(tid, cas), asdus))
        return len(c) >= len(cas)

    tid100_cas = [1, 3, 11, 13]

    # Boolean Series for each condition
    cond1 = df["data_asdus"].apply(lambda a: all_asdus(a, 100, tid100_cas))
    cond2 = df["data_sdt"].str.contains("680e00000000", na=False)

    return df[cond1 | cond2]

def conpot_enip(df: pd.DataFrame) -> pd.DataFrame:
    serial = "7079450"
    items_filled = df["data_items"].apply(lambda x: x if isinstance(x, list) else [])

    # Create a temporary Series where each row is exploded into multiple dicts
    exploded = items_filled.explode()

    # Mask: check dicts for matching serial_number
    mask = exploded.apply(lambda d: d.get("serial") == serial if isinstance(d, dict) else False)

    # Group back by original index, keep rows where any exploded item matched
    matched_index = mask.groupby(mask.index).any()
    return df[matched_index]

def conpot_modbus(df: pd.DataFrame) -> pd.DataFrame:
    """
    Check for the default modbus template. T-Pot uses the same config
    Vendor name: Siemens 
    Product code: SIMATIC 
    Revision: S7-200
    """ 
    mask = (
            (df["data_vendor"].eq("Siemens")) &
            (df["data_product_code"].eq("SIMATIC")) &
            (df["data_revision"].eq("S7-200"))
        )
    return df[mask]

def honeygrove_modbus(df: pd.DataFrame) -> pd.DataFrame:
    'https://github.com/UHH-ISS/honeygrove/blob/master/honeygrove/config.py'
    mask = (
        (df["data_vendor"].eq("Siemens")) &
        (df["data_product_code"].eq("S935")) &
        (df["data_revision"].eq("4.2.4"))
    )
    return df[mask]

def honeypot_init(mod: Module) -> None:
    mod.register_tag("honeypot", "Honeypot fingerprint")

def make_hp_handler(p: str, filt, hp: str) -> ModuleHandler:
    def handler(mod: Module) -> None:
        def itemize(b):
            for fp in filt(b).itertuples(index=False):
                mod.store(mod.make_tag(getattr(fp,"host"), "honeypot", hp, getattr(fp,"protocol"), getattr(fp,"port")))
        q = query_db("fingerprints", protocol=p)
        mod.itemize(q, itemize, orient="dataframe")
    return handler

conpot_reg = new_registry("conpot")
conpot_reg.add(
    *[
        new_module(TAGGER, p, make_hp_handler(p, filt, "conpot"), honeypot_init)
        for p, filt in [("iec104", conpot_iec104), ("ethernetip", conpot_enip), ("modbus", conpot_modbus)]
    ]
)

honeygrove_reg = new_registry("honeygrove")
honeygrove_reg.add(
    new_module(TAGGER, "modbus", make_hp_handler("modbus", honeygrove_modbus, "honeygrove"), honeypot_init)
)

honeypot_reg = new_registry("honeypot")
honeypot_reg.add_groups([
    conpot_reg,
    honeygrove_reg
])