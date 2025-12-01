import pandas as pd

from typing import Generator

from dice.module import Module, new_module, new_registry, ModuleHandler
from dice.query import query_db
from dice.config import TAGGER

def tag_hp(gen: Generator[pd.DataFrame, None, None], filt, mod: Module, hp: str) -> None:
    for b in gen:
        tags = []
        for fp in filt(b).itertuples(index=False):
            tag = mod.make_tag(getattr(fp,"host"), "honeypot", hp, getattr(fp,"protocol"), getattr(fp,"port"))
            tags.append(tag)
        mod.save(*tags)

def conpot_iec104(df: pd.DataFrame) -> pd.DataFrame:
    def in_tid_cas(tid: int, cas: list[int]):
        """
        Check ASDUs 100 with system description, by defalt conpot gives some addresses
        Conpot responds in CA=0xFFFF (65536)
        TypeID=C_IC_NA_1
        COT=7
        CA=(1,3,5,7,9,11,13)
        """
        def filt(asdu: dict):
            t = asdu["TypeID"]
            cot = asdu["Cause"]
            ca = asdu["CA"]
            return (tid == t) and (cot == 7) and (ca in cas)

        return filt

    def all_asdus(asdus:list[dict], tid: int, cas: list[int]):
        c = []
        c.extend(filter(in_tid_cas(tid, cas), asdus))
        return len(c) >= len(cas)

    tid100_cas = [1,3,11,13]
    return df[
        df["asdus"].apply(lambda a: all_asdus(a, 100, tid100_cas)).notna()
        or
        df["startdf"].str.contains("680e00000000") # gas what
    ]

def conpot_enip(df: pd.DataFrame) -> pd.DataFrame:
    return df[df["serial_number"] == "7079450"]

def conpot_modbus(df: pd.DataFrame) -> pd.DataFrame:
    """
    Check for the default modbus template. T-Pot uses the same config
    Vendor name: Siemens 
    Product code: SIMATIC 
    Revision: S7-200
    """ 
    return df[
        df["vendor"] =="Siemens" and 
        df["product_code"] == "SIMATIC" and 
        df["revision"] == "S7-200"
    ]

def honeygrove_modbus(df: pd.DataFrame) -> pd.DataFrame:
    'https://github.com/UHH-ISS/honeygrove/blob/master/honeygrove/config.py'
    return df[
        df["vendor"] == "Siemens" and
        df["product_code"] == "S935" and
        df["revision"] == "4.2.4"
    ]

def honeypot_init(mod: Module) -> None:
    mod.register_tag("honeypot", "Honeypot fingerprint")

def make_hp_handler(p: str, filt, hp: str) -> ModuleHandler:
    def handler(mod: Module) -> None:
        _, gen = mod.repo().queryb(query_db("fingerprints", protocol=p))
        tag_hp(gen, filt, mod, hp)
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