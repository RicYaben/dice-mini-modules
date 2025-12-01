from dice.module import Module, new_registry, new_module
from dice.models import HostTag
from dice.query import query_db
from dice.config import TAGGER

import pandas as pd

def enip_odd(mod: Module) -> None:
    # TODO: needs a fix to get the serial number, which is in items, and not always
    q_serial = """
        SELECT f.serial, COUNT(f.serial) AS count
        FROM fingerprints as f
        WHERE f.protocol == 'ethernetip'
            AND count > 1
        GROUP BY f.serial;
    """
    for fp in mod.query(q_serial):
        tag = mod.make_tag(
            fp["host"], 
            "odd", 
           "reused serial",
            fp["protocol"],
            fp["port"]
        )
        mod.store(tag)

def iec_odd(mod: Module) -> None:
    """
    Flags 2 behaviors:
    - contains type 100 for CAs 1,2, and 10 (the ones scan for normally)
    - same IOA responds multiple times with the same value
    """
    # TODO: this should be an argument. Others may scan differently
    scanned = [1,2,10]
    f100 = lambda asdu: asdu["TypeID"] == 100 and asdu["CA"] in scanned
    f36 = lambda asdu: asdu["TypeID"] == 36

    def ev(fp) -> HostTag | None:
        ioas = {}
        if asdus := fp.get("data_interrogation", []):
            if len(set(filter(f100, asdus))) >= int(len(scanned)*.75):
                return mod.make_tag(
                        fp["host"], 
                        "odd", 
                        "too many filled addresses",
                        fp["protocol"],
                        fp["port"]
                    )

            for asdu in list(filter(f36, asdus)):
                for ioa in asdu.get("IOAs", []):
                    addr=ioa["Address"]
                    if addr not in ioas:
                        ioa[addr] = []
                    
                    v = ioa["Data"]
                    if v not in ioa[addr]:
                        ioa[addr].append(v)
                        continue

                    return mod.make_tag(
                        fp["host"], 
                        "odd", 
                        f'IOA responds multiple times with the same value+timestamp: {addr} "{v}"', 
                        fp["protocol"],
                        fp["port"]
                    )
                
    def handler(df: pd.DataFrame) -> None:
        for _, fp in df.iterrows():
            if tag := ev(fp): mod.store(tag)
    
    q = query_db("fingerprints", protocol="iec104")
    mod.with_pbar(handler, q)

def odd_init(mod: Module) -> None:
     mod.register_tag("odd", "Tags suspicious properties, e.g., reused serial number")

def make_odd_iec104_module() -> Module:
    return new_module(TAGGER, "iec104", iec_odd, odd_init)

def make_odd_enip_module() -> Module:
    return new_module(TAGGER, "ethernetip", enip_odd, odd_init)

odd_reg = new_registry("odd").add(
    make_odd_iec104_module(),
    make_odd_enip_module()
)