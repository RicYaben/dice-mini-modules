from dice.module import Module, new_registry, new_module
from dice.models import HostTag
from dice.query import query_db
from dice.config import TAGGER

import pandas as pd


def enip_odd(mod: Module) -> None:
    q_serial = """
    WITH extracted AS (
        SELECT
            f.host,
            f.port,
            f.protocol,
            CAST(j.value AS BIGINT) AS serial
        FROM fingerprints f,
            json_tree(f.data, '$.items') AS j
        WHERE f.protocol = 'ethernetip'
        AND j.key = 'serial'
        AND j.value IS NOT NULL
    ),
    counts AS (
        SELECT
            serial,
            COUNT(*) AS count
        FROM extracted
        GROUP BY serial
        HAVING COUNT(*) > 1 OR serial = 0
    )
    SELECT DISTINCT(e.host), e.serial, c.count, e.port, e.protocol
    FROM extracted e
    JOIN counts c USING (serial)
    ORDER BY c.count DESC, e.serial
    """
    def it(fp):
        if int(fp.serial) == 0:
            mod.store(mod.make_tag(str(fp.host), "odd", "0 serial", str(fp.protocol), int(fp.port)))
            return
        mod.store(mod.make_tag(str(fp.host), "odd", f"reused {fp.count}", str(fp.protocol), int(fp.port)))
    mod.itemize(q_serial, it, orient="tuples")


def iec_odd(mod: Module) -> None:
    """
    Flags 2 behaviors:
    - contains type 100 for CAs 1,2, and 10 (the ones scan for normally)
    - same IOA responds multiple times with the same value
    """
    # TODO: this should be an argument. Others may scan differently
    scanned = [1, 2, 10]
    def f100(asdu):
        return asdu["TypeID"] == 100 and asdu["CA"] in scanned
    def f36(asdu):
        return asdu["TypeID"] == 36

    def ev(fp) -> HostTag | None:
        ioas = {}
        if asdus := fp.get("data_interrogation", []):
            if len(set(filter(f100, asdus))) >= int(len(scanned) * 0.75):
                return mod.make_tag(
                    fp["host"],
                    "odd",
                    "too many filled addresses",
                    fp["protocol"],
                    fp["port"],
                )

            for asdu in list(filter(f36, asdus)):
                for ioa in asdu.get("IOAs", []):
                    addr = ioa["Address"]
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
                        fp["port"],
                    )

    def handler(df: pd.DataFrame) -> None:
        for _, fp in df.iterrows():
            if tag := ev(fp):
                mod.store(tag)

    q = query_db("fingerprints", protocol="iec104")
    mod.with_pbar(handler, q)

def dicom_odd(mod: Module) -> None:
    'Some echo honeypot that returns the Impl. Class UID and version as we sent it'
    def handler(df: pd.DataFrame) -> None:
        mask_echo = (
            (df["data_uid"].eq("1.2.3.4.5")) |
            (df["data_version"].eq("ZGRAB2"))
        )
        echo_rsp = df[mask_echo]
        for _, fp in echo_rsp.iterrows():
            mod.store(mod.make_fp_tag(
                fp, 
                "echo", 
                "same UserInfo"
            ))

        # 2 and 3 are accept and reject assoc responses
        # 7 is abort PDU
        mal_rsp = df[~df["data_response"].isin((2,3,7))]
        for _, fp in mal_rsp.iterrows():
            mod.store(mod.make_fp_tag(
                fp, 
                "mal1", 
                f"PDUType not ASSOC RSP, RJ, or abort: {fp['data_response']}"
            ))

        # malformed accepted associations: missing UID
        mal_rsp2 = df[(
            df["data_uid"].isna() &
            df["data_response"].eq(2)
        )]
        for _, fp in mal_rsp2.iterrows():
            mod.store(mod.make_fp_tag(
                fp, 
                "mal2", 
                "Association accepted, but Implementation UID missing"
            ))

    q = query_db("fingerprints", protocol="DICOM")
    mod.with_pbar(handler, q, desc="dicom-odd")


def odd_init(mod: Module) -> None:
    mod.register_tag("odd", "Tags suspicious properties, e.g., reused serial number")
    mod.register_tag("echo", "Echoed parameters")
    mod.register_tag("mal1", "Unexpected PDU Type")
    mod.register_tag("mal2", "Malformed response")

def make_odd_dicom_module() -> Module:
    return new_module(TAGGER, "dicom", dicom_odd, odd_init)

def make_odd_iec104_module() -> Module:
    return new_module(TAGGER, "iec104", iec_odd, odd_init)


def make_odd_enip_module() -> Module:
    return new_module(TAGGER, "ethernetip", enip_odd, odd_init)


odd_reg = new_registry("odd").add(make_odd_iec104_module(), make_odd_enip_module(), make_odd_dicom_module())
