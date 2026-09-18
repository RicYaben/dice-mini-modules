from dice.modules import registry
from dice.sdk import Module, query
from dice.shared.models import Fingerprint
from dice.shared.repository import CRepo


def enip_odd(mod: Module) -> None:
    q_serial = """
    WITH extracted AS (
        SELECT
            f.host,
            f.port,
            f.protocol,
            CAST(j.value AS BIGINT) AS serial
        FROM fingerprint f,
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
            mod.store(
                mod.make_tag(
                    str(fp.host), "odd", "0 serial", str(fp.protocol), int(fp.port)
                )
            )
            return
        mod.store(
            mod.make_tag(
                str(fp.host),
                "odd",
                f"reused {fp.count}",
                str(fp.protocol),
                int(fp.port),
            )
        )

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

    q = query_db("fingerprint", protocol="iec104")
    mod.with_pbar(handler, q)


def dicom_odd(repo: CRepo, *args, **kwargs) -> None:
    q_echo = query(
        Fingerprint,
        protocol="dicom",
        **{"data_uid": "1.2.3.4.5", "data_version": "ZGRAB2"},
    )
    for r in repo.search(q_echo):
        repo.label(r["id"], "echo")

    q_mal1 = query(Fingerprint, protocol="dicom", **{"data_response__in": [2, 3, 7]})
    for r in repo.search(q_mal1):
        repo.label(r["id"], "mal1")

    q_mal2 = query(
        Fingerprint, protocol="dicom", **{"data_uid": None, "data_response": 2}
    )
    for r in repo.search(q_mal2):
        repo.label(r["id"], "mal2")


def odd_iec104() -> Module:
    return Module(
        "c",
        "iec104",
        run_fn=odd_iec104,
    ).add_label("odd", "Tags suspicious properties, e.g., reused serial number")


def odd_enip() -> Module:
    return Module(
        "c",
        "ethernetip",
        run_fn=odd_enip,
    ).add_label("odd", "Tags suspicious properties, e.g., reused serial number")


def odd_dicom() -> Module:
    return (
        Module(
            "c",
            "dicom",
            run_fn=odd_dicom,
        )
        .add_label("echo", "Echoed parameters")
        .add_label("mal1", "Unexpected PDU Type")
        .add_label("mal2", "Malformed response")
    )


odd_reg = (
    registry("odd").register(odd_iec104()).register(odd_enip()).register(odd_dicom())
)
