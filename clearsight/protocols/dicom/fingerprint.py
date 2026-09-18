import base64

import ujson
from dice.sdk import Module, query
from dice.shared.models import Record
from dice.shared.repository import FRepo


def fingerprint(row) -> dict | None:
    drow = row.get("data")
    drow = ujson.loads(drow)
    assoc = drow.get("association")

    # At this point we already know the server "speaks" dicom.
    msg = assoc.get("Msg")
    data = {
        # TODO: missing probe status
        "response": assoc.get("Header").get("PDUType"),
        "calling": msg.get("CallingAETitle"),
        "called": msg.get("CalledAETitle"),
        "echo_status": None,
        "uid": None,
        "version": None,
        "probe_status": drow.get("status"),
    }

    if (echo := drow.get("echo", None)) and (echo_msg := echo.get("Msg", None)):
        for cmd in echo_msg.get("Commands"):
            if cmd.get("ElementTag") == 0x900:
                data["echo_status"] = cmd.get("Value")

    # if not type 0x50 (80) the ufo is bad, so we dont care
    if (uinfo := msg.get("UserInfo")) and uinfo.get("Type") == 80:
        p_ufo = {}
        for i in uinfo.get("Items", []):
            match i.get("Type"):
                case 82:  # x52 (82) = Implementation Class UID Sub-item
                    p_ufo["uid"] = base64.b64decode(i.get("Value")).decode("utf-8")
                case 85:  # x55 (85) = Implementation Version Name Sub-item
                    p_ufo["version"] = (
                        base64.b64decode(i.get("Value"))
                        .decode("utf-8")
                        .split("\\u0000", 1)[0]
                    )

        data["uid"] = p_ufo.get("uid")
        data["version"] = p_ufo.get("version")

    return data


def run(repo: FRepo, *args, **kwargs) -> None:
    q = query(Record, None, protocol="DICOM", **{"data.association__ne": None})
    for r in repo.search(q):
        if data := fingerprint(r):
            repo.fingerprint(r["host"], r["id"], data, protocol=r["protocol"])


# class DicomFlags(Flags):
#     services: str = flag("services.csv", "Path to CSV containing services info")


def dicom_fingerprinter() -> Module:
    return Module(
        "f",
        "dicom",
        # flags=DicomFlags,
        run_fn=run,
    )
