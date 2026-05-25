import base64

from dice.shared.repository import FRepo
from dice.shared.models import Record
from dice.experimental import query
from dice.sdk import Module


def fingerprint(row) -> dict | None:
    assoc = row.get("association", None)
    # bad response
    if not assoc:
        return
    
    # At this point we already know the server "speaks" dicom. 
    msg = assoc.get("Msg")
    data = {
        "response": assoc.get("Header").get("PDUType"),
        "calling": msg.get("CallingAETitle"),
        "called": msg.get("CalledAETitle"),
        "echo_status": None,
        "uid": None,
        "version": None
    }

    if echo:=row.get("echo", None):
        for cmd in echo.get("Msg").get("Commands"):
            if cmd.get("ElementTag") == 0x900:
                data["echo_status"] = cmd.get("Value")

    # if not type 0x50 (80) the ufo is bad, so we dont care
    if (uinfo := msg.get("UserInfo")) and uinfo.get("Type") == 80:
        p_ufo = {}
        for i in uinfo.get("Items", []):
            match i.get("Type"):
                case 82: # x52 (82) = Implementation Class UID Sub-item
                    p_ufo["uid"] = base64.b64decode(i.get("Value")).decode("utf-8")
                case 85: # x55 (85) = Implementation Version Name Sub-item
                    p_ufo["version"] = base64.b64decode(i.get("Value")).decode("utf-8").split("\\u0000", 1)[0]

        data["uid"] = p_ufo.get("uid")
        data["version"] = p_ufo.get("version")
    
    return data

# class DicomFlags(Flags):
#     services: str = flag("services.csv", "Path to CSV containing services info")

def run(repo: FRepo, *args, **kwargs) -> None:
    q = query(Record, protocol="dicom")
    for r in repo.search(q):
        if data:=fingerprint(r):
            repo.fingerprint(r["host"], r["id"], data, protocol=r["protocol"])

def dicom_fingerprintetr() -> Module:
    return (
        Module(
            "f", "dicom",
            #flags=DicomFlags,
            run_fn=run,
        )
    )

