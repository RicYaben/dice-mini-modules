import base64
from dice.module import make_fp_handler, Module, new_module
from dice.config import FINGERPRINTER
from dice.helpers import get_record_field 

def fingerprint(row) -> dict | None:
    assoc = get_record_field(row, "association", None)
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

    if echo:=get_record_field(row, "echo", None):
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

dicom_fp_handler = make_fp_handler(fingerprint, "DICOM")

def make_fingerprinter() -> Module:
    return new_module(FINGERPRINTER, "DICOM", dicom_fp_handler)