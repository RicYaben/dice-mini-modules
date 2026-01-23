import base64
from dice.module import make_fp_handler, Module, new_module
from dice.config import FINGERPRINTER
from dice.helpers import get_record_field 

def fingerprint(row) -> dict | None:
    assoc = get_record_field(row, "association", None)
    # bad response
    if not assoc:
        return
    
    msg = assoc.get("Msg")
    uinfo = msg.get("UserInfo")
    if not uinfo:
        return

    # if not type 0x50 (80) the ufo is bad
    if uinfo.get("Type") != 80:
        return
    
    p_ufo = {}
    for i in uinfo.get("Items", []):
        match i.get("Type"):
            case 82: # x52 (82) = Implementation Class UID Sub-item
                p_ufo["uid"] = base64.b64decode(i.get("Value")).decode("utf-8")
            case 85: # x55 (85) = Implementation Version Name Sub-item
                p_ufo["version"] = base64.b64decode(i.get("Value")).decode("utf-8").split("\\u0000", 1)[0]
                break
    
    data = {
        "response": assoc.get("Header").get("PDUType"),
        "client": msg.get("CallingAETitle"),
        "viewer": msg.get("CalledAETitle"),
        "uid":p_ufo.get("uid"),
        "version": p_ufo.get("version"),
        "echo": row.get("data_echo") is not None
    }
    return data

dicom_fp_handler = make_fp_handler(fingerprint, "DICOM")

def make_fingerprinter() -> Module:
    return new_module(FINGERPRINTER, "DICOM", dicom_fp_handler)