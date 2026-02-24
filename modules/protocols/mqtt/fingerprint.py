from copy import copy
from dice.module import make_fp_handler, Module, new_module
from dice.config import FINGERPRINTER
from dice.helpers import get_record_field
from dice.records import Service

from packaging.version import parse, InvalidVersion

import pandas as pd

BROKERS: dict[str, Service] = {
    "vernemq": Service(
        name="VerneMQ", 
        vendor="Octabolabs", 
        cpe="cpe:2.3:a:octavolabs:vernemq:*:*:*:*:*:*:*:*",
        version=None,
    ),
    "mosquitto": Service(
        name="Mosquitto", 
        vendor="Eclipse", 
        cpe="cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*", 
        version=None
    ),
    "activemq": Service(
        name="ActiveMQ",
        vendor="Apache",
        cpe="cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*",
        version=None
    ),

}

def get_hub(topics: list[tuple[str, list[str]]]) -> Service | None:
    hub = Service("", None, None, None)
    for topic, msgs in topics:
        msg = msgs[0] # first message
        match topic:
            case _ if topic.endswith("/sysdescr"):
                hub.name = msg
            case _ if topic.endswith("/version"):
                hub.version = msg

        if hub.name and hub.version:
            return hub
        
def get_broker(topics: list[tuple[str, list[str]]]) -> Service | None:
    for topic, msgs in topics:
        match topic:
            case "$SYS/brokers":
                return get_hub(topics)
            
            case s if s.startswith("$SYS/VerneMQ"):
                return copy(BROKERS["vernemq"])
            
            case s if s.startswith(("$SYS/ActiveMQ", "ActiveMQ/")):
                return copy(BROKERS["activemq"])
            
            case "$SYS/broker/version":
                v = msgs[0] if msgs else ""

                if "mosquito" in v:
                    b = copy(BROKERS["mosquitto"])
                    b.version = str(parse(v.split("mosquitto version")[1]))
                    return b
                
                bversion = v.split("version")
                pv = None
                try:
                    pv = parse(bversion[-1])
                except InvalidVersion:
                    pass

                broker = Service(
                    name=bversion[0] if pv else v,
                    version=str(pv) if pv else None,
                    vendor=None,
                    cpe=None,
                )
                return broker    
                    

def fingerprint(row: pd.Series) -> dict | None:
    # check if we connected at all or the broker refused
    # the communication
    topics=get_record_field(row, "topics", [])
    if not topics:
        return
    
    data = {
        "access": ["read"],
        "authentication": "anonymous" if row.get("scheme") == "tcp" else "self-signed-certificate",
    }
    
    if broker := get_broker(topics):
        data["topics"] = topics
        data["service"] = broker.__dict__

mqtt_fp_handler = make_fp_handler(fingerprint, "mqtt")

def make_fingerprinter() -> Module:
    return new_module(FINGERPRINTER, "mqtt", mqtt_fp_handler)