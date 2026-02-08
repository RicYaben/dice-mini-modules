from dice.module import make_fp_handler, Module, new_module
from dice.config import FINGERPRINTER
from dice.helpers import get_record_field

from packaging.version import parse, InvalidVersion

class Broker:
    name: str
    version: str
    cpe: str
    topics: list[tuple[str, list[str]]]

def get_hub(topics: list[tuple[str, list[str]]]) -> Broker | None:
    hub = Broker()
    for topic, msgs in topics:
        msg = msgs[0] # first message
        match topic:
            case _ if topic.endswith("/sysdescr"):
                hub.name = msg
            case _ if topic.endswith("/version"):
                hub.version = msg

        if hub.name and hub.version:
            return hub
        
def get_broker(topics: list[tuple[str, list[str]]]) -> Broker | None:
    broker = Broker()
    for topic, msgs in topics:
        match topic:
            case "$SYS/brokers":
                if hub := get_hub(topics):
                    return hub
            
            case s if s.startswith("$SYS/VerneMQ"):
                broker.name = "VerneMQ"
                broker.cpe = "cpe:2.3:a:octavolabs:vernemq:*:*:*:*:*:*:*:*"
                return broker
            
            case s if s.startswith(("$SYS/ActiveMQ", "ActiveMQ/")):
                broker.name = "ActiveMQ"
                broker.cpe = "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*"
                return broker
            
            case "$SYS/broker/version":
                v = msgs[0] if msgs else ""

                if "mosquito" in v:
                    broker.name = "mosquitto"
                    broker.version = str(parse(v.split("mosquitto version")[1]))
                    broker.cpe = "cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*"
                    return broker
                
                b = v.split("version")
                broker.name = v
                try:
                    pv = parse(b[-1])
                    broker.version = str(pv)
                    broker.name = b[0]
                except InvalidVersion:
                    pass
                return broker    
                    

def fingerprint(row) -> dict | None:
    # check if we connected at all or the broker refused
    # the communication

    if broker := get_broker((topics:=get_record_field(row, "topics", []))):
        broker.topics = topics
        return broker.__dict__

mqtt_fp_handler = make_fp_handler(fingerprint, "mqtt")

def make_fingerprinter() -> Module:
    return new_module(FINGERPRINTER, "mqtt", mqtt_fp_handler)