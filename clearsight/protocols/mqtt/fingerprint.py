from copy import copy
from packaging.version import parse, InvalidVersion

import logging
import csv

from dice.shared.repository import FRepo
from dice.shared.models import Record
from dice.experimental import query

from dice.sdk import Module, Service, Flags, flag

def get_hub(topics: list[tuple[str, list[str]]]) -> Service | None:
    hub = Service("", None, None, None)
    for topic, msgs in topics:
        msg = msgs[0]  # first message
        match topic:
            case _ if topic.endswith("/sysdescr"):
                hub.name = msg
            case _ if topic.endswith("/version"):
                hub.version = msg

        if hub.name and hub.version:
            return hub


def identify(topics: list[tuple[str, list[str]]], brokers: dict[str, Service]) -> Service | None:
    for topic, msgs in topics:
        match topic:
            case "$SYS/brokers":
                return get_hub(topics)

            case s if s.startswith("$SYS/VerneMQ"):
                if b:=brokers["vernemq"]:
                    return copy(b)

            case s if s.startswith(("$SYS/ActiveMQ", "ActiveMQ/")):
                if b:= brokers["activemq"]:
                    return copy(b)

            case "$SYS/broker/version":
                v = msgs[0] if msgs else ""

                if "mosquito" in v and (b:=brokers["mosquitto"]):
                    b = copy(b)
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
            
def load_brokers(fpath: str) -> dict[str, Service]:
    srvs = {}
    with open(fpath, newline='') as csvfile:
        r = csv.reader(csvfile)
        headers = next(r, None)
        if not headers:
            return srvs
        
        for row in r:
            row = dict(zip(headers, row))
            s = Service(**row)
            srvs[s.name] = s
    return srvs

class MqttFlags(Flags):
    brokers: str = flag("brokers.csv", "fpath to CSV with brokers info")

def run(repo: FRepo, flags: MqttFlags, logger: logging.Logger) -> None:
    brokers = load_brokers(flags.brokers)

    q = query(Record, protocol="mqtt", **{"data.topics__ne": None})
    for r in repo.search(q):
        data = {
            "access": ["read"],
            "authentication": (
                "anonymous" if r.get("scheme") == "tcp" else "self-signed-certificate"
            ),
            "topics": r["topics"]
        }

        if s := identify(r["topics"], brokers):
            data["service"] = s.__dict__

        repo.fingerprint(r["host"], r["id"], data, protocol=r["protocol"])

def mqtt_fingerprinter() -> Module:
    return (
        Module(
            "f", "mqtt",
            flags=MqttFlags, 
            run_fn=run,
        )
    )