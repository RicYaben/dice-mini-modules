from dice.sdk import Labels, Module, label, query
from dice.shared.models import Fingerprint
from dice.shared.repository import CRepo


class MqttLabels(Labels):
    anon_con = label(
        "anonymous-connection", "allows unauthenticated clients to associate"
    )
    ssc = label(
        "self-signed-certificate",
        "allows anonymous clients to connect using a self-signed certificate",
    )
    rtopics = label(
        "read-topics", "allows anonymous clients subscribing to arbitrary topics"
    )
    itopics = label(
        "internal-topics", "allows anonymous clients subscribing to internal topics"
    )


def run(repo: CRepo, *args, **kwargs) -> None:
    q = query(Fingerprint, protocol="mqtt")
    for r in repo.search(q):
        repo.label(r["id"], MqttLabels.rtopics)
        if next(filter(lambda x: x.startswith("$SYS/"), r["topics"]), None):
            repo.label(r["id"], MqttLabels.itopics)


def mqtt_classifier() -> Module:
    return Module("c", "mqtt", run_fn=run, labels=MqttLabels)
