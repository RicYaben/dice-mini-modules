from dice.shared.repository import CRepo
from dice.shared.models import Fingerprint
from dice.experimental import query
from dice.sdk import Module


def run(repo: CRepo, *args, **kwargs) -> None:
    q = query(Fingerprint, protocol="mqtt")
    for r in repo.search(q):
        repo.label(r["id"], "read-topics")
        if next(filter(lambda x: x.startswith("$SYS/") ,r["topics"]), None):
            repo.label(r["id"], "internal-topics")

def mqtt_classifier() -> Module:
    return (
        Module("c","mqtt",run_fn=run)
        .add_label(
            "anonymous-connection", 
            "allows unauthenticated clients to associate"
        ).add_label(
            "self-signed-certificate",
            "allows anonymous clients to connect using a self-signed certificate"
        ).add_label(
            "read-topics",
            "allows anonymous clients subscribing to arbitrary topics"
        ).add_label(
            "internal-topics",
            "allows anonymous clients subscribing to internal topics"
        )
    )