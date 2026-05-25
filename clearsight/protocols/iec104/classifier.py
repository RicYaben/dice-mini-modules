from dice.shared.repository import CRepo
from dice.shared.query import query
from dice.sdk import Module
from dice.shared.models import Fingerprint


def run(repo: CRepo, *args, **kwargs) -> None:
    q = query(Fingerprint, protocol="iec104", asdus__ne=None)
    for r in repo.search(q):
        repo.label(r["id"], "anonymous-connection")

def iec104_classifier() -> Module:
    return (
        Module(
            "c", "iec104", 
            run_fn=run,
        ).add_label(
            "anonymous-connection",
            "allows unauthenticatied clients to communicate"
        )
    )