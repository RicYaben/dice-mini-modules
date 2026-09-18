from dice.sdk import Module, query
from dice.shared.models import Fingerprint
from dice.shared.repository import CRepo


def run(repo: CRepo, *args, **kwargs) -> None:
    q = query(Fingerprint, protocol="iec104", asdus__ne=None)
    for r in repo.search(q):
        repo.label(r["id"], "anonymous-connection")


def iec104_classifier() -> Module:
    return Module(
        "c",
        "iec104",
        run_fn=run,
    ).add_label(
        "anonymous-connection", "allows unauthenticatied clients to communicate"
    )
