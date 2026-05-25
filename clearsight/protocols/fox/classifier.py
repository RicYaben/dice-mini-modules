from dice.shared.repository import CRepo

from dice.sdk import Module
from dice.shared.query import query
from dice.shared.models import Fingerprint

def run(repo: CRepo, *args, **kwargs) -> None:
    q = query(Fingerprint, protocol="fox")
    for r in repo.search(q):
        repo.label( r["id"], "anonymous-connection")

def fox_classifier() -> Module:
    return (
        Module(
            "c", "fox", 
            run_fn=run,
        ).add_label(
            "anonymous-connection",
            "allows unauthenticatied clients to communicate"
        )
    )