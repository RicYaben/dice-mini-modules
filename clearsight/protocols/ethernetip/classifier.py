from dice.shared.repository import CRepo
from dice.shared.models import Fingerprint
from dice.experimental import query
from dice.sdk import Module


def run(repo: CRepo, *args, **kwargs) -> None:
    q = query(Fingerprint, protocol="ethernetip", **{"data.vendor_name__ne":None})
    for r in repo.search(q):
        repo.label(r["id"], "anonymous-connection")

def enip_classifier() -> Module:
    return (
        Module(
            "c", "ethernetip", 
            run_fn=run,
        ).add_label(
            "anonymous-connection",
            "allows unauthenticatied clients to communicate"  
        )
    )