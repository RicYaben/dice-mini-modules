from dice.shared.repository import CRepo
from dice.shared.models import Fingerprint
from dice.experimental import query
from dice.sdk import Module


def run(repo: CRepo, *args, **kwargs) -> None:
    q = query(
        Fingerprint,
        protocol="modbus",
        **{
            "data.vendor__ne": None,
            "data.product_code__ne": None,
            "data.revision__ne": None
        }
    )

    for r in repo.search(q):
        repo.label(r["id"], "anonymous-connection")


def modbus_classifier() -> Module:
    return Module(
        "c", "modbus",
        run_fn=run,
    ).add_label(
        "anonymous-connection", "allows unauthenticatied clients to communicate"
    )
