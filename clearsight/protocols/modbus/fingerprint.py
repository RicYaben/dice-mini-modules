from dice.shared.repository import FRepo
from dice.shared.models import Record
from dice.experimental import query
from dice.sdk import Module


def run(repo: FRepo, *args, **kwargs) -> None:
    q = query(Record, data={"data.mei_response__ne":None}, protocol="modbus")

    for r in repo.search(q):
        mei = r["mei_response"]
        objects = mei.pop("objects", {})
        data = {**mei, **objects, "unit_id": r.get("unit_id", 0)}
        repo.fingerprint(r["host"], r["id"], data, protocol=r["protocol"])

def modbus_fingerprinter() -> Module:
    return (
        Module(
            "f", "modbus", 
            run_fn=run,
        )
    )