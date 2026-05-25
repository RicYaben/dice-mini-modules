from dice.shared.repository import FRepo
from dice.shared.models import Record
from dice.sdk import Module
from dice.experimental import query


def run(repo: FRepo, *args, **kwargs) -> None:
    q = query(Record, protocol="iec104", **{"data.interrogation__ne":None})
    for r in repo.search(q):
        data = {
            "asdus": r.get("interrogation"),
            "sdt": r.get("startdt"),
            "tfr": r.get("testfr")
        }
        repo.fingerprint(r["host"], r["id"], data, protocol=r["protocol"])

def iec104_fingerprinter() -> Module:
    return (
        Module(
            "f", "iec104", 
            run_fn=run,
        )
    )