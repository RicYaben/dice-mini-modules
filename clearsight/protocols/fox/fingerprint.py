from dice.shared.repository import FRepo
from dice.shared.query import query
from dice.shared.models import Record
from dice.sdk import Module


def run(repo: FRepo, *args, **kwargs) -> None:
    # TODO: This means: look into records, query the db into a view,
    # normalize the json data into columns without the prefix, and query the view
    q = query(Record, protocol="fox", data={"is_fox":True, "version__ne":None})
    for r in repo.search(q):
        repo.fingerprint(r["host"], r["id"], r["data"], protocol=r["protocol"])

def fox_fingerprinter() -> Module:
    return (
        Module(
            "f", "fox", 
            run_fn=run,
        )
    )