from dice.shared.repository import CRepo
from dice.shared.models import Fingerprint
from dice.experimental import query
from dice.sdk import Module


def run(repo: CRepo, *args, **kwargs) -> None:
    q = query(Fingerprint, protocol="dicom")
    for r in repo.search(q):
        repo.label(r["id"], "anonymous-association")

        if r["echo_status"] == "AAA=":
            repo.label(r["id"], "echo-response")

def dicom_classifier() -> Module:
    return (
        Module(
            "c", "dicom", 
            run_fn=run,
        ).add_label(
            "anonymous-association",
            "allows unauthenticated clients to associate",
        ).add_label(
            "echo-response",
            "allows unauthenticated clients to send ECHO requests"
        )
    )