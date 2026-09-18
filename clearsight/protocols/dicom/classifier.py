from dice.sdk import Module, query
from dice.shared.models import Fingerprint
from dice.shared.repository import CRepo


def run(repo: CRepo, *args, **kwargs) -> None:
    q = query(Fingerprint, protocol="dicom")
    for r in repo.search(q):
        repo.label(r["id"], "anonymous-association")

    q2 = query(Fingerprint, None, protocol="dicom", **{"data.echo.status": "Success"})
    for r in repo.search(q2):
        repo.label(r["id"], "echo-response")

    cfind = query(
        Fingerprint,
        None,
        protocol="dicom",
        **{"data.find.status__in": ["Success", "Pending", "Warning"]},
    )
    for r in repo.search(cfind):
        repo.label(r["id"], "find-response")


def dicom_classifier() -> Module:
    return (
        Module(
            "c",
            "dicom",
            run_fn=run,
        )
        .add_label(
            "anonymous-association",
            "allows unauthenticated clients to associate",
        )
        .add_label(
            "echo-response", "allows unauthenticated clients to send ECHO requests"
        )
        .add_label("find-response", "allows unauthenticated clients to query records")
    )
