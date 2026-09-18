import base64
from base64 import b64decode
from dataclasses import asdict, dataclass
from enum import IntEnum

import ujson
from dice.sdk import Module, query
from dice.shared.models import Record
from dice.shared.repository import FRepo
from sqlalchemy import RowMapping


class DicomStatus(IntEnum):
    description: str

    def __new__(cls, value: int, description: str):
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.description = description
        return obj

    @classmethod
    def from_base64(cls, value: str) -> "DicomStatus | int":
        code = int.from_bytes(b64decode(value), byteorder="big")

        try:
            return cls(code)
        except ValueError:
            return code

    @property
    def binary(self) -> str:
        return f"{self.value:016b}"

    @property
    def hex(self) -> str:
        return f"0x{self.value:04X}"

    def __str__(self) -> str:
        return self.description


class CEchoStatus(DicomStatus):
    SUCCESS = 0x0000, "Success"
    SOP_CLASS_NOT_SUPPORTED = 0x0122, "SOP Class not supported"
    DUPLICATE_INVOCATION = 0x0210, "Duplicate invocation"
    UNRECOGNIZED_OPERATION = 0x0211, "Unrecognized operation"
    MISTYPED_ARGUMENT = 0x0212, "Mistyped argument"


class CFindStatus(DicomStatus):
    SUCCESS = 0x0000, "Success"
    PENDING = 0xFF00, "Pending"
    PENDING_WARNING = 0xFF01, "Pending Warning"
    CANCEL = 0xFE00, "Cancel"
    OUT_OF_RESOURCES = 0xA700, "Refused: Out of resources"
    DATASET_DOES_NOT_MATCH_SOP_CLASS = (
        0xA900,
        "Dataset does not match SOP Class",
    )


@dataclass
class Response:
    response: str | None = None
    status: str | None = None


@dataclass
class Association(Response):
    calling: str | None = None
    called: str | None = None
    impl_uid: str | None = None
    impl_version: str | None = None


@dataclass
class Echo(Response):
    pass


@dataclass
class Find(Response):
    pass


@dataclass
class Fingerprint:
    status: str | None = None
    association: Association | None = None
    echo: Echo | None = None
    find: Find | None = None


def response(header: dict | None, msg: dict | None) -> Response:
    res = Response()
    if header:
        res.response = header.get("PDUType", None)

    if msg:
        for cmd in msg.get("Commands", []):
            if cmd.get("element_tag") == 2304:  # 0x900
                status = (
                    base64.b64decode(cmd.get("value"))
                    .decode("utf-8", errors="ignore")
                    .split("\\u0000", 1)[0]
                )
                res.status = status

    return res


def generic[T: Response, R: DicomStatus](
    model: type[T], data: dict, status: type[R]
) -> T:
    head = data.get("Header", None)
    msg = data.get("Msg", None)

    rsp = response(head, msg)
    if rsp.status is not None:
        rsp.status = str(status.from_base64(rsp.status))
    return model(**asdict(rsp))


def echo(data: dict) -> Echo:
    return generic(Echo, data, CEchoStatus)


def find(data: dict) -> Find:
    return generic(Find, data, CFindStatus)


def association(data: dict) -> Association:
    head = data.get("Header", None)
    msg = data.get("Msg", None)

    base = response(head, msg)
    assoc = Association(
        response=base.response,
        status=base.status,
    )

    if not msg:
        return assoc

    assoc.calling = msg.get("CallingAETitle", None)
    assoc.called = msg.get("CalledAETitle", None)
    for item in msg.get("UserInfo", {}).get("Items", []):
        match item.get("Type"):
            case 82:  # x52 (82) = Implementation Class UID Sub-item
                assoc.impl_uid = base64.b64decode(item.get("Value")).decode("utf-8")
            case 85:  # x55 (85) = Implementation Version Name Sub-item
                assoc.impl_version = (
                    base64.b64decode(item.get("Value"))
                    .decode("utf-8")
                    .split("\\u0000", 1)[0]
                )

    return assoc


def fingerprint(row: RowMapping) -> dict | None:
    drow = row.get("data", {})
    if not drow:
        return

    drow = ujson.loads(drow)
    resps = drow.get("responses")

    fp = Fingerprint(status=drow.get("status"))
    for rsp in resps:
        data = rsp.get("data", [None])[0]
        if not data:
            continue

        match rsp.get("command"):
            case "associate":
                fp.association = association(data)
            case "echo":
                fp.echo = echo(data)
            case "find":
                fp.find = find(data)
    return asdict(fp)


def run(repo: FRepo, *args, **kwargs) -> None:
    clauses = {
        "data.responses[0].data__ne": None,
        "data.responses[0].command": "associate",
    }

    q = query(
        Record,
        None,
        protocol="dicom",
        **clauses,
    )
    for r in repo.search(q):
        if data := fingerprint(r):
            repo.fingerprint(r["host"], r["id"], data, protocol="dicom")


# class DicomFlags(Flags):
#     services: str = flag("services.csv", "Path to CSV containing services info")


def dicom_fingerprinter() -> Module:
    return Module(
        "f",
        "dicom",
        # flags=DicomFlags,
        run_fn=run,
    )
