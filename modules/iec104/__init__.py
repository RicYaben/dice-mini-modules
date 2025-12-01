from dice.module import new_registry
from .classifier import make_classifier
from .fingerprint import make_fingerprinter

iec104_reg = new_registry("iec104").add(
    make_classifier(), 
    make_fingerprinter()
)

__all__ = [
    "iec104_reg",
]