from dice.module import new_registry
from .classifier import make_classifier
from .fingerprint import make_fingerprinter

enip_reg = new_registry("ethernetip").add(
    make_classifier(), 
    make_fingerprinter()
)

__all__ = [
    "enip_reg"
]