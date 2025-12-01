from dice.module import new_registry
from .classifier import make_classifier
from .fingerprint import make_fingerprinter

modbus_reg = new_registry("modbus").add(
    make_classifier(), 
    make_fingerprinter()
)

__all__ = [
    "modbus_reg",
]