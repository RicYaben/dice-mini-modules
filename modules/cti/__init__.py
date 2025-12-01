from dice.module import new_registry
from .scanner import make_scanners

cti_reg = new_registry("cti").add(*make_scanners())

__all__ = [
    "cti_reg"
]