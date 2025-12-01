from dice.module import new_registry
from .classifier import make_classifier
from .fingerprint import make_fingerprinter

fox_reg = new_registry("fox").add(
    make_classifier(), 
    make_fingerprinter()
)

__all__ = [
    "fox_reg"
]