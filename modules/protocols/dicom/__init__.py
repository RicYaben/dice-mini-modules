from dice.module import new_registry
from .classifier import make_classifier
from .fingerprint import make_fingerprinter

registry = new_registry("dicom").add(
    make_classifier(), 
    make_fingerprinter()
)

__all__ = [
    "registry"
]