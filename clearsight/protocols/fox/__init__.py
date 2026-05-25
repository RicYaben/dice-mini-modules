from dice.internal.modules import new_registry
from .classifier import fox_classifier
from .fingerprint import fox_fingerprinter

registry = (
    new_registry("fox")
    .register(fox_classifier()) 
    .register(fox_fingerprinter())
)

__all__ = [
    "registry"
]