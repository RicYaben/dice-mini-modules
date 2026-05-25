# TODO: the SDK should have a registry, and even various types of registries. 
# E.g., one that requires an API token from the config to load modules
from dice.internal.modules import new_registry
from .classifier import iec104_classifier
from .fingerprint import iec104_fingerprinter

registry = (
    new_registry("iec104")
    .register(iec104_classifier()) 
    .register(iec104_fingerprinter())
)

__all__ = [
    "registry",
]