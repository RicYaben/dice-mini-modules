from dice.internal.modules import new_registry
from .classifier import enip_classifier
from .fingerprint import enip_fingerprinter

registry = (
    new_registry("ethernetip")
    .register(enip_classifier())
    .register(enip_fingerprinter())
)

__all__ = [
    "registry"
]