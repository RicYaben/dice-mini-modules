from dice.module import new_registry
from .scanner import make_scanners

registry = new_registry("cti").add(*make_scanners())

__all__ = [
    "registry"
]