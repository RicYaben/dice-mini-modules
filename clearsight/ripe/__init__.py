from .scanner import  make_asn_scanner

from dice.modules import new_registry

registry = new_registry("ripe").add(
    make_asn_scanner(),
)

__all__ = [
    "registry"
]