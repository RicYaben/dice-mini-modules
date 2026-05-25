from dice.internal.modules import new_registry
from .classifier import modbus_classifier
from .fingerprint import modbus_fingerprinter

registry = (new_registry("modbus")
    .register(modbus_classifier())
    .register(modbus_fingerprinter())
)

__all__ = [
    "registry",
]