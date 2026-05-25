from dice.internal.modules import new_registry
from .classifier import mqtt_classifier
from .fingerprint import mqtt_fingerprinter

registry = (
    new_registry("mqtt")
    .register(mqtt_classifier())
    .register(mqtt_fingerprinter())
)

__all__ = [
    "registry"
]