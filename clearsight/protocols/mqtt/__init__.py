from dice.modules import registry

from .classifier import mqtt_classifier
from .fingerprint import mqtt_fingerprinter

mqtt = registry("mqtt").register(mqtt_classifier()).register(mqtt_fingerprinter())
