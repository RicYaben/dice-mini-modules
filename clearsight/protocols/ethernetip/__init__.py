from dice.modules import registry

from .classifier import enip_classifier
from .fingerprint import enip_fingerprinter

ethernetip = (
    registry("ethernetip").register(enip_classifier()).register(enip_fingerprinter())
)
