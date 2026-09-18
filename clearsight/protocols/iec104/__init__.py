from dice.modules import registry

from .classifier import iec104_classifier
from .fingerprint import iec104_fingerprinter

iec104 = (
    registry("iec104").register(iec104_classifier()).register(iec104_fingerprinter())
)
