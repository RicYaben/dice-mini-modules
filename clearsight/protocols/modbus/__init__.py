from dice.modules import registry

from .classifier import modbus_classifier
from .fingerprint import modbus_fingerprinter

modbus = (
    registry("modbus").register(modbus_classifier()).register(modbus_fingerprinter())
)
