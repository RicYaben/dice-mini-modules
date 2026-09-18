from dice.modules import registry

from .classifier import fox_classifier
from .fingerprint import fox_fingerprinter

fox = registry("fox").register(fox_classifier()).register(fox_fingerprinter())
