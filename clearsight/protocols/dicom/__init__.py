from dice.modules import registry

from .classifier import dicom_classifier
from .fingerprint import dicom_fingerprinter

dicom = registry("dicom").register(dicom_classifier()).register(dicom_fingerprinter())
