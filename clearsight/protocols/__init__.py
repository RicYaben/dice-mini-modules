from dice.modules import registry

from .dicom import dicom
from .fox import fox
from .iec104 import iec104
from .modbus import modbus

protocols = registry("protocols").add_groups(
    [
        dicom,
        modbus,
        iec104,
        fox,
    ]
)
