from dice.module import new_registry

# protocol cls and fps
from .ethernetip import enip_reg
from .modbus import modbus_reg
from .iec104 import iec104_reg
from .fox import fox_reg
# noise tags
from .noise import noise_registry
from .cti import cti_reg
from .ripe import ripe_reg
# cti scanners

registry = new_registry("imc-2026")
registry.add_groups([
    noise_registry,
    enip_reg,
    modbus_reg,
    iec104_reg,
    fox_reg,
    cti_reg,
    ripe_reg
])

