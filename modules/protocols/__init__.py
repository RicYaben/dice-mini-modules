from dice.module import new_registry

from .ethernetip import registry as enip_reg
from .modbus import registry as modbus_reg
from .iec104 import registry as iec104_reg
from .fox import registry as fox_reg

registry = new_registry("protocols")
registry.add_groups([
    enip_reg,
    modbus_reg,
    iec104_reg,
    fox_reg,
])

__all__ = [
    "registry"
]