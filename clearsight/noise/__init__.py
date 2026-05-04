from dice.modules import new_registry

from .condensation import condensation_reg
from .displacement import displacement_reg
from .hostility import hostility_reg
from .volatility import volatility_reg

registry = new_registry("noise")
registry.add_groups([
    displacement_reg,
    volatility_reg,
    hostility_reg,
    condensation_reg
])

__all__ = [
    "registry"
]