from dice.module import new_registry

from modules.noise.condensation import condensation_reg
from modules.noise.displacement import displacement_reg
from modules.noise.hostility import hostility_reg
from modules.noise.volatility import volatility_reg

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