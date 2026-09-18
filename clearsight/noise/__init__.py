from dice.modules import registry

from .condensation import condensation
from .displacement import displacement
from .hostility import hostility

# from .volatility import volatility_reg

noise = registry("noise").add_groups(
    [
        displacement,
        # volatility_reg,
        hostility,
        condensation,
    ]
)
