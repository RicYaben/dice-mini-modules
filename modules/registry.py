from dice.module import new_registry

# protocol cls and fps
from .protocols import registry as proto_reg
# noise tags
from .noise import registry as noise_registry
from .cti import registry as cti_reg
from .ripe import registry as ripe_reg

registry = new_registry("modules")
registry.add_groups([
    noise_registry,
    cti_reg,
    ripe_reg,
    proto_reg
])

