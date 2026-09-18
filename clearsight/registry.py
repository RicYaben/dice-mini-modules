from dice.modules import registry

from .protocols import protocols

clearsight = registry("clearsight").add_groups(
    [
        protocols,
    ]
)
