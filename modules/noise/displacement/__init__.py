from dice.module import new_registry

from .aletheia import make_aletheia_module
from .bloat import make_bloated_module
from .honeypot import honeypot_reg
from .odd import odd_reg

displacement_reg = new_registry("displacement")
displacement_reg.add(
    make_aletheia_module(),
    make_bloated_module(),
)
displacement_reg.add_groups([
    honeypot_reg,
    odd_reg,
])