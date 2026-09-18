from dice.modules import registry

from .bloat import bloated_module

# from .aletheia import make_aletheia_module
# from .honeypot import honeypot_reg
# from .odd import odd_reg

displacement = registry("displacement").register(bloated_module())
