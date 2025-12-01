from .scanner import  make_hosts_scanner, make_asn_scanner
from .fingerprint import make_asn_fp_module

from dice.module import new_registry

ripe_reg = new_registry("ripe").add(
    make_hosts_scanner(),
    make_asn_scanner(),
    make_asn_fp_module()
)

__all__ = [
    "ripe_reg"
]