from dice.models import Model
from dataclasses import dataclass

@dataclass
class AutonomousSystem(Model):
    asn: str
    name: str
    contacts: list[str]

    @classmethod
    def primary_key(cls):
        return ("asn",)
    
    @classmethod
    def table(cls) -> str:
        return "asns"

@dataclass
class Resource(Model):
    # AS number
    asn: str
    # prefix resource
    resource: str
    # all the rest of resources in this location
    prefixes: list[str]
    country: str
    city: str
    latitude: str
    longitude: str

    @classmethod
    def primary_key(cls):
        return ("asn", "resource")
    
    @classmethod
    def table(cls) -> str:
        return "resources"
    
@dataclass
class Prefix(Model):
    prefix: str
    asn: str

    @classmethod
    def primary_key(cls):
        return ("asn", "prefix")
    
    @classmethod
    def table(cls) -> str:
        return "prefixes"