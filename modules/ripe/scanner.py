from dice.module import Module, ModuleHandler, new_module
from dice.models import  Host
from dice.config import logger
from dice.query import query_db
from dice.config import SCANNER
from dice.store import OnConflict

import ujson
import ipaddress
import requests
import pandas as pd

from .models import AutonomousSystem, Prefix, Resource
from .query import query_prefixes
from .helpers import PrefixTree, build_prefix_tree, build_resource_tree, flatten_resources

API = "https://stat.ripe.net/data"
ENDPOINTS = {
    "ris": "network-info/data.json",
    "contact": "abuse-contact-finder/data.json",
    "name": "as-names/data.json",
    "prefixes": "maxmind-geo-lite-announced-by-as/data.json",
}

# TODO: This is not very good.
# - the hosts db already has prefix and asn
# 1. gather the prefixes and make a tree
# 2. gather all the hosts without prefix
# 3. update hosts with their new prefix and asn

# def get_asn_name(asn: str) -> str:
#     p = {"resource": asn}
#     try:
#         res = requests.get("/".join([API, ENDPOINTS["name"]]), params=p).json()
#         return res["data"]["names"][asn]
#     except Exception as e:
#         logger.warning(f"failed to get ans info ({asn}): {e}")
#         return ""

# def get_asn_contacts(asn: str) -> list[str]:
#     p = {"resource": asn}
#     try:
#         res = requests.get("/".join([API, ENDPOINTS["contact"]]), params=p).json()
#         return res["data"].get("abuse_contacts", [])
#     except Exception as e:
#         logger.warning(f"failed to get abuse contacts ({asn}): {e}")
#         return []

# def get_asn_resources(asn: str) -> list[Resource]:
#     p = {"data_overload_limit": "ignore", "resource": asn}
#     try:
#         res = requests.get("/".join([API, ENDPOINTS["prefixes"]]), params=p).json()
#     except Exception as e:
#         logger.warning(f"failed to get resources ({asn}): {e}")
#         return []
    
#     resources = []
#     for pf in res["data"].get("located_resources"):
#         res = pf.get("resource")
#         if isinstance(ipaddress.ip_network(res), ipaddress.IPv6Network):
#             continue # dont care about IPv6

#         res = [make_resource(asn, res, loc) for loc in pf.get("locations")]
#         resources.extend(res)
#     return resources

# def new_resource(asn: str, resource: str, prefixes: list[str], city: str, country: str, longitude: str, latitude: str) -> Resource:
#     return Resource(asn, resource, prefixes, country, city, latitude, longitude)
    
# def make_resource(asn: str, resource: str, loc: dict) -> Resource:
#     return new_resource(
#         asn, resource,
#         prefixes=loc.get("resources", []),
#         city=loc.get("city", ""),
#         country=loc.get("country", ""),
#         longitude=loc.get("longitude", ""),
#         latitude=loc.get("latitude", ""),
#     )

# def new_asn(num: str, name: str, contacts: list[str]) -> AutonomousSystem:
#     return AutonomousSystem(num, name, contacts)

# def make_asn(asn: str) -> AutonomousSystem:
#     return new_asn(
#         asn, 
#         name=get_asn_name(asn),
#         contacts=get_asn_contacts(asn),
#     )

# def fetch_asn(mod: Module):
#     def handler(df: pd.DataFrame):
#         for row in df.itertuples():
#             asn = str(row.asn)
#             as_model = make_asn(asn)
#             mod.store(as_model)

#             res = get_asn_resources(asn)
#             mod.store(res)

#             logger.debug(f"done fetching asn {asn}")

#     mod.with_pbar(handler, query_db("prefixes"), desc="asns", bsize=10)

def get_ris(addr: str) -> dict | None:
    p = {"resource": addr}
    try:
        data = requests.get("/".join([API, ENDPOINTS["ris"]]), params=p).json()
        return data["data"]
    except Exception as e:
        logger.warning(f"failed to fetch ip {addr} info: {e}")

def fetch_ris(addr: str) -> Prefix | None:
    'returns basic AS info from an address'
    if net_info := get_ris(addr):
        asn_d = net_info.get("asns", [None])
        prefix = net_info.get("prefix", None)
        if asn_d and (asn:=asn_d[0]) and prefix:
            return Prefix(
                prefix = prefix,
                asn = asn,
            )

def fetch_prefixes(mod: Module):
    tree = PrefixTree()
    for host in mod.query(query_db("hosts", prefix__ne="")):
        tree.add(host["prefix"], Prefix(host["prefix"], host["asn"]))

    mod.set_store_policy(OnConflict.UPDATE)
    def handler(df: pd.DataFrame):
        for _, host in df.iterrows():
            ip = host["ip"]

            prefix = tree.get(ip)
            if not prefix:
                prefix = fetch_ris(ip)
                if not prefix:
                    continue
                tree.add(prefix.prefix, prefix)

            host["prefix"] = prefix.prefix
            host["asn"] = prefix.asn
            mod.store(Host.from_series(host))

    mod.with_pbar(handler, query_db("hosts", prefix=""), desc="prefixes", bsize=10)

def make_asn_scn() -> ModuleHandler:
    def handler(mod: Module) -> None:
        fetch_prefixes(mod)
        #fetch_asn(mod)
    return handler

def make_asn_scanner() -> Module:
    return new_module(SCANNER, "asn", make_asn_scn())

def update_hosts(mod: Module) -> None:
    mod.set_store_policy(OnConflict.UPSERT)
    repo = mod.repo()

    # Gather resources and build tree
    resources = repo.get_records(normalize=True, source="resources")
    resources["prefixes"] = resources["prefixes"].apply(ujson.loads)

    flat = flatten_resources(resources)
    tree = build_resource_tree(flat)

    def handler(df: pd.DataFrame) -> None:
        for _,host in df.iterrows():
            if info := tree.get(host["ip"]):
                host["prefix"] = info.get("prefix")
                host["asn"] = info.get("asn")
                mod.store(Host.from_series(host))

    # only hosts without prefix
    mod.with_pbar(handler, query_db("hosts", prefix=""))

def make_hosts_scn() -> ModuleHandler:
    def handler(mod: Module) -> None:
        update_hosts(mod)
    return handler

def make_hosts_scanner() -> Module:
    return new_module(SCANNER, "hosts", make_hosts_scn())