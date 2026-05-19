from dice.modules import Module, ModuleHandler, new_module
from dice.models import  Host
from dice.config import logger
from dice.query import query_db

import requests
import pandas as pd

from .helpers import Prefix, PrefixTree

API = "https://stat.ripe.net/data"
ENDPOINTS = {
    "ris": "network-info/data.json",
    "contact": "abuse-contact-finder/data.json",
    "name": "as-names/data.json",
    "prefixes": "maxmind-geo-lite-announced-by-as/data.json",
}

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

    mod.with_pbar(handler, query_db("host", prefix=""), desc="prefixes", bsize=10)

def make_asn_scn() -> ModuleHandler:
    def handler(mod: Module) -> None:
        fetch_prefixes(mod)
        #fetch_asn(mod)
    return handler

def make_asn_scanner() -> Module:
    return new_module("s", "asn", make_asn_scn())