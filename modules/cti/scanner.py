from dice.module import Module, ModuleHandler, new_module
from dice.models import Source
from dice.helpers import new_source
from dice.loaders import with_records
from dice.config import SCANNER

from typing import Callable
from shodan import Shodan
from greynoise.api import GreyNoise, APIConfig

import requests
import os
import ujson

CENSYS_API = "https://api.platform.censys.io/v3"
CENSYS_ENDPOINTS = {
    "multiple":"global/asset/host"
}
IPINFO_API = "https://api.ipinfo.io"
IPINFO_ENDPOINTS = {
    "batch": "batch"
}

type CTIScannerHandler = Callable[[str, list[str]], Source]
type CTIScanner = Callable[[str, list[str]], list[dict]]

def greynoise_lookup(api: GreyNoise, *hosts: str, quick: bool = False) -> list[dict]:
    try:
        response = api.quick(list(hosts)) if quick else api.quick(list(hosts))
        return response
    except Exception as e:
        print(f'failed to query GreyNoise: {e}')
        return []

def fetch_greynoise(api: GreyNoise, *hosts: str) -> list[dict]:
    def filter_malicious(response: dict) -> bool:
        intel = response.get("internet_scanner_intelligence", {})
        return intel["found"] and (intel["classification"] in ["malicious", "suspicious"])
    res = greynoise_lookup(api, *hosts, quick=True)
    return list(filter(filter_malicious, res))

def fetch_shodan(api: Shodan, host: str) -> dict:
    try:
        # NOTE: the api suggests they accept bulk requests
        # for multiple hosts. Doesn't work tho, it only accepts
        # one. Is very bad.
        response = api.host(host)
        return response
    except Exception as e:
        print(f'failed to query shodan for host {host}: {e}')
        return {}

def fetch_censys(api_key: str, *hosts: str) -> dict:
    headers = {
        "accept": "application/vnd.censys.api.v3.host.v1+json",
        "content-type": "application/json",
        "authorization": api_key,
    }
    payload = {"host_ids": hosts}
    url = os.path.join(CENSYS_API, CENSYS_ENDPOINTS["multiple"])

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()["data"]
    except Exception as e:
        print(f"failed to fetch censys hosts: {e}")
        return {}
    
def fetch_ipinfo(api_key: str, *host: str) -> dict:
    headers = {
        "token": api_key,
        "content-type": "application/json",
    }
    payload = {"data": ujson.dumps(host)}
    url = os.path.join(IPINFO_API, IPINFO_ENDPOINTS["batch"])
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()["data"]
    except Exception as e:
        print(f"failed to fetch ipinfo hosts: {e}")
        return {}


def shodan_scanner(api_key: str, hosts: list[str]) -> list[dict]:
    client = Shodan(api_key)
    return [r for h in hosts if (r:= fetch_shodan(client, h))]

def censys_scanner(api_key: str, hosts: list[str]) -> list[dict]:
    return [r for h in hosts if (r:= fetch_censys(api_key, h))]

def greynoise_scanner(api_key: str, hosts: list[str]) -> list[dict]:
    api_config = APIConfig(api_key=api_key, integration_name="sdk-sample")
    client = GreyNoise(api_config)
    return fetch_greynoise(client, *hosts)

def ipinfo_scanner(api_key: str, hosts: list[str], batch_size: int = 1000) -> list[dict]:
    results: list[dict] = []

    for i in range(0, len(hosts), batch_size):
        batch = hosts[i:i + batch_size]
        results.extend(r for r in fetch_ipinfo(api_key, *batch) if r)

    return results

def wrap_scanner(name: str,  scanner: CTIScanner) -> CTIScannerHandler:
    def wrapper(api_key: str, hosts: list[str]) -> Source:
        res = scanner(api_key, hosts)
        src = new_source(name, "-", "-", loader=with_records(res))
        return src
    return wrapper

def with_cti_scn(api_key: str, scn: CTIScannerHandler) -> ModuleHandler:
    def handler(mod: Module) -> None:
        df = mod.repo().get_connection().execute("SELECT DISTINCT host FROM fingerprints").df()
        src = scn(api_key, df.host.tolist())
        mod.repo().add_sources(src)

    return handler

def get_scanner(cti: str) -> CTIScanner:
    match cti:
        case "shodan":
            return shodan_scanner
        case "censys":
            return censys_scanner
        case "greynoise":
            return greynoise_scanner
        case "ipinfo":
            return ipinfo_scanner
        case _:
            raise Exception(f"unknown CTI {cti}")

def make_cti_scn_handler(cti: str, api_key: str) -> ModuleHandler:
    return with_cti_scn(api_key, wrap_scanner(cti, get_scanner(cti)))

def make_scanners() -> list[Module]:
    return [
        new_module(SCANNER, cti, make_cti_scn_handler(cti, os.environ.get(f"{cti.upper()}_KEY", "")))
        for cti in ["shodan", "censys", "greynoise", "ipinfo"]
    ]