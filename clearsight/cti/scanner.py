from dataclasses import dataclass

from dice.modules import Module, ModuleHandler, new_module, query_db, tqdm
from dice.models import Source
from dice.config import ModuleEnum
from dice.database import get_or_create
from dice.resources import add_resource

from typing import Callable, Generator
from shodan import Shodan
from greynoise.api import GreyNoise, APIConfig
from uuid import uuid4

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

type CTIScannerHandler = Callable[[str, list[str]], Summary]
type CTIResult = Generator[tuple[int, list[dict]], None, None]
type CTIScanner = Callable[[str, list[str]], CTIResult]

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

def shodan_scanner(api_key: str, hosts: list[str]) -> CTIResult:
    client = Shodan(api_key)
    for h in hosts:
        if r:= fetch_shodan(client, h):
            yield 1, [r]

def censys_scanner(api_key: str, hosts: list[str]) -> CTIResult:
    for h in hosts:
        if r:= fetch_censys(api_key, h):
            yield 1, [r]

def greynoise_scanner(api_key: str, hosts: list[str]) -> CTIResult:
    api_config = APIConfig(api_key=api_key, integration_name="sdk-sample")
    client = GreyNoise(api_config)
    yield len(hosts), fetch_greynoise(client, *hosts)

def ipinfo_scanner(api_key: str, hosts: list[str], batch_size: int = 1000) -> CTIResult:
    for i in range(0, len(hosts), batch_size):
        batch = hosts[i:i + batch_size]
        yield len(batch), [fetch_ipinfo(api_key, *batch)]

def store_scan_results(fpath: str, records: list[dict]) -> None:
    with open(fpath, "+a") as f:
        ujson.dump(records, f, ensure_ascii=False)

@dataclass
class Summary:
    scanner: str
    results: str

def new_summary(name: str, fpath: str= "", ext: str = "jsonl") -> Summary:
    if not fpath:
        fpath = "_".join([name, str(uuid4())])
    if not fpath.endswith(ext):
        fpath += "."+ext
    return Summary(name, fpath)

def wrap_scanner(name: str,  scanner: CTIScanner) -> CTIScannerHandler:
    def wrapper(api_key: str, hosts: list[str]) -> Summary:
        summary = new_summary(name)
        with tqdm(total=len(hosts), desc=name) as pbar:
            for n, r in scanner(api_key, hosts):
                store_scan_results(summary.results, r)
                pbar.update(n)
        return summary
    return wrapper

def with_cti_scn(api_key: str, scn: CTIScannerHandler) -> ModuleHandler:
    def handler(mod: Module) -> None:
        _, gen = mod.query(query_db("fingerprint"))
        for fps in gen:
            with mod.repo().session() as s:
                summary = scn(api_key, fps.host.unique().tolist())
                src, _ = get_or_create(s, Source, name=summary.scanner)

                assert(src.id is not None)
                add_resource(mod.repo(), summary.scanner, src.id, summary.results)

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
        new_module(ModuleEnum.SCANNER.value, cti, make_cti_scn_handler(cti, os.environ.get(f"{cti.upper()}_KEY", "")))
        for cti in ["shodan", "censys", "greynoise", "ipinfo"]
    ]