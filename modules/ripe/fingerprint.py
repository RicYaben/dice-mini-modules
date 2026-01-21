from dice.module import Module, ModuleHandler,new_module
from dice.query import query_records
from dice.config import FINGERPRINTER

from .helpers import PrefixTree, build_resource_tree
from typing import Any

import pandas as pd

TREE: PrefixTree | None = None

def fingerprint(mod: Module, row: pd.Series, tree: PrefixTree) -> Any:
    if (fp := tree.get(row["ip"])) is not None:
        mod.store(mod.make_fingerprint(row, fp, "asn"))

def load_tree(mod: Module) -> PrefixTree:
    _, batches = mod.repo().queryb(query_records("resources"))
    resources = pd.concat(batches, ignore_index=True)
    return build_resource_tree(resources)

def make_asn_fp_handler() -> ModuleHandler:
    def handler(mod: Module) -> None:
        global TREE
        if not TREE:
            TREE = load_tree(mod)

        def fp(df: pd.DataFrame):
            global TREE
            assert isinstance(TREE, PrefixTree)
            
            for _, row in df.iterrows():
                fingerprint(mod, row, TREE)
        mod.with_pbar(fp, query_records("zgrab2"))
    return handler

def make_asn_fp_module() -> Module:
    return new_module(FINGERPRINTER, "asn", make_asn_fp_handler())