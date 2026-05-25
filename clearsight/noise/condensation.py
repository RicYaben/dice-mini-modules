import logging
import ipaddress

import pandas as pd
import numpy as np

from dice.internal.modules import new_registry
from dice.shared.repository import TRepo
from dice.shared.models import Host
from dice.experimental import query

from dice.sdk import Flags, Module

from sklearn.linear_model import LinearRegression
from sklearn.mixture import GaussianMixture


# def describe_condensation(df: pd.DataFrame) -> pd.DataFrame:
#     """
#     Summarize condensation info grouped by prefix length (/n).
#     Shows descriptive statistics for size, density, and p_dense.
#     """
#     grouped = []

#     for slash, g in df.groupby("slash"):
#         sizes = g["size"]
#         densities = g["density"]
#         p_dense = g["p_dense"]

#         grouped.append({
#             "slash": slash,
#             "count_prefixes": len(g),

#             # size stats
#             "size_mean": sizes.mean(),
#             "size_p50": sizes.median(),
#             "size_p90": sizes.quantile(0.90),
#             "size_p99": sizes.quantile(0.99),
#             "size_min": sizes.min(),
#             "size_max": sizes.max(),
#             "size_total_hosts": sizes.sum(),

#             # density stats
#             "density_mean": densities.mean(),
#             "density_p50": densities.median(),
#             "density_p90": densities.quantile(0.90),
#             "density_p95": densities.quantile(0.95),
#             "density_p99": densities.quantile(0.99),

#             # condensation (GMM probability)
#             "p_dense_mean": p_dense.mean(),
#             "p_dense_p90": p_dense.quantile(0.90),
#             "p_dense_p95": p_dense.quantile(0.95),
#             "p_dense_p99": p_dense.quantile(0.99),
#         })

#     summary = pd.DataFrame(grouped)
#     return summary.sort_values("slash")

def model_condensation(df: pd.DataFrame) -> None:
    df["slash"] = df["prefix"].apply(lambda p: f"/{ipaddress.ip_network(p).prefixlen}")
    df["size"] = [2 ** (32 - ipaddress.ip_network(p).prefixlen) for p in df["prefix"]]
    df["density"] = df["count"] / df["size"]

    # --- Step 1: baseline regression (log–log)
    X = np.asarray(np.log10(df["size"])).reshape(-1, 1)
    y = np.asarray(np.log10(df["density"].clip(lower=1e-9)))
    base_model = LinearRegression().fit(X, y)
    df["expected_density"] = 10 ** base_model.predict(X)

    # --- Step 2: residuals
    df["log_excess"] = np.log10(df["density"].clip(lower=1e-9) / df["expected_density"])

    # --- Step 3: Gaussian mixture
    Xg = np.asarray(df["log_excess"]).reshape(-1, 1)
    gmm = GaussianMixture(n_components=2, random_state=0).fit(Xg)
    probs = gmm.predict_proba(Xg)

    # Identify the dense component
    dense_component = np.argmax(gmm.means_)
    df["p_dense"] = probs[:, dense_component]


def dense(pfx: list[dict], t: float) -> list[str]:
    df = pd.DataFrame.from_records(pfx)
    model_condensation(df)
    dense = df[df["p_dense"] > t]
    return dense["prefix"].tolist()

class DFlags(Flags):
    threshold: float = 0.95

def run(repo: TRepo, flags: DFlags, logger: logging.Logger) -> None:
    q = query(Host, fields=["prefix"], prefix__ne=None)
    pfx = repo.search(q).all()

    dpfx = dense(pfx, flags.threshold)
    
    for r in repo.search(query(Host, fields=["ip"], prefix__in=dpfx)).all():
        repo.tag(r["ip"], "dense", f'density: {r["p_dense"]:.3f}')

condensation_reg = new_registry("condensation").register(
        Module(
            "t", "condensation",
            flags=DFlags,
            run_fn=run,
        )
        .add_tag("dense", "condensation model to estimate whether a prefix is abnormally populated based on how dense other prefixes of similar size are")
    )