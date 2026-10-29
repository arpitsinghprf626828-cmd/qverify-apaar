"""Explainable anomaly detection: robust z-scores give human-readable explanations,
IsolationForest catches multivariate outliers."""
import numpy as np, pandas as pd
from sklearn.ensemble import IsolationForest

FEATS = {"fill_ratio": "intake fill ratio", "sn_share": "supernumerary share",
         "nri_share": "NRI share", "oci_fn_share": "OCI/FN share", "error_rate": "rejected-row rate"}

def features(stats: dict, intake: int) -> dict:
    n = max(stats["n"], 1)
    return {"fill_ratio": stats["regular"] / max(intake, 1), "sn_share": stats["sn"] / n,
            "nri_share": stats["nri"] / n, "oci_fn_share": (stats["oci"] + stats["fn"]) / n,
            "error_rate": stats["err_rows"] / n}

def score(df: pd.DataFrame) -> pd.DataFrame:
    cols = ["anomaly_score", "flagged", "reasons"]
    if df.empty:
        return pd.DataFrame(columns=cols)
    X = df[list(FEATS)].astype(float).values
    med = np.median(X, 0)
    mad = np.median(np.abs(X - med), 0) * 1.4826 + 0.03
    z = (X - med) / mad
    iso = np.zeros(len(df)); out_iso = np.zeros(len(df), bool)
    if len(df) >= 8:
        m = IsolationForest(n_estimators=200, random_state=0).fit(X)
        iso = -m.score_samples(X); out_iso = m.predict(X) == -1
    rows = []
    for i, inst in enumerate(df.index):
        why = [f"{lab} {X[i,j]:.0%} vs typical {med[j]:.0%}" for j, lab in enumerate(FEATS.values()) if z[i, j] > 3.5]
        if out_iso[i] and not why:
            why = ["unusual combination of features (isolation forest)"]
        rows.append({"institution": inst, "anomaly_score": round(float(iso[i]), 3), "flagged": bool(why), "reasons": "; ".join(why)})
    return pd.DataFrame(rows).set_index("institution")
