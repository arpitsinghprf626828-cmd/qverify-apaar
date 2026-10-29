"""Synthetic data generator with seeded irregularities for benchmarking."""
import numpy as np, pandas as pd
from .validation import COLS

PROGS = ["B.Tech CSE", "B.Tech ECE", "B.Tech ME", "MBA", "MCA"]

def generate(seed=7, n_inst=14):
    rng = np.random.default_rng(seed)
    used = set()
    def aid():
        while True:
            a = "".join(map(str, rng.integers(0, 10, 12)))
            if a not in used: used.add(a); return a
    inst, data = {}, {}
    for k in range(1, n_inst + 1):
        iid = f"INST-{k:03d}"
        intake = int(rng.integers(6, 25) * 10)
        inst[iid] = {"name": f"National Institute of Technology {k}", "intake": intake}
        regular = int(intake * (1.35 if k == 7 else rng.uniform(0.75, 0.95)))
        sn_n = int(intake * (0.30 if k == 11 else rng.uniform(0.0, 0.06)))
        rows = []
        for i in range(regular + sn_n):
            if i >= regular: q = "Supernumerary"
            elif k == 11: q = str(rng.choice(["Regular", "NRI"], p=[0.5, 0.5]))
            else: q = str(rng.choice(["Regular", "NRI", "OCI", "FN"], p=[0.93, 0.04, 0.02, 0.01]))
            rows.append([aid(), f"Student {k}-{i:03d}", str(rng.choice(PROGS)), 2026, q])
        data[iid] = pd.DataFrame(rows, columns=COLS)
    # Plant distinct anomalies
    d3 = data["INST-003"]
    for i in range(8): d3.loc[i, "apaar_id"] = f"12AB{i:04d}00"
    for i in range(10, 16): d3.loc[i, "apaar_id"] = d3.loc[30, "apaar_id"]
    for i in range(5): data["INST-002"].loc[i, "apaar_id"] = data["INST-001"].loc[i, "apaar_id"]
    return inst, data
