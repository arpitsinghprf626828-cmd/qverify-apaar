"""Rule-based validation for institutional student enrollment."""
import hashlib, hmac, re
import pandas as pd

COLS = ["apaar_id", "name", "programme", "year", "quota"]
QUOTAS = {"Regular", "NRI", "OCI", "FN", "Supernumerary"}
SN_CAP = 0.10  # Illustrative 10% supernumerary quota threshold

def pseudonym(apaar_id: str, key: bytes) -> str:
    """Keyed HMAC (secret held by AICTE). Prevents rainbow table brute force on 12-digit IDs."""
    return hmac.new(key, str(apaar_id).encode(), hashlib.sha256).hexdigest()[:24]

def validate(df: pd.DataFrame, inst_id: str, intake: int, others: dict, key: bytes):
    """Validates dataframe rows. Returns (issues_df, ok_mask)."""
    cols = ["row", "apaar_id", "rule", "severity", "message"]
    issues = []
    add = lambda row, apaar, rule, sev, msg: issues.append(
        {"row": row, "apaar_id": apaar, "rule": rule, "severity": sev, "message": msg})
    miss = [c for c in COLS if c not in df.columns]
    if miss:
        add(None, "", "MISSING_COLUMNS", "error", f"Missing columns: {miss}")
        return pd.DataFrame(issues, columns=cols), pd.Series(False, index=df.index)
    bad, seen = set(), set()
    for pos, (idx, r) in enumerate(df.iterrows()):
        a = str(r["apaar_id"]).strip()
        if not re.fullmatch(r"\d{12}", a):
            add(pos, a, "APAAR_FORMAT", "error", "APAAR ID must be exactly 12 digits"); bad.add(idx); continue
        if a in seen:
            add(pos, a, "DUPLICATE_IN_UPLOAD", "error", "Same APAAR ID appears more than once in batch"); bad.add(idx)
        seen.add(a)
        if r["quota"] not in QUOTAS:
            add(pos, a, "QUOTA_VALUE", "error", f"Unknown quota '{r['quota']}'"); bad.add(idx)
        p = pseudonym(a, key)
        if p in others:
            add(pos, a, "CROSS_INSTITUTION", "error", f"Already enrolled at {others[p]} (matched via keyed pseudonym)"); bad.add(idx)
    regular = int((df["quota"] != "Supernumerary").sum())
    sn = int((df["quota"] == "Supernumerary").sum())
    if regular > intake:
        add(None, "", "INTAKE_EXCEEDED", "error", f"{regular} regular admissions exceed approved intake of {intake}")
    if sn > SN_CAP * intake:
        add(None, "", "SUPERNUMERARY_CAP", "warning", f"{sn} supernumerary seats exceed illustrative {int(SN_CAP*100)}% threshold")
    return pd.DataFrame(issues, columns=cols), pd.Series([i not in bad for i in df.index], index=df.index)
