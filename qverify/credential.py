"""Selective-disclosure credentials. The signed credential holds only salted
commitments to each field. The student reveals chosen (value, salt) pairs, and
the verifier checks them against the signed commitments. Consent = what you reveal."""
import hashlib, os, time, uuid
from .pqc import sign_envelope, verify_envelope

commit = lambda salt, f, v: hashlib.sha256(f"{salt}|{f}|{v}".encode()).hexdigest()

def issue(record: dict, issuer: dict, pseudonym: str, priv, pub):
    cid = uuid.uuid4().hex[:16]
    salts = {f: os.urandom(16).hex() for f in record}
    payload = {"schema": "qv-cred-1", "cid": cid, "issuer": issuer, "pseudonym": pseudonym,
               "issued": int(time.time()),
               "commitments": {f: commit(salts[f], f, record[f]) for f in record}}
    return sign_envelope(payload, priv, pub), salts

def present(env, record, salts, fields):
    return {"credential": env, "disclosed": {f: {"value": record[f], "salt": salts[f]} for f in fields}}

def verify_presentation(pres, pub, revoked_ids):
    out = {"valid": False, "status": "INVALID", "reasons": [], "facts": {}}
    try:
        env = pres["credential"]
        if not verify_envelope(env, pub):
            out["reasons"].append("Signature check failed (Ed25519 and ML-DSA must both pass)")
            return out
        p = env["payload"]
        for f, d in pres["disclosed"].items():
            if p["commitments"].get(f) != commit(d["salt"], f, d["value"]):
                out["reasons"].append(f"Field '{f}' does not match the signed commitment")
                return out
            out["facts"][f] = d["value"]
        out["facts"]["issuer"] = p["issuer"]["name"]
        if p["cid"] in revoked_ids:
            out.update(status="REVOKED", reasons=["Credential was revoked by the issuer/AICTE"])
            return out
        out.update(valid=True, status="VALID", reasons=["Both signatures verified; disclosed fields match"])
        return out
    except Exception as e:
        out["reasons"].append(f"Malformed presentation: {e}")
        return out
