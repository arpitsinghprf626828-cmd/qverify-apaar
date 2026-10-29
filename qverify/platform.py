"""Service layer coordinating verification, cryptographic keys, and state."""
import hashlib, json, os
from pathlib import Path
import pandas as pd
from . import pqc, credential as cred, anomaly
from .audit import AuditLog
from .validation import validate, pseudonym

EMPTY = {"institutions": {}, "records": {}, "registry": {}, "stats": {}, "held": {}, "creds": {}, "wallet": {},
         "revoked": [], "entries": [], "checkpoints": []}

class Platform:
    def __init__(self, root="data"):
        self.root = Path(root); kd = self.root / "keys"; kd.mkdir(parents=True, exist_ok=True)
        pp, sp, kp = kd / "public.json", kd / "private.json", kd / "pseudo.key"
        if not (pp.exists() and sp.exists()):
            priv, pub = pqc.generate_keys()
            sp.write_text(json.dumps(priv)); pp.write_text(json.dumps(pub))
        if not kp.exists():
            kp.write_bytes(os.urandom(32))
        self.pub, self.priv, self.pkey = json.loads(pp.read_text()), json.loads(sp.read_text()), kp.read_bytes()
        self.sf = self.root / "state.json"
        self.s = json.loads(self.sf.read_text()) if self.sf.exists() else json.loads(json.dumps(EMPTY))
        self.audit = AuditLog(self.s["entries"], self.s["checkpoints"])

    def save(self):
        self.sf.write_text(json.dumps(self.s, indent=2))

    def set_institutions(self, inst: dict, actor="system"):
        self.s["institutions"] = inst
        self.audit.add(actor, "AICTE", "INSTITUTIONS_SET", {"count": len(inst)})
        self.save()

    def upload(self, inst_id, df: pd.DataFrame, actor="institution"):
        s = self.s; df = df.reset_index(drop=True).astype(str)
        for p in [p for p, i in s["registry"].items() if i == inst_id]: del s["registry"][p]
        for cid, c in list(s["creds"].items()):
            if c["inst"] == inst_id and cid not in s["revoked"]: s["revoked"].append(cid)
        others = dict(s["registry"])
        issues, ok = validate(df, inst_id, s["institutions"][inst_id]["intake"], others, self.pkey)
        good = df[ok]
        s["records"][inst_id] = good.to_dict("records")
        for r in s["records"][inst_id]: s["registry"][pseudonym(r["apaar_id"], self.pkey)] = inst_id
        s["held"][inst_id] = bool(((issues["severity"] == "error") & issues["row"].isna()).any())
        q = df["quota"]
        st = {"n": len(df), "regular": int((q != "Supernumerary").sum()), "sn": int((q == "Supernumerary").sum()),
              "nri": int((q == "NRI").sum()), "oci": int((q == "OCI").sum()), "fn": int((q == "FN").sum()),
              "err_rows": int((~ok).sum()), "accepted": int(ok.sum())}
        s["stats"][inst_id] = st
        self.audit.add(actor, "Institution", "UPLOAD", {"inst": inst_id, **st, "held": s["held"][inst_id],
                       "rule_hits": issues["rule"].value_counts().to_dict()})
        self.save()
        return issues, st

    def issue_credentials(self, inst_id, actor="institution"):
        s = self.s
        if s["held"].get(inst_id): return 0
        have = {s["creds"][c]["pseudonym"] for c in s["creds"] if s["creds"][c]["inst"] == inst_id and c not in s["revoked"]}
        n = 0
        for r in s["records"].get(inst_id, []):
            p = pseudonym(r["apaar_id"], self.pkey)
            if p in have: continue
            issuer = {"id": inst_id, "name": s["institutions"][inst_id]["name"]}
            env, salts = cred.issue(r, issuer, p, self.priv, self.pub)
            cid = env["payload"]["cid"]
            s["creds"][cid] = {"inst": inst_id, "pseudonym": p, "apaar_id": r["apaar_id"],
                               "digest": hashlib.sha256(pqc.canon(env)).hexdigest()}
            s["wallet"][cid] = {"record": r, "salts": salts, "env": env}
            n += 1
        self.audit.add(actor, "Institution", "ISSUE", {"inst": inst_id, "issued": n})
        self.save()
        return n

    def revoke(self, cid, reason, actor="AICTE"):
        if cid in self.s["creds"] and cid not in self.s["revoked"]:
            self.s["revoked"].append(cid)
            self.audit.add(actor, "AICTE", "REVOKE", {"cid": cid, "reason": reason})
            self.save()

    def verify(self, pres): return cred.verify_presentation(pres, self.pub, set(self.s["revoked"]))

    def lookup(self, cid):
        if cid not in self.s["creds"]: return "UNKNOWN"
        return "REVOKED" if cid in self.s["revoked"] else "ACTIVE"

    def anomalies(self):
        rows = {i: anomaly.features(st, self.s["institutions"][i]["intake"]) for i, st in self.s["stats"].items()}
        return anomaly.score(pd.DataFrame.from_dict(rows, orient="index"))

    def checkpoint(self, actor="AICTE"):
        self.audit.checkpoint(self.priv, self.pub)
        self.save()

    def verify_audit(self): return self.audit.verify(self.pub)
