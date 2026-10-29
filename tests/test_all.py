import os, sys, copy
os.environ.setdefault("QV_ALLOW_FAKE_PQC", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest, pandas as pd
from qverify import pqc, datagen, credential
from qverify.platform import Platform

@pytest.fixture
def plat(tmp_path):
    p = Platform(str(tmp_path))
    inst, data = datagen.generate()
    p.set_institutions(inst)
    for k, df in data.items(): p.upload(k, df)
    return p

def test_hybrid_needs_both_signatures():
    priv, pub = pqc.generate_keys()
    sig = pqc.sign(priv, b"hello")
    assert pqc.verify(pub, b"hello", sig)
    assert not pqc.verify(pub, b"hellO", sig)
    bad = dict(sig); bad["pq"] = pqc.b64(b"\x00" * len(pqc.unb64(sig["pq"])))
    assert not pqc.verify(pub, b"hello", bad)
    bad = dict(sig); bad["ed"] = pqc.b64(b"\x00" * 64)
    assert not pqc.verify(pub, b"hello", bad)

def test_validation_rules(plat):
    st = plat.s["stats"]
    assert plat.s["held"]["INST-007"]
    assert st["INST-003"]["err_rows"] >= 14
    assert st["INST-002"]["err_rows"] >= 5
    assert not plat.s["held"]["INST-001"]

def test_anomaly_flags_planted_institutions(plat):
    a = plat.anomalies()
    for k in ["INST-007", "INST-011", "INST-003"]:
        assert a.loc[k, "flagged"] and a.loc[k, "reasons"]
    assert not a.loc["INST-001", "flagged"]

def test_issue_verify_selective_disclosure_revoke(plat):
    assert plat.issue_credentials("INST-007") == 0
    assert plat.issue_credentials("INST-001") > 0
    cid = next(c for c, v in plat.s["creds"].items() if v["inst"] == "INST-001")
    w = plat.s["wallet"][cid]
    pres = credential.present(w["env"], w["record"], w["salts"], ["programme", "year"])
    r = plat.verify(pres)
    assert r["valid"] and "name" not in r["facts"] and "apaar_id" not in r["facts"]
    forged = copy.deepcopy(pres); forged["disclosed"]["programme"]["value"] = "MBBS"
    assert plat.verify(forged)["status"] == "INVALID"
    plat.revoke(cid, "test")
    assert plat.verify(pres)["status"] == "REVOKED"

def test_audit_chain_and_checkpoint(plat):
    plat.checkpoint()
    assert plat.verify_audit()[0]
    plat.s["entries"][3]["detail"]["tampered"] = True
    assert not plat.verify_audit()[0]

def test_reupload_supersedes_old_credentials(plat):
    plat.issue_credentials("INST-001")
    cid = next(c for c, v in plat.s["creds"].items() if v["inst"] == "INST-001")
    plat.upload("INST-001", pd.DataFrame(plat.s["records"]["INST-001"]))
    assert plat.lookup(cid) == "REVOKED"
