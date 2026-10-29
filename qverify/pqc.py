"""Hybrid signatures: Ed25519 (classical) + ML-DSA-65 (FIPS 204, post-quantum).
A signature is valid ONLY if BOTH verify. Algorithm names travel inside every
signature/public key, so the scheme can be upgraded (crypto-agility)."""
import base64, hashlib, hmac, json, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization as S

PREFIX = b"QVERIFY-v1|"  # domain separation

def canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

b64 = lambda b: base64.b64encode(b).decode()
unb64 = lambda s: base64.b64decode(s)

class _FakePQ:  # Stand-in only for environment/test fallback when QV_ALLOW_FAKE_PQC=1
    @staticmethod
    def keygen():
        k = os.urandom(32)
        return k, k
    @staticmethod
    def sign(sk, m):
        return hmac.new(sk, m, "sha256").digest()
    @staticmethod
    def verify(pk, m, s):
        return hmac.compare_digest(hmac.new(pk, m, "sha256").digest(), s)

def backend():
    try:
        from dilithium_py.ml_dsa import ML_DSA_65
        return ML_DSA_65, "ML-DSA-65"
    except ImportError:
        if os.environ.get("QV_ALLOW_FAKE_PQC") == "1":
            return _FakePQ, "FAKE-PQ-TESTS-ONLY"
        raise RuntimeError("PQC library missing. Run: pip install dilithium-py")

def generate_keys():
    dsa, name = backend()
    ed = Ed25519PrivateKey.generate()
    ed_pk = ed.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
    ed_sk = ed.private_bytes(S.Encoding.Raw, S.PrivateFormat.Raw, S.NoEncryption())
    pq_pk, pq_sk = dsa.keygen()
    pub = {"alg": f"Ed25519+{name}", "ed_pk": b64(ed_pk), "pq_pk": b64(pq_pk)}
    pub["kid"] = hashlib.sha256(ed_pk + pq_pk).hexdigest()[:16]
    return {"ed_sk": b64(ed_sk), "pq_sk": b64(pq_sk)}, pub

def sign(priv, msg: bytes) -> dict:
    dsa, name = backend()
    m = PREFIX + msg
    ed = Ed25519PrivateKey.from_private_bytes(unb64(priv["ed_sk"]))
    return {"alg": f"Ed25519+{name}", "ed": b64(ed.sign(m)), "pq": b64(dsa.sign(unb64(priv["pq_sk"]), m))}

def verify(pub, msg: bytes, sig: dict) -> bool:
    try:
        dsa, name = backend()
        if sig.get("alg") != pub.get("alg"):
            return False
        m = PREFIX + msg
        try:
            Ed25519PublicKey.from_public_bytes(unb64(pub["ed_pk"])).verify(unb64(sig["ed"]), m)
        except Exception:
            return False
        return bool(dsa.verify(unb64(pub["pq_pk"]), m, unb64(sig["pq"])))
    except Exception:
        return False

def sign_envelope(payload: dict, priv, pub) -> dict:
    return {"payload": payload, "kid": pub["kid"], "sig": sign(priv, canon(payload))}

def verify_envelope(env: dict, pub) -> bool:
    return env.get("kid") == pub["kid"] and verify(pub, canon(env["payload"]), env["sig"])
