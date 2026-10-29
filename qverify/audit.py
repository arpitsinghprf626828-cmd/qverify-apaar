"""Hash-chained audit log with periodically signed Merkle checkpoints.
Editing/deleting/reordering any past entry breaks the chain or a checkpoint."""
import hashlib, time
from .pqc import canon, sign_envelope, verify_envelope

h = lambda b: hashlib.sha256(b).digest()

def merkle_root(leaves):
    if not leaves:
        return h(b"")
    lvl = [h(b"\x00" + l) for l in leaves]
    while len(lvl) > 1:
        if len(lvl) % 2:
            lvl.append(lvl[-1])
        lvl = [h(b"\x01" + lvl[i] + lvl[i + 1]) for i in range(0, len(lvl), 2)]
    return lvl[0]

class AuditLog:
    def __init__(self, entries, checkpoints):
        self.entries, self.checkpoints = entries, checkpoints

    def add(self, actor, role, action, detail=None):
        prev = self.entries[-1]["hash"] if self.entries else "0" * 64
        e = {"i": len(self.entries), "ts": int(time.time()), "actor": actor, "role": role,
             "action": action, "detail": detail or {}, "prev": prev}
        e["hash"] = hashlib.sha256(canon(e)).hexdigest()
        self.entries.append(e)

    def checkpoint(self, priv, pub):
        root = merkle_root([bytes.fromhex(e["hash"]) for e in self.entries]).hex()
        self.checkpoints.append(sign_envelope({"size": len(self.entries), "root": root, "ts": int(time.time())}, priv, pub))

    def verify(self, pub):
        prev = "0" * 64
        for i, e in enumerate(self.entries):
            body = {k: v for k, v in e.items() if k != "hash"}
            if e["i"] != i or e["prev"] != prev or hashlib.sha256(canon(body)).hexdigest() != e["hash"]:
                return False, f"Chain broken at entry {i}"
            prev = e["hash"]
        for c in self.checkpoints:
            n = c["payload"]["size"]
            if n > len(self.entries):
                return False, f"Checkpoint over {n} entries but log is shorter"
            root = merkle_root([bytes.fromhex(e["hash"]) for e in self.entries[:n]]).hex()
            if not verify_envelope(c, pub) or root != c["payload"]["root"]:
                return False, f"Checkpoint over {n} entries failed"
        return True, f"OK: {len(self.entries)} entries, {len(self.checkpoints)} signed checkpoints"
