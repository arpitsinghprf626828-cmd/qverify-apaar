import io, json
import pandas as pd, streamlit as st
from qverify import datagen, credential, pqc
from qverify.platform import Platform
from qverify.validation import COLS

st.set_page_config(page_title="Q-Verify APAAR", page_icon="🛡️", layout="wide")

@st.cache_resource
def plat(): return Platform("data")

P = plat(); S = P.s
st.title("🛡️ Q-Verify APAAR")
st.caption(f"Quantum-Safe Academic Record Verification (AICTE SIH26263) · Suite: **{P.pub['alg']}** · Key ID: `{P.pub['kid']}`")

if "FAKE" in P.pub["alg"]:
    st.error("⚠️ Running with an INSECURE mock for ML-DSA. Run `pip install dilithium-py` and restart after deleting the `data` folder.")

PINS = {"Institution": "inst123", "AICTE": "aicte123", "Student": "stu123", "Verifier": ""}
role = st.sidebar.radio("Role Switcher", list(PINS))
pin = st.sidebar.text_input("Demo PIN", type="password", help="Institution: inst123 | AICTE: aicte123 | Student: stu123 | Verifier: none") if PINS[role] else ""
if pin != PINS[role]:
    st.info(f"Enter the demo PIN for {role} (see tooltip for PINs).")
    st.stop()

if not S["institutions"]:
    inst, data = datagen.generate()
    P.set_institutions(inst)
    st.session_state["sample"] = data

sample = st.session_state.setdefault("sample", datagen.generate()[1])

if role == "Institution":
    st.header("🏫 Institution Enrollment Upload & Issuance")
    iid = st.selectbox("Select Institution", list(S["institutions"]), format_func=lambda k: f"{k} - {S['institutions'][k]['name']} (Intake: {S['institutions'][k]['intake']})")
    
    col1, col2 = st.columns(2)
    with col1:
        up = st.file_uploader("Upload Student CSV (Cols: apaar_id, name, programme, year, quota)", type="csv")
        btn_upload = st.button("Validate and Submit Uploaded CSV")
    with col2:
        st.markdown("**Quick Test:**")
        btn_sample = st.button("Use Pre-loaded Sample CSV for this College")
        st.caption("Or upload one of the pre-made CSV files from the `sample_data/` folder!")
        
    df = None
    if up and btn_upload:
        df = pd.read_csv(up, dtype=str)
    elif btn_sample:
        df = sample[iid]

    if df is not None:
        issues, stt = P.upload(iid, df, actor=iid)
        st.session_state["last"] = (iid, issues, stt)

    if st.session_state.get("last", (None,))[0] == iid:
        _, issues, stt = st.session_state["last"]
        st.markdown(f"### Ingestion Results: Accepted **{stt['accepted']}** of **{stt['n']}** records")
        if S["held"].get(iid):
            st.error("🚨 Institutional Hold Triggered: Approved intake capacity exceeded or serious compliance error. Credential issuance locked!")
        else:
            st.success("✅ Records validated successfully against AICTE compliance norms.")
        st.dataframe(issues, use_container_width=True)

    st.markdown("---")
    if st.button("🔏 Issue Quantum-Signed Credentials for Accepted Records", disabled=iid not in S["records"]):
        if S["held"].get(iid):
            st.error("Cannot issue: Institution is currently in HELD status due to intake quota violation.")
        else:
            n_issued = P.issue_credentials(iid, actor=iid)
            st.success(f"Successfully generated {n_issued} dual-signed (Ed25519 + ML-DSA-65) credentials.")

elif role == "AICTE":
    st.header("🏛️ AICTE Central Monitoring & Oversight")
    t1, t2, t3, t4 = st.tabs(["Compliance Overview", "Explainable Anomalies", "Immutable Audit Chain", "Revocation Management"])
    with t1:
        if st.button("Load All 14 Sample Colleges"):
            for k, d in sample.items(): P.upload(k, d, actor="AICTE-Admin")
            st.rerun()
        rows = [{"institution": k, "intake": S["institutions"][k]["intake"], **v, "held": S["held"].get(k, False),
                 "active_credentials": sum(c["inst"] == k and i not in S["revoked"] for i, c in S["creds"].items())} for k, v in S["stats"].items()]
        if rows:
            st.dataframe(pd.DataFrame(rows).set_index("institution"), use_container_width=True)
    with t2:
        if S["stats"]:
            a = P.anomalies()
            st.dataframe(a.sort_values("anomaly_score", ascending=False), use_container_width=True)
            st.info("💡 Robust z-score metrics explain *why* an institution was flagged (e.g. seat padding, quota skew).")
    with t3:
        c1, c2 = st.columns(2)
        if c1.button("Sign Checkpoint (Merkle Root + Hybrid ML-DSA)"):
            P.checkpoint()
            st.rerun()
        if c2.button("Verify Complete Ledger Integrity"):
            ok, msg = P.verify_audit()
            if ok: st.success(msg)
            else: st.error(msg)
        st.dataframe(pd.DataFrame(S["entries"]).drop(columns=["prev"], errors="ignore").iloc[::-1], use_container_width=True)
    with t4:
        cid = st.selectbox("Select Active Credential to Revoke", [c for c in S["creds"] if c not in S["revoked"]])
        why = st.text_input("Revocation Reason (e.g. Fraudulent Enrollment, Disciplinary Action)")
        if st.button("Revoke Credential") and cid:
            P.revoke(cid, why)
            st.success(f"Credential {cid} revoked and appended to immutable audit log.")

elif role == "Student":
    st.header("🎓 Student Sovereign Wallet & Selective Consent")
    aid = st.text_input("Enter your 12-digit APAAR ID (or check sample_data/ for examples):")
    mine = [c for c, v in S["creds"].items() if v["apaar_id"] == aid.strip()]
    if aid and not mine:
        st.warning("No signed credentials found for this APAAR ID. Ensure your college issued credentials first.")
    for cid in mine:
        w = S["wallet"][cid]
        st.subheader(f"Credential ID: `{cid}` | Status: **{P.lookup(cid)}**")
        fields = st.multiselect("Select fields you give consent to disclose:", list(w["record"]), default=["programme", "year"], key=cid)
        pres = credential.present(w["env"], w["record"], w["salts"], fields)
        st.download_button("📥 Download Presentation (JSON)", json.dumps(pres, indent=2), f"presentation_{cid}.json")
        ptr = f"qv://{cid}#{S['creds'][cid]['digest'][:16]}"
        st.caption("Lightweight Compact QR Representation:")
        st.code(ptr)
        try:
            import qrcode
            b = io.BytesIO()
            qrcode.make(ptr).save(b, format="PNG")
            st.image(b.getvalue(), width=160)
        except Exception:
            pass

else:
    st.header("🔍 Public Verifier Portal (Employers & Universities)")
    st.caption("Verifies credentials offline using only the AICTE Public Key (`public.json`). Zero PII leaked.")
    up = st.file_uploader("Upload Student Presentation JSON File", type="json")
    if up:
        pres_data = json.load(up)
        r = P.verify(pres_data)
        if r["valid"]:
            st.success("✅ VALID: Post-Quantum & Classical Signatures Verified. Disclosed facts match cryptographic commitments.")
            st.json(r["facts"])
        else:
            st.error(f"❌ {r['status']}: {'; '.join(r['reasons'])}")
    ptr = st.text_input("Or query online status by compact QR pointer (`qv://<cid>#<digest>`):")
    if ptr.startswith("qv://"):
        cid, _, dg = ptr[5:].partition("#")
        known = S["creds"].get(cid)
        match = bool(known and known["digest"].startswith(dg))
        st.write("Status:", P.lookup(cid), "· Hash Digest Match:", match)
