# Q-Verify APAAR: Technical Approach (AICTE SIH26263)

## Architectural Differentiators
1. **Hybrid Quantum Security (Ed25519 + ML-DSA-65)**: Dual-signature verification safeguarding long-term degree authenticity against Harvest-Now-Decrypt-Later threats.
2. **Selective-Disclosure Credentials**: Salted SHA-256 commitments enable graduates to prove degree qualifications without leaking full APAAR IDs, caste quota, or unnecessary PII.
3. **Keyed HMAC Duplicate Detection**: Centralized AICTE secret prevents brute-force rainbow table attacks across 12-digit student identifiers.
4. **Tamper-Evident Merkle Ledger**: Regulatory actions are recorded in a hash-chained audit log with post-quantum signed Merkle checkpoints.
