# 2c. Hybrid ECDSA + WOTS+C Instantiation Analysis

**Scope**: The rotation protocol instantiated with a hybrid scheme — both an ECDSA signature and a WOTS+C signature required per transaction. This document analyses the security properties, the design space for hybrid backup/recovery, and the trade-offs relative to the pure instantiations (2a, 2c). All findings from the [abstract protocol analysis](1-abstract-protocol-analysis.md) apply.

**Last updated**: 2026-04-09

---

## 1. Instantiation Summary

- **Primary signer**: Hybrid — valid transaction requires BOTH a valid ECDSA signature AND a valid WOTS+C signature under the current key index
- **On-chain commitment**: `(ecdsa_address, hash(wots_pk))` or a single hash binding both
- **Signature size**: 65 bytes (ECDSA) + 292 bytes (WOTS+C) = 357 bytes
- **Key derivation**: Unspecified "BIP-44-like" derivation from root seed

---

## 2. What "Hybrid" Means

The core idea is **hedging**: requiring both signatures ensures security as long as *at least one* of the two schemes is secure.

- If ECDSA is broken (quantum adversary solves ECDLP) but WOTS+C is intact → the attacker cannot produce a valid WOTS+C signature → system remains secure
- If WOTS+C has an implementation flaw or the hash function is weaker than expected, but ECDSA is intact → the attacker cannot produce a valid ECDSA signature → system remains secure
- Both must be broken simultaneously for the system to fail

This is the standard "belt-and-suspenders" argument for hybrid post-quantum constructions. It is the approach taken by X-Wing (ML-KEM + X25519) and recommended by NIST SP 800-227 for the PQ transition.

**[FINDING-2c1] Hybrid provides strictly stronger security guarantees than either component alone — Severity: Informational (positive)**

The hybrid construction's security is `max(ECDSA_security, WOTS+C_security)` — not the minimum. This is because an adversary must break BOTH to forge a valid transaction.

---

## 3. Security Analysis

### 3.1 Classical Security

Classical security is provided by ECDSA (~128-bit) AND WOTS+C (~128-bit). The hybrid is at least as secure as the stronger of the two, which in the classical setting are equivalent.

### 3.2 Quantum Resistance

Quantum resistance is provided by the WOTS+C component. Even if a quantum adversary breaks ECDSA instantly, they still cannot forge the WOTS+C signature (assuming hash function quantum resistance).

**Crucially**: The hybrid design does NOT depend on the quantum exposure window argument (`T_Shor >> Δ`). Even if `T_Shor = 0` (instantaneous ECDSA break), the WOTS+C component holds. This is a strict upgrade over the ECDSA-only design.

**[FINDING-2c2] Hybrid eliminates dependence on the quantum timing assumption — Severity: Informational (positive)**

The ECDSA-only design's security degrades continuously as quantum computers improve. The hybrid design has a binary security property: it is secure as long as WOTS+C is secure. The ECDSA component provides defence-in-depth against WOTS+C implementation errors or hash function weaknesses.

### 3.3 One-Time Use Enforcement

The WOTS+C component is one-time. Therefore, the hybrid inherits the OTS constraint: each key pair (ECDSA + WOTS+C at index `i`) must be used for at most one signature.

**Key question**: What happens on transaction failure/retry?

If the user needs to retry, they cannot reuse the WOTS+C component (one-time). The ECDSA component could be reused safely, but the WOTS+C cannot. This means the hybrid design inherits the retry problem from the WOTS+C-only design.

**[FINDING-2c3] Hybrid inherits the OTS retry/reuse problem from WOTS+C — Severity: High**

The ECDSA component does not help with the retry problem. If a transaction is dropped, the user must advance to key index `i+1` and produce a fresh hybrid signature. The key at index `i` is burned. This is identical to the WOTS+C-only design.

**However**: If the retry uses the *exact same message* (same calldata, same gas parameters), and the WOTS+C signature is deterministic, then resigning produces the same WOTS+C signature. No new information is leaked. This narrow case is safe — but it fails as soon as any transaction parameter changes (e.g., gas price adjustment for congestion).

### 3.4 Two-Signature Leakage (WOTS+C Component)

If the user produces two hybrid signatures at the same key index with different messages:
- The ECDSA component leaks nothing (ECDSA tolerates reuse)
- The WOTS+C component leaks chain values per the standard WOTS+ reuse analysis

**But**: A forged WOTS+C signature alone is insufficient. The attacker also needs a valid ECDSA signature. If the ECDSA private key at that index has not been compromised, the forged WOTS+C signature is useless.

**[FINDING-2c4] Hybrid mitigates WOTS+C key-reuse leakage — the attacker needs BOTH forgeries — Severity: Informational (positive, partial mitigation)**

If the ECDSA key at index `i` is not compromised (i.e., the quantum adversary hasn't broken it yet), then even if the WOTS+C component is fully compromised via two-signature leakage, the attacker cannot produce a valid hybrid signature. The ECDSA component acts as a second authentication factor.

However, this mitigation is time-limited: once a quantum adversary can break ECDSA, the leaked WOTS+C chain values become exploitable. Since the WOTS+C key is spent (rotated on-chain), the forged hybrid signature would be rejected by the on-chain commitment check — *unless* the attacker can exploit the leaked values before rotation lands.

**Net assessment**: The hybrid provides a partial mitigation window for WOTS+C reuse, but this window disappears once ECDSA falls. In a world where ECDSA is already broken, the hybrid's WOTS+C component must be treated with the same reuse severity as the standalone WOTS+C design.

### 3.5 Recovery / Backup Design

This is the most complex aspect of the hybrid design. The recovery mechanism must maintain the hybrid security guarantee — otherwise, forcing recovery becomes a downgrade attack.

**Option 1: Hybrid recovery (ECDSA + WOTS+C backup pool)**
- Pre-register a pool of hybrid backup key pairs
- Recovery requires both a valid ECDSA backup signature and a valid WOTS+C backup signature
- Maintains the hybrid guarantee throughout
- Cost: pool management complexity × 2 (two key types per pool entry)

**Option 2: WOTS+C-only recovery**
- Recovery uses only a WOTS+C backup key (no ECDSA component)
- Secure against quantum adversaries
- Loses the ECDSA hedge during recovery
- If WOTS+C has a flaw, recovery is the weak point

**Option 3: SPHINCS+ recovery**
- Stateless, no pool management, no reuse risk
- Natively post-quantum
- Large signatures (7.8-49.8 KB)
- Does not require ECDSA, so no quantum-vulnerable component
- But loses the classical-crypto hedge

**[FINDING-2c5] Applying A7 to hybrid: recovery must be at least PQ-secure — Severity: High**

### 3.6 Composability

**EIP-1271 (Off-Chain Verification)**:

A non-consuming verification path must verify BOTH the ECDSA and WOTS+C components without triggering rotation. This is possible:
- Verify ECDSA signature via `ecrecover` (pure, no state change)
- Verify WOTS+C signature by reconstructing the public key and checking the hash (pure, no state change)
- Return success only if both verify

**[FINDING-2c6] Off-chain hybrid verification exposes the WOTS+C signature without consuming the key — Severity: High**

The same EIP-1271 / OTS issue from the abstract analysis and §2b applies here, except that the ECDSA component of the off-chain signature is safe to expose multiple times, while the WOTS+C component is not.

If the user:
1. Signs an off-chain message (EIP-1271) with their current hybrid key
2. Then signs an on-chain transaction with the same hybrid key

Both WOTS+C signatures are now public (one off-chain, one on-chain). If the messages differ, the two-signature leakage applies. However, §3.4 shows that the ECDSA component provides a partial mitigation.

**Possible recommendation**: For off-chain signatures, sign with only the ECDSA component (not the hybrid). This avoids exposing the WOTS+C key material for non-rotation purposes. The verifying contract (via EIP-1271) would accept an ECDSA-only signature for off-chain verification and require the full hybrid for on-chain transactions. However, this creates an asymmetry such that on-chain actions require hybrid security, off-chain verification accepts ECDSA-only.
