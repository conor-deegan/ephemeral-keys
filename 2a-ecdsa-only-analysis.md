# 2a. ECDSA-Only Instantiation Analysis

**Scope**: The rotation protocol instantiated with ECDSA for both the primary signing path and the recovery/rotation path. All findings from the [abstract protocol analysis](1-abstract-protocol-analysis.md) apply; this document covers ECDSA-specific concerns only.

**Last updated**: 2026-04-09

---

## 1. Instantiation Summary

- **Primary signer**: ECDSA on secp256k1. One key per transaction.
- **On-chain commitment**: Ethereum address (`address(keccak256(pubkey)[12:])`)
- **Signature size**: 65 bytes (r, s, v)
- **Verification**: `ecrecover` precompile
- **Recovery signer**: ECDSA key(s), also derived from the HD tree (separate index range or derivation path)
- **Key reuse tolerance**: ECDSA is not a one-time scheme. Multiple signatures under the same key do not leak the private key.
- **Key derivation**: Unspecified "BIP-44-like" derivation from root seed

---

## 2. Security Analysis

### 2.1 Classical Security

ECDSA on secp256k1 provides ~128-bit security against classical adversaries, assuming ECDLP hardness. This is standard and well-established.

The rotation mechanism does not weaken classical security — it provides the same authentication guarantees as a standard EOA, with the additional property that old keys are retired.

**Forward secrecy (classical)**: Achieved. If the current key `sk_i` is compromised, past keys cannot be derived (BIP-32 derivation is one-way parent→child even under quantum adversaries). The attacker can sign one transaction with `sk_i` (racing the legitimate user), but cannot access keys at other indices without the seed.

### 2.2 Quantum Resistance

This is the central question for the ECDSA-only instantiation.

**The security argument**: Shor's algorithm can recover `sk_i` from `pk_i`, but by the time a quantum computer completes this computation, the key `sk_i` has been rotated out and is no longer accepted by the smart account.

**Formal statement**: The ECDSA-only instantiation is secure against quantum adversaries if and only if:

```
T_Shor(secp256k1) >> Δ_max
```

where:
- `T_Shor(secp256k1)` = time for a quantum computer to solve a 256-bit ECDLP instance
- `Δ_max` = maximum time between public key exposure (broadcast) and rotation finalisation (block inclusion + finality)

**Current estimates for `T_Shor`**:
- Babbush et al. (2026): ≤ 1200 logical qubits and ≤ 90 million Toffoli gates or ≤ 1450 logical qubits and ≤ 70 million Toffoli gates for 256-bit ECDLP in ~9 minutes depending on the implementation.

**Current estimates for `Δ_max`**:
- Ethereum L1: 12 seconds per slot. With public mempool, exposure includes mempool dwell time (seconds to minutes under congestion).
- L2 (Base, Optimism): 2-second block times.
- Worst case (congestion + public mempool): minutes to hours.

**[FINDING-2a1] The ECDSA-only design has a concrete, quantifiable security lifetime — Severity: Low**

The design is secure as long as `T_Shor >> Δ_max`. Current estimates suggest a safety margin but this margin will shrink as quantum computers improve. The protocol should define an explicit "sunset condition": a quantum computing capability benchmark at which the ECDSA-only design should be retired in favour of PQ alternatives.

### 2.3 Key Reuse Under Failure

Unlike OTS schemes, ECDSA tolerates key reuse without catastrophic security loss. This is the primary advantage of the ECDSA-only instantiation for handling transaction failures.

If a transaction is dropped and the user resigns with the same key:
- The second signature does not leak additional information about the private key
- The only concern is the extended exposure window (the public key remains active longer)
- No need for backup/recovery infrastructure for simple retry cases

**[FINDING-2a2] ECDSA-only eliminates the retry/reuse problem entirely — Severity: Informational (positive)**

The most complex aspect of OTS-based designs (handling failed transactions without reusing one-time keys) does not exist in the ECDSA-only instantiation. The user can retry freely with the same key until the transaction lands. The key is only rotated upon successful on-chain inclusion.

This simplification has a significant downstream effect: the recovery mechanism becomes simpler (just another ECDSA key), state management is less fragile (local index tracks *successful rotations*, not *signing attempts*), and the single-device constraint is softer (two devices signing with the same key produces racing transactions, not a security vulnerability).

However, the protocol design should favour agnostic design with respect to the primitive used.

### 2.4 Recovery Path

Recovery in the ECDSA-only design uses one or more pre-registered ECDSA keys.

**Options**:
1. **Single recovery key**: Registered at account creation. Can always rotate the signer. Simple but creates a long-lived key — its address is known on-chain, and if it ever signs (including for recovery), its public key is exposed permanently.
2. **Rotating recovery pool**: A small set of ECDSA keys, also derived from the HD tree but at reserved indices. Used one-at-a-time for recovery, then rotated.

**[FINDING-2a3] A long-lived ECDSA recovery key undermines the ephemeral property — Severity: Medium**

If a single recovery key is registered and never rotated, its address is permanently visible on-chain. This key is no more quantum-resistant than a standard EOA — its public key is hidden behind a hash, but the first time it's used for recovery, the public key is exposed and remains useful indefinitely (since it's not rotated).

An adversary's strategy: force the user into recovery (by censoring primary transactions), wait for the recovery key's public key to be exposed, then use a quantum computer to derive the recovery private key. This bypasses the ephemeral rotation entirely.

**Mitigation**: Recovery keys should also rotate. After each recovery operation, the recovery key commitment should be updated. This is equivalent to running two parallel rotation chains — one for primary signing, one for recovery.

### 2.5 Harvest-Now-Decrypt-Later

**Assessment**: The ECDSA-only design provides strong mitigation against HNDL.

Past ECDSA signatures (and their corresponding public keys) are permanently recorded on-chain. A future quantum adversary can derive all past private keys. However:
- All past keys have been rotated out — they are not accepted by the smart account
- Past Ethereum transactions carry no encrypted data — there is no confidentiality to break
- The only value of past private keys is proving you *could have* signed a historical transaction, which has no security relevance

The HNDL risk exists only for the *current* key (which is in-use) and the *recovery key* (if long-lived). The current key is protected by the rotation mechanism. The recovery key a potential weak link — see Finding 2a3.

### 2.6 Mempool Exposure (ECDSA-Specific)

When a UserOperation is broadcast, the ECDSA signature reveals the signer's public key (via `ecrecover`). In a public mempool, this public key is visible to all observers.

**Classical adversary**: Cannot derive the private key from the public key. No risk.

**Quantum adversary**: Can (eventually) derive the private key. Must do so within `Δ_max` to front-run. Currently infeasible per §2.2.

**Private mempool**: Eliminates public exposure. The only entities that see the public key are the private mempool operator and the block proposer. This narrows the attack surface to a colluding operator+proposer.

### 2.7 Composability

**EIP-1271**: ECDSA signatures can be verified in a read-only path without consuming the key (since ECDSA is not one-time). The smart account can implement `isValidSignature` that verifies an ECDSA signature against the current signer address without triggering rotation. This is straightforward and has no security concerns.

**Permits / SIWE / WalletConnect**: The current signer can produce off-chain signatures freely. The only caveat is that the signer may rotate between the time the off-chain signature is produced and the time it is used. The verifying contract must check the signature against the signer that was active at the time of signing, not the current signer. This is a general EIP-1271 consideration, not specific to this protocol.

**Multisig**: Works naturally. Each signer's smart account presents a stable address. The multisig coordination happens at the smart account level; key rotation is internal to each signer.

**[FINDING-2a4] ECDSA-only has the simplest composability — Severity: Informational (positive)**

Since ECDSA tolerates multiple signatures and is widely supported by existing tooling, the ECDSA-only instantiation avoids all the off-chain signature tensions that affect OTS-based designs. EIP-1271, permits, SIWE, and multisig all work with minimal friction. This is a significant practical advantage.
