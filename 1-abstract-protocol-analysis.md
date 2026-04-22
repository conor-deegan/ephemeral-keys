# 1. Abstract Protocol Analysis: Ephemeral Key Rotation via Account Abstraction

**Scope**: The rotation mechanism itself — primitive-agnostic. This analysis covers the system design independent of whether the signing slots are filled by ECDSA, WOTS+C, a hybrid, or any other scheme. Primitive-specific concerns are covered in the companion documents (2a, 2b, 2c).

**Last updated**: 2026-04-09

---

## 1. System Model

The protocol is a key-rotation layer built on ERC-4337 Account Abstraction. It has three components:

**On-chain (Smart Account)**:

- Stores a commitment to the current authorised signer (e.g., an address, a public key hash, or a Merkle root — the exact form depends on the primitive)
- Validates signatures against the current commitment
- Executes the user's intended transaction
- Rotates the commitment to the next signer
- (Optionally) maintains a record of spent keys

**Off-chain (Wallet)**:

- Holds long-term key material (seed/root key)
- Derives ephemeral signing keys from a deterministic sequence
- Tracks the current key index
- Signs one transaction per key, then advances the index

**Infrastructure (Bundler / EntryPoint)**:

- Receives UserOperations from the wallet
- Submits them to the ERC-4337 EntryPoint
- EntryPoint calls `validateUserOp` then executes the call

The user's stable on-chain identity is the smart account address. The signer rotates; the account does not.

---

## 2. Primitive-Agnostic Security Properties

### 2.1 Rotation Atomicity

**Requirement**: The signer rotation must occur atomically with (or unconditionally after) signature validation. If the rotation can be separated from validation, there exists a window where the old signer is validated but not yet rotated out.

**Design choice: rotation in validation vs. execution**

There are two approaches:


|                       | Rotation in `validateUserOp`                                                         | Rotation in `execute`                                                                           |
| --------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| Persistence guarantee | Validation-phase state changes persist even if execution reverts (ERC-4337 property) | If `execute` itself reverts, rotation does not occur                                            |
| Inner call failure    | Rotation occurs regardless — correct behaviour                                       | Must catch inner call failures to prevent rotation from being blocked by a reverting inner call |
| Complexity            | Simpler — rotation is unconditional                                                  | Must handle inner-call error propagation carefully                                              |


**[FINDING-A1] Rotation in the validation phase is strictly safer — Severity: Informational**

Rotating during `validateUserOp` guarantees the old key is retired regardless of what happens in the execution phase. Rotating during `execute` requires the implementation to catch all revert paths and still rotate — a more error-prone pattern. Any implementation should prefer validation-phase rotation where the execution environment supports it.

### 2.2 Next-Key Commitment Authentication

**Requirement**: The commitment to the next signer (address, public key hash, etc.) must be included in the data authenticated by the current signature. If it is not, any intermediary (bundler, MEV searcher, mempool observer) can substitute a different next-key commitment and take over the account.

**[FINDING-A2] Unauthenticated next-key commitment = complete account takeover — Severity: Critical (design requirement)**

This is the single most important correctness property of the abstract protocol. Regardless of the signing primitive:

- The signed message must include the next-signer commitment
- In ERC-4337, the `signature` field is excluded from `userOpHash`. Therefore, the next-signer commitment must NOT be placed in the `signature` field — it must be in `callData` or another signed field
- Any implementation that places the next-signer commitment in an unsigned field is fundamentally broken

This is not an attack that requires cryptographic sophistication — it requires only the ability to modify a UserOperation in transit, which every bundler inherently has.

### 2.3 Key Consumption Semantics

**The problem**: At what point is a key "consumed"? This sounds a bit abstract but it determines what happens during transaction failures and retries.

There are four candidate consumption points:


| Point              | Meaning                                                            | Consequence                                                                |
| ------------------ | ------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| **Signing time**   | Key is consumed when the wallet signs                              | Dropped transactions burn a key. Most conservative.                        |
| **Broadcast time** | Key is consumed when the UserOperation enters the mempool          | Same practical effect as signing time.                                     |
| **Inclusion time** | Key is consumed when the block containing the rotation is produced | Allows retry with the same key if not yet included. Risky for OTS schemes. |
| **Finality time**  | Key is consumed when the block is finalised                        | Allows retry until finality. Reorgs can re-expose a consumed key.          |


**[FINDING-A3] The only safe consumption point is signing time — Severity: High**

For one-time signature schemes, any consumption point after signing creates a window where:

1. The signature is broadcast (public key exposed)
2. The transaction is not yet on-chain
3. The user might resign with the same key (for retry, gas adjustment, etc.)
4. Two signatures under the same key are now public

Even for schemes that tolerate multiple signatures (like ECDSA), the principle of "consumed at signing" simplifies the state machine and eliminates an entire class of race conditions.

The protocol should mandate: **once a key is used to produce a signature, it is irrevocably consumed, regardless of whether the transaction lands on-chain.** The wallet must advance its index at signing time, not at confirmation time.

This means dropped transactions burn keys. The protocol must accept this as a cost of security and size the key space accordingly (BIP-32 supports 2^31 indices — even burning 100 keys/day exhausts the space in ~58,000 years).

The general guidance is that before a signature is released from the signing device, it is considered "consumed" and should be advanced to the next key.

### 2.4 State Synchronisation

The protocol has split state: the wallet tracks `currentIndex` (or some variant) locally, and the smart account stores the current signer commitment on-chain. Every effort should be made for these to be consistent.

**Desynchronisation causes**:

1. Wallet crash after signing but before updating local index
2. Transaction dropped by bundler (local index advanced, on-chain state unchanged)
3. Block reorg reverts a rotation (on-chain state reverts, local index does not)
4. Multiple wallet instances (tabs, devices) racing to sign
5. localStorage corruption or clearing

**Recovery mechanism**: The wallet must be able to resynchronise by reading the on-chain signer commitment and scanning its derivation tree to find the matching index. This is O(n) in the number of past transactions.

**[FINDING-A4] Resynchronisation requires the on-chain commitment to be deterministically matchable — Severity: Low**

The wallet must be able to compute `commitment(pk_i)` for arbitrary index `i` and compare it to the on-chain value. This is straightforward for address-based commitments (derive key, compute address, compare) but may be non-trivial for more complex commitment structures (e.g., Merkle roots, nested hashes). The commitment scheme must support efficient forward scanning.

### 2.5 Single-Device Constraint

**[FINDING-A5] Sequential key rotation inherently requires single-device signing — Severity: High (adoption constraint)**

If two devices independently derive key `i` and both attempt to sign, one of two outcomes occurs:

1. Both sign with key `i`: if the scheme is OTS, this creates a key-reuse vulnerability. If the scheme tolerates reuse (ECDSA), the first-included transaction rotates the signer, and the second becomes invalid.
2. One device signs with key `i`, the other with key `i+1`: only key `i` matches the on-chain signer. The key `i+1` transaction fails.

There is no resolution within the current design that allows concurrent multi-device signing without external coordination. This is a fundamental consequence of sequential key rotation. The design should document this constraint plainly - it will be a major factor in wallet UX and institutional adoption decisions.

### 2.6 Mempool Exposure

When a UserOperation is broadcast to the public mempool, the current signer's signature (and potentially the public key, depending on the scheme) is visible to all observers. This creates a time window between exposure and rotation (when the transaction is included on-chain).

The severity of this exposure depends entirely on the primitive:

- **ECDSA**: Public key is exposed. A quantum adversary with sufficient speed could derive the private key and front-run.
- **WOTS+C**: Signature reveals chain values. But the key is one-time, and if the signature is included, the key is immediately rotated. An observer who records the signature gains nothing useful (the key is spent).
- **Hybrid**: Both signatures are exposed. The WOTS+C signature is safe; the ECDSA component has the same quantum exposure as pure ECDSA.

**[FINDING-A6] Mempool exposure is a primitive-specific risk, not a protocol-level risk — Severity: Informational**

The abstract rotation protocol does not create the mempool exposure — the mempool does. The protocol's contribution is minimising the exposure window (one transaction per key) and ensuring rotation happens. The residual risk depends entirely on the primitive's properties under observation, which is analysed in the companion documents.

Private mempools (e.g., Flashbots Protect) eliminate public exposure entirely but transfer trust to the mempool operator.

### 2.7 Recovery / Backup Path (Abstract)

When the primary signing path fails (transaction dropped, key burned without rotation), the protocol needs a recovery mechanism to rotate to a fresh key without using the (now-consumed) primary key.

**Abstract requirements for any recovery mechanism**:

1. **Authentication**: The recovery signature must prove authorisation to rotate the signer. A recovery signer must be pre-registered on-chain.
2. **Scope limitation**: Recovery should only be able to rotate the signer — not execute arbitrary transactions. This limits the damage if a recovery key is compromised.
3. **Rate limiting**: Recovery should be naturally bounded (e.g., finite pool of recovery keys) to prevent abuse.
4. **Non-interference**: Recovery must not degrade the security of the primary path. If recovery uses a weaker primitive, it becomes the binding constraint on overall security.

**[FINDING-A7] The recovery path sets the security floor for the system — Severity: High**

The system's security is `min(primary_path_security, recovery_path_security)`. If the primary path uses a strong post-quantum scheme but recovery falls back to a quantum-vulnerable scheme, the effective security is quantum-vulnerable. An adversary who can force the recovery path (e.g., by censoring primary transactions) can exploit whatever weakness the recovery scheme has.

### 2.8 On-Chain State Growth

The protocol stores per-account state: the current signer commitment and (optionally) a spent-key bitmap. The signer commitment is a single storage slot, overwritten each rotation (no growth). The spent-key bitmap grows by one slot per 256 transactions.

**[FINDING-A8] Spent-key bitmap is defence-in-depth, not strictly required — Severity: Informational**

The commitment check alone prevents replay of old keys (the stored commitment has moved on). The bitmap adds protection against rotation to a previously-used key index — a real concern if the wallet has a bug, but not a protocol-level threat. Whether the gas cost justifies the defence-in-depth is an engineering call.

### 2.9 Composability

#### 2.9.1 EIP-1271 (Off-Chain Signature Verification)

Many protocols verify smart account signatures via EIP-1271 `isValidSignature`. The rotating signer design must accommodate both:

- On-chain rotation verification **must** consume the key (advance the signer)
- Off-chain verification via EIP-1271 **must not** consume the key (it's a read-only query)

**[FINDING-A9] The protocol must define a non-consuming verification path for EIP-1271 — Severity: High**

Without this:

- Permit flows, SIWE, WalletConnect, and Safe composition fail
- The smart account is incompatible with a significant portion of the Ethereum ecosystem

The non-consuming path verifies the signature against the current commitment but does not trigger rotation or mark the key as spent. This is straightforward to implement but creates a subtle interaction for OTS schemes: the off-chain signature exposes the same key material as the on-chain signature. If a user signs off-chain (EIP-1271) and then signs on-chain with the same key, two signatures exist under the same key. The severity of this depends on the primitive (see companion documents).

#### 2.9.2 Multisig / Safe Composition

In a Safe-style multisig, each signer is a smart account. The Safe sees each signer's smart account address (stable). Signature collection happens off-chain via EIP-1271, then the Safe executes on-chain.

This works architecturally but inherits the EIP-1271 key-consumption tension from §2.9.1.

#### 2.9.3 Standard DApp Interactions

For standard ERC-4337 transactions (dApp receives a call from the smart account), nothing changes — dApps see only the smart account address. No dApp modifications needed.

Non-standard interactions that expect a direct EOA signature (raw `ecrecover` for permits, session keys derived from the signer) will need to route through EIP-1271 or be redesigned.

### 2.10 Block Reorganisations

**[FINDING-A10] Reorgs can re-expose a rotated key — Severity: Medium**

If a block containing a rotation transaction is reorged out:

1. The on-chain state reverts to the previous signer commitment
2. The wallet's local index has already advanced (key consumed at signing time per A3)
3. The previous key's signature was already broadcast publicly
4. The previous key is now the active on-chain signer again

For OTS schemes, this is concerning: the key was used to sign the (now-reverted) transaction, and may need to be used again to submit a new rotation. This constitutes a second use of a one-time key.

For multi-signature schemes (ECDSA), this is less severe — the key can be reused safely.

**Mitigation**: The wallet should treat keys as consumed but monitor for reorgs. If a reorg is detected, the wallet should use the recovery path to rotate away from the re-exposed key rather than reusing it.