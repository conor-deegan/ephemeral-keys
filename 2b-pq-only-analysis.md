# 2b. PQ-Only Instantiation Analysis: WOTS+C Primary + Hash-Based Recovery

**Scope**: The rotation protocol instantiated with WOTS+C as the primary signing scheme and a hash-based scheme for recovery/backup. No ECDSA component. All findings from the [abstract protocol analysis](1-abstract-protocol-analysis.md) apply; this document covers WOTS+C-specific and recovery-specific concerns.

**Last updated**: 2026-04-09

---

## 1. Instantiation Summary

- **Primary signer**: WOTS+C (Winternitz One-Time Signature, Compressed)
- **Parameters**: `n = 16 bytes` (128-bit security parameter), `w = 256` (Winternitz parameter), `l = 16` chains
- **Signature size**: 292 bytes (l × n + 32-byte randomness + 4-byte counter)
- **On-chain commitment**: `hash(pk_n)` - a single hash of the WOTS+C public key at index `n`
- **Verification**: Reconstruct public key from signature (16 hash chain evaluations), hash it, compare to stored commitment
- **Recovery signer**: Hash-based — candidate schemes: WOTS+C pool, SPHINCS+, FORS
- **Key derivation**: Unspecified "BIP-44-like" derivation from root seed

---

## 2. Security Analysis

### 2.1 Post-Quantum Unforgeability

WOTS+C is EU-1CMA secure (existentially unforgeable under one chosen-message attack) under the standard model, assuming second-preimage resistance and PRF security of the hash function ([Hülsing, 2017](https://eprint.iacr.org/2017/965)).

**Concrete security at `n = 16`**:
- Classical: 128-bit (meets NIST Level 1)
- Quantum: 64-bit against Grover-based preimage attacks

**[FINDING-2b1] `n = 16` provides 64-bit quantum security — adequate for single-target, marginal for multi-target — Severity: Low**

In a single-target setting, 64-bit quantum security is the NIST Level 1 floor and is generally considered sufficient for the foreseeable future (Grover's algorithm on 128-bit preimages requires ~2^64 quantum queries, which is impractical).

In a multi-target setting with `L` active keys in the ecosystem, effective security is `64 - log2(L)` bits. For L = 2^20 (≈1 million active wallets), this is 44 bits. Whether this is concerning depends on the cost model for quantum queries — at current projected costs, 2^44 quantum hash evaluations remain infeasible.

**Recommendation**: For a conservative long-term parameter choice, `n = 20` (160-bit classical / 80-bit quantum) provides meaningful margin at a signature cost of 356 bytes. For maximum conservatism, `n = 32` (256-bit classical / 128-bit quantum) at 548 bytes. This is an engineering decision.

### 2.2 One-Time Use

Every aspect of this instantiation's security rests on enforcing that each WOTS+C key is used to produce exactly one signature. This section analyses the failure modes in detail.

#### 2.2.1 What Goes Wrong with Two Signatures

Each signature reveals one hash chain value per message chain, at the position determined by the message digest.

For a message digest `d = (d_1, ..., d_16)` where each `d_i ∈ {0, ..., 255}`, the signature reveals the value at position `d_i` in chain `i`. An observer who knows this value can compute all values at positions `d_i, d_i+1, ..., 255` by iterating the hash function forward.

**Two signatures** at the same key with digests `d` and `d'` reveal:
- Chain `i`: values at positions `d_i` and `d'_i`
- The adversary knows all values at positions `min(d_i, d'_i)` through `255`

The adversary can forge a signature for any message with digest `m` satisfying `m_i >= min(d_i, d'_i)` for all message chains `i`.

**Without checksum**: For uniformly random digests, `E[min(d_i, d'_i)] ≈ 85`. The expected fraction of forgeable messages is `(171/256)^16 ≈ 0.0016` — roughly 0.16%, or 1 in 640 messages.

**With checksum** (standard WOTS+): The checksum chains constrain forgery further. Increasing message digits (to satisfy `m_i >= min(d_i, d'_i)`) decreases the checksum value, which requires going *backward* in checksum chains — computationally infeasible. The adversary must find messages where the increased message digits are balanced such that checksum chain positions remain computable from known values. This reduces the forgeable fraction below 0.16%, though the exact bound depends on the checksum parameterisation (this will need more research).

**[FINDING-2b2] Two-signature leakage under WOTS+C enables non-trivial forgery — Severity: High**

Even with the checksum constraining the forgeable space, an adversary who observes two signatures under the same key has a meaningful advantage. The adversary controls the forged message (they choose the transaction calldata) and can grind through candidates cheaply — each attempt is just hash evaluations and inequality checks.

**Practical exploitability**: The adversary needs:
1. Two signatures under the same key to be broadcast (mempool observation)
2. The ability to construct a transaction whose digest falls in the forgeable region AND satisfies the checksum constraint
3. The forged transaction to be valid on-chain (correct nonce, sufficient gas, etc.)

Step 2 is feasible given enough grinding, though the checksum makes it harder than the naive 1-in-640 estimate suggests. The exact cost depends on parameters not yet specified.

**Mitigations** (in order of effectiveness):
1. **Never produce two signatures at the same index**: Mark key as consumed at signing time. Burn the key on any failure.
2. **Deterministic WOTS+C signing**: If the WOTS+C signature is a deterministic function of (key, message), then re-signing the *exact same message* produces the *exact same signature* — no new information is leaked. This protects against exact retries but not against retries with modified gas parameters.
3. **Smaller `w`**: With `w = 16`, each chain has 16 positions. Two signatures leak fewer exploitable values, and the fraction of forgeable messages drops significantly. However, `l` increases (more chains needed for the same security), increasing signature size.
4. **FORS instead of WOTS+C**: FORS (Few-time signatures) is designed to tolerate a bounded number of signatures per key. See §2.5.

#### 2.2.2 Failure Scenarios That Cause Reuse

| Scenario | Likelihood | Two Different Messages? | Mitigation |
|---|---|---|---|
| Transaction dropped, user retries with same params | Common | No (if deterministic signing) | Deterministic signing eliminates risk |
| Transaction dropped, user retries with updated gas | Common | **Yes** — different gas = different digest | Burn key, use next index |
| Two devices race to sign with same index | Uncommon but possible | **Yes** — different transactions | Single-device constraint |
| Block reorg reverts rotation, user resigns | Rare | Likely yes | Use recovery path, not primary key |
| Wallet state corruption causes index reuse | Rare | **Yes** | On-chain state resync |

The "dropped transaction with gas adjustment" is the most dangerous scenario because it is **both common and produces different messages**. The protocol must ensure the wallet never adjusts gas and resigns with the same key — it must burn the key and advance to the next index.

### 2.3 Key Derivation Function

**[FINDING-2b3] The WOTS+C key derivation function is unspecified — Severity: High**

**Recommended construction**:

```
chain_seed[i][j] = HKDF-Expand(
    PRK = HKDF-Extract(seed, "WOTS+C"),
    info = encode(key_index=i, chain_index=j),
    length = n
)
```

Where `seed` is the root seed and `i` and `j` are the key index and chain index respectively and `n` is the length of the chain seed.

Using SHA-256 or Keccak-256 as the underlying hash. HKDF (RFC 5869) is standard, well-analysed, and quantum-safe when instantiated with a quantum-safe hash.

### 2.4 Recovery Path Options

When the primary WOTS+C key is consumed without successful on-chain rotation (transaction dropped, mempool failure), the recovery path must:
1. Authenticate the rotation request
2. Update the on-chain signer commitment to a fresh WOTS+C key
3. Not execute arbitrary transactions (scope limitation)
4. Be post-quantum secure (otherwise it's a downgrade vector)

#### 2.4.1 Option A: Pre-Committed WOTS+C Pool

Register `k` backup WOTS+C keys at account creation (or replenish during normal operations). Each backup key can trigger exactly one rotation.

**Pros**: Same security properties as primary path. Same signature size. Pool is finite (natural rate limiting).

**Cons**: Pool exhaustion after `k` consecutive failures. Requires on-chain storage for `k` key hashes. Pool replenishment requires primary-path transactions.

**Security**: Sound, assuming each pool key is used at most once. Pool exhaustion under sustained censorship is a liveness concern.

**Recommended pool size**: `k = 4`. The probability of 4 consecutive primary failures without any successful transaction is very low under normal conditions.

#### 2.4.2 Option B: SPHINCS+ (Stateless Hash-Based)

A single SPHINCS+ key registered as a recovery signer. Stateless — can be used arbitrarily many times without security degradation.

**Pros**: No pool management. No reuse risk. No exhaustion. Natively PQ. Well-analysed (SLH-DSA, NIST FIPS 205).

**Cons**: Signature size: 7,856 bytes (SPHINCS+-SHA2-128s) to 49,856 bytes (SPHINCS+-SHA2-256f). Verification gas is high.

**Security**: The SPHINCS+ recovery key is long-lived (registered once, never rotated). However, since SPHINCS+ is stateless and PQ-secure, long-term key exposure does not create a quantum vulnerability. The public key hash is on-chain, but the public key itself is not exposed until first use. After first use, the public key is known — but SPHINCS+ security does not depend on public key secrecy.

**[FINDING-2b4] SPHINCS+ recovery is sound but creates a two-tier signature size profile — Severity: Low**

Under normal operation: small WOTS+C signatures. Under recovery: large SPHINCS+ signatures. If recovery is rare (<1% of transactions), the average signature size remains close to 292 bytes. If recovery is common, the effective signature profile approaches the SPHINCS+-only, negating the WOTS+C advantage.

#### 2.4.3 Option C: FORS (Few-Time Signature)

A FORS key registered as a recovery signer. FORS allows a configurable number of signatures before security degrades.

**Pros**: Smaller signatures than SPHINCS+. Tolerates bounded reuse. PQ-secure.

**Cons**: Security degrades with each use. After `k` signatures, the forgery probability becomes non-negligible. Parameters must be chosen for the expected number of recovery operations.

**[FINDING-2b5] WOTS+C is the best-fit recovery scheme for the PQ-only instantiation — Severity: Informational**

**Recommendation**: Use WOTS+C for recovery.

### 2.5 Composability (EIP-1271 and Off-Chain Signatures)

**[FINDING-2b7] EIP-1271 is fundamentally incompatible with one-time WOTS+C signatures — Severity: High**

`isValidSignature` is a `view` function. It cannot modify state — no rotation, no bitmap update, no key consumption. But verifying a WOTS+C signature exposes the signature (and its chain values) publicly. If the user then signs an on-chain transaction with the same key, two signatures exist and the two-signature leakage from §2.2.1 applies.

There is no way to "consume" a key during a read-only call. The off-chain signing pattern (sign, then submit to a third-party contract for validation) is structurally incompatible with one-time signatures.

**Options considered**:

1. **Don't support EIP-1271 at all.** Return `isValidSignature = invalid`. Off-chain flows (permits, SIWE, WalletConnect, Safe composition) are unsupported. Simplest, most limiting.

2. **Separate key space for off-chain.** Store a second commitment for off-chain verification. `isValidSignature` checks this; `validateUserOp` checks the primary. But the off-chain key is long-lived — a `view` function cannot rotate it — so the second use with a different message triggers the same two-signature leakage.

3. **Use a stateless scheme for off-chain.** Register a SPHINCS+ key for off-chain use. Stateless = unlimited signatures, no reuse risk. But signatures are large (7.8+ KB) and verification is expensive for on-chain `isValidSignature` calls (e.g., permit execution).

4. **Burn the primary key on off-chain use.** Treat off-chain signing as consuming the primary key and immediately submit an on-chain rotation. Preserves one-time use but requires an on-chain transaction per off-chain signature.

**Assessment**: There is no clean solution. Option 1 (no EIP-1271) is the only approach that fully preserves the WOTS+C security guarantee. Options 2-4 each re-introduce a long-lived key, large signatures, or an on-chain round-trip. This is a fundamental limitation of one-time signatures.

For the PQ-only instantiation, the protocol should be explicit: **EIP-1271 off-chain verification is not natively supported with WOTS+C keys.**

### 2.6 Hash Function Selection

**[FINDING-2b8] The hash function choice must be specified — Severity: High**

The WOTS+C security proof requires:
1. **Second-preimage resistance** of the chain hash function
2. **PRF security** of the key derivation function

The most natural choice for EVM is **Keccak-256** (available as a precompile). SHA-256 is also available as a precompile.

**Keccak-256 considerations**:
- NIST SHA-3 standard — well-analysed
- Quantum security: 128-bit preimage resistance against Grover (for 256-bit output)
- When truncating to `n = 16` bytes for WOTS+C chain values: the truncation must preserve second-preimage resistance at the `n`-byte level. Standard results show that truncating a random oracle to `n` bytes preserves `n`-byte second-preimage resistance.

**SHA-256 considerations**:
- Merkle-Damgård construction. Susceptible to length-extension attacks (not relevant for WOTS+C use).
- Same quantum security profile as Keccak-256 for the properties needed here.
- 2x gas cost on EVM.

**Recommendation**: Keccak-256 for gas efficiency. Document that the security claim relies on Keccak-256's second-preimage resistance at the `n`-byte truncation level.
