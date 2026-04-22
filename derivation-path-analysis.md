# Derivation Paths

**Last updated**: 2026-04-22

---

A wallet supporting ephemeral keys derives four kinds of signing keys from a single BIP-39 mnemonic:

- WOTS+C ephemeral signers, for transactions.
- ECDSA ephemeral signers, for ECDSA mode or the ECDSA half of a hybrid.
- An EIP-1271 permit signer ([Annex A](protocol-spec-annex-a.md)).
- A stateless post-quantum recovery signer.

The derivation proceeds in three stages: mnemonic → seeds, seeds → BIP-32 tree, tree → leaf keys. WOTS+C leaves then have one additional expansion step to produce the chain seeds the signature scheme needs.

## Stage 1: mnemonic -> seeds

The mnemonic is standard BIP-39, 24 words, 256 bits of entropy. BIP-39's PBKDF2-HMAC-SHA512 stage produces two seeds from it, depending on the passphrase:

- `S_rec = BIP39-Seed(mnemonic, "")` — the **recovery seed**. Empty passphrase. Reproducible from the mnemonic alone by any BIP-39 tool.
- `S_wal = BIP39-Seed(mnemonic, "ephemeral-keys:v1:" || wallet_id)` — the **wallet-bound seed**. Non-empty passphrase including a per-install identifier (`wallet_id`, covered in Stage 2).

The two seeds produce disjoint BIP-32 trees. The recovery tree is always derivable from the mnemonic alone; the wallet-bound tree additionally requires `wallet_id`. This split means the 24-word mnemonic is a complete backup: if the device and `wallet_id` are lost together, the recovery signer (rooted in `S_rec`) can still rotate the on-chain wallet to a fresh signer stream.

## Stage 2: `wallet_id`

`wallet_id` is a 32-byte per-install identifier. Uniqueness across wallets sharing the same mnemonic is the only hard requirement: two wallets with the same `wallet_id` on the same mnemonic would produce identical WOTS+C streams, which is catastrophic for a one-time signature scheme.

It is generated at wallet first-run as:

```
wallet_id = HKDF-Extract(salt = "ephemeral-keys-wallet-id", ikm = install_entropy)
```

where `install_entropy` is 32 bytes from the platform CSPRNG, stored in the device's secure enclave or equivalent..

`wallet_id` is not secret but is requiured. If the stored `wallet_id` is lost, the recovery path should be used.

## Stage 3: seeds -> BIP-32

Both seeds are fed into standard BIP-32 (`HMAC-SHA512("Bitcoin seed", S)`), then derived down with hardened indices at every level. Hardening every level is a deviation from standard BIP-44, which leaves `change` and `address_index` non-hardened to enable xpub-based watch-only wallets. Under BIP-32, one non-hardened child private key plus the parent xpub reveals every sibling. In this wallet every sibling is a signing key, so non-hardened derivation would turn a single-leaf compromise into a full-branch compromise. Watch-only export via xpub was already meaningless for WOTS+C, where the on-chain "public key" is a hash commitment that changes every transaction, so there is no cost.

## Stage 4: four leaf paths

```
m / 44' / 60' / 0'   / 0' / i'    — WOTS+C ephemeral         [S_wal]
m / 44' / 60' / 1'   / 0' / i'    — ECDSA ephemeral           [S_wal]
m / 44' / 60' / 2'   / 0' / i'    — Permit signer             [S_wal]
m / 44' / 60' / 100' / 0' / 0'    — SLH-DSA recovery          [S_rec]
```

BIP-44 with SLIP-44 coin type 60 (Ethereum) keeps the mnemonic importable into any standard-compliant tool. Each key kind lives under its own BIP-44 account, so no two streams share an ancestor below the account level and their rotation cadences are independent. The three wallet-bound paths draw from `S_wal`; the recovery path draws from `S_rec`.

The 2³¹ hardened-index space per account is effectively unbounded: at 100 transactions per day, exhaustion takes around 58,000 years.

## Stage 5: WOTS+C leaf expansion

A BIP-32 leaf is a single 32-byte secret. WOTS+C at parameters `(n, l)` needs `l` independent `n`-byte chain seeds, so WOTS+C leaves have one extra expansion step before keygen:

```
PRK_i        = HKDF-Extract(salt = "EPHEMERAL-WOTS+C-v1", ikm = sk_i)
chain_seed_j = HKDF-Expand(PRK_i, info = LE32(j), length = n)    for j in [0, l)
```

HKDF is instantiated with HMAC-Keccak-256, the same hash used on the EVM and in the WOTS+C chain walk, so only one hash function appears in the security reduction. The `-v1` suffix in the salt means any future parameter change produces a disjoint chain-seed space by construction. The 32-byte BIP-32 leaf is discarded after expansion.

This step does not apply to the other three paths. ECDSA and permit leaves are used directly as secp256k1 scalars; the recovery leaf is passed to SLH-DSA's own keygen.

## Quantum-safety of the derivation

Every step from mnemonic to leaf reduces to the preimage or second-preimage resistance of a hash function: PBKDF2-HMAC-SHA512 for the seed, HMAC-SHA512 for BIP-32, HKDF-HMAC-Keccak-256 for WOTS+C leaf expansion, and SLH-DSA's own hash-based keygen for recovery. The ECDSA leaf is a modular reduction of a 32-byte value with no hardness assumption attached. Nothing in the derivation depends on discrete log or factoring. The ECDSA signing path is quantum-vulnerable by construction, but the derivation that produces the ECDSA scalar is not.
