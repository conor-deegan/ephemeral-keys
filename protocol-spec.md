## Abstract

NiceTry is a quantum-safe smart wallet infrastructure for Ethereum. The core design leverages ERC-4337 account abstraction to enforce single-use signing keys: each key pair is used exactly once and rotated post-execution, while the smart account address remains constant. This eliminates long-term public key exposure, the attack surface that Shor's algorithm exploits against ECDSA, without requiring any changes to Ethereum's protocol. A second mode replaces ECDSA with WOTS+C (Winternitz One-Time Signature Plus, Compressed), a hash-based one-time signature scheme whose security reduces to preimage resistance rather than discrete log hardness, closing the residual vulnerability present in the ECDSA design.

## Motivation

Ethereum accounts are secured by ECDSA over the secp256k1 curve. The private key never appears on-chain; only the public key or its hash is exposed when a transaction is signed. This design is secure against classical computers because computing a discrete logarithm over an elliptic curve group is believed to be computationally infeasible.  
That assumption breaks under Shor's algorithm. A quantum computer with sufficient qubit fidelity and count can recover an ECDSA private key from a public key in polynomial time. Current expert estimates place a cryptographically relevant quantum computer, one capable of breaking 256-bit elliptic curve cryptography, at roughly 5 to 10 years away, with significant uncertainty in both directions. The threat is not immediate, but the preparation window is.  
Upgrading Ethereum's signature infrastructure is a multi-year process requiring EVM opcode changes, new precompiles, wallet software updates, and ecosystem-wide coordination. Historical precedent from SHA-1 deprecation and early TLS migrations suggests that even after standardization, actual adoption takes years. NiceTry is an alternative available today: a wallet that achieves quantum safety without any dependency on Ethereum protocol changes, and without waiting for ecosystem convergence on a post-quantum standard.

### Threat Model Summary

We consider an adversary who can observe all on-chain and mempool data and can perform Shor's algorithm to recover an ECDSA private key from an observed public key. The adversary cannot break preimage resistance or collision resistance of SHA-2 or Keccak-256. Additionally, we assume the adversary cannot censor the Ethereum mempool indefinitely. The timing assumption is that the adversary's quantum computation takes longer than a single Ethereum block (currently 12 seconds), meaning the attack window is the mempool interval between transaction submission and inclusion.

## Protocol Overview

NiceTry is a smart contract wallet conforming to ERC-4337 (Account Abstraction). It exposes a single, stable address to the user and supports two independent signing modes, which can be used alternatively, each with different security properties and tradeoffs.

**ECDSA mode** is the simpler of the two. The account holds a single authorized signer address. Each signing key is used exactly once: after every transaction, the signer rotates to a fresh ECDSA key pair, while the smart account address never changes. This eliminates the long-term public key exposure that Shor's algorithm exploits, using only standard secp256k1 infrastructure available today. The one residual vulnerability is the mempool window: between broadcast and inclusion, the signature, and therefore the public key, is briefly visible, making it possible for a sufficiently fast quantum adversary to use this window to recover the private key and front-run the transaction.

**WOTS+C mode** closes that window: rather than ECDSA, the account uses WOTS+C (Winternitz One-Time Signature Plus, Compressed), a hash-based one-time signature scheme whose security reduces to preimage resistance rather than discrete log hardness. A WOTS+C signature does not expose a public key that can be inverted, observing a signature in the mempool gives an adversary nothing actionable. Key rotation still occurs after every transaction, and the on-chain state remains a single hash commitment to the current key. The signature is NIST security level 1.

Both modes are implemented as an ERC-4337 smart account and, separately, as an ERC-7579 validator module installable on any compliant modular account.

## Definitions and Notation

**`sk`** — Signing private key. Never stored or transmitted on-chain.

**`pk`** — Signing public key corresponding to `sk`.

**`addr(pk)`** — Ethereum address derived from an ECDSA public key. The on-chain signer identifier in ECDSA mode.

**`H(pk)`** — Hash of a serialized public key. The on-chain signer identifier in WOTS+C mode.

**`sk_i`, `pk_i`** — The signing key pair at index `i`. Derived deterministically from the user's seed.

**`seed`** — The user's master secret. Stored only on the client device. All key pairs are derived from it.

**`n`** — WOTS+C security parameter. Byte-length of each hash output and chain element.

**`w`** — Winternitz parameter. Controls the tradeoff between chain length and signature size.

**`l`** — Number of hash chains in a WOTS+C key pair. A function of `n` and `w`.

**`sig`** — A signature over the ERC-4337 UserOp hash. 65 bytes in ECDSA mode; `l·n + overhead` bytes in WOTS+C mode.

**`ephemeral key`** — Any key pair `(sk_i, pk_i)` valid for exactly one signing operation before rotation. Applies to both modes.

### WOTS+C Parameters

WOTS+C is parameterized by `n` and `w`. The number of chains `l` is determined by `n` and `w`. The **C** in WOTS+C stands for **Compression**: the signer brute-forces a short counter appended to the message such that the resulting digest always produces a fixed, known checksum, allowing the checksum chains to be dropped from the signature entirely. The `+` is inherited from WOTS+, the tweaked-hash variant. Concrete values for `n`, `w`, `l`, and the resulting signature size are given in Section 7.

## Account Architecture

### Smart Account Contract Layout

NiceTry is deployed as a non-upgradeable smart contract. The current signer identifier: either `addr(pk_i)` for ECDSA mode or `H(pk_i)` for WOTS+C mode. A single storage slot tracks the signer identity, advancing the key after each transaction is an atomic update to that slot.

### ERC-7579 Module Compatibility

The validation logic is also packaged as a standalone ERC-7579 validator module. Users with an existing compliant modular account can install the NiceTry validator without deploying a new account. The module stores its own per-account key state, keyed by account address as the outermost mapping key to satisfy ERC-7562 storage access rules.

### Validation Flow

When `validateUserOp` is called by the EntryPoint:

1. **ECDSA mode:** recover the signer address from the UserOp signature via `ecrecover` and compare against the stored `addr(pk_i)`.  
2. **WOTS+C mode:** call the WOTS+C verifier to reconstruct `pk_i` from the signature and the UserOp hash; assert `H(pk_i)` matches the stored value.  
3. If validation passes, return `SIG_VALIDATION_SUCCESS`.  
4. Rotate the signer to the new one passed in the transaction. Rotation is done atomically during the validation to minimize risk of transactions being submitted and authorized without a rotation occurring.

### Key Derivation

In both modes, key pairs are derived deterministically from `seed` using a BIP32-like path indexed by `idx`. The user never needs to store individual private keys; the seed alone is sufficient to regenerate any key at any index. In ECDSA mode the derived material is used as a secp256k1 scalar; in WOTS+C mode it feeds the WOTS+C key generation function directly.

## ECDSA Mode

### Validation

The ECDSA mode contract stores `addr(pk_i)`. When `validateUserOp` is called:

1. Recover the signer address from the UserOp signature via `ecrecover` and compare against the stored `addr(pk_i)`.  
2. If validation passes, return `SIG_VALIDATION_SUCCESS`.  
3. Atomically rotate: overwrite the stored signer with `addr(pk_{i+1})`. The next signer address must be provided by the user in the UserOp. Rotation happens during validation to ensure no authorized transaction can be finalized without advancing the key.

### Security Properties and Residual Vulnerability

Each key pair is used exactly once. An observer who sees a transaction in the mempool learns `pk_i`, but by the time the block is included, `pk_i` is already spent and the account has rotated to `pk_{i+1}`. A classical adversary gains nothing from observing spent keys.

The residual vulnerability is the mempool window: between broadcast and inclusion, a sufficiently fast quantum adversary could recover `sk_i` from the observed `pk_i` and submit a competing transaction before inclusion. This window is short, on the order of one block time, but non-zero. Private mempool relays (e.g. Flashbots Protect) eliminates it entirely by keeping the UserOp off the public mempool until inclusion.

### Key Rotation

Key rotation is done inside the `validateUserOp`, this way no authorized transaction can be finalized without advancing the key, reducing the possibility of user error.  
If one of the UserOps reverts, the rotation must go through independently. This is possible in ERC-4337, where single userOps can revert while the parent transaction is still successful.  
If the transaction fails entirely, for instance due to a wrong nonce in the transaction or insufficient gas being provided, the user key is exposed to potential quantum attackers since no rotation can be done onchain. In this case the user should be prompted to resubmit a transaction as soon as possible, to rotate the exposed signer to a fresh one. Spamming transactions has no downside in the ECDSA approach.  
The same approach goes for a transaction that is not being included and is not visible onchain after a reasonable amount of time. This could mean that a malicious node operator has read the user's `pk` and is using a quantum computer to recover the user's `sk`. In this case too the user should be advised to resubmit a transaction as soon as possible, to rotate the exposed signer to a fresh one.

### When to Use

ECDSA mode is appropriate for users operating under a classical threat model, or as a starting point for quantum resistance. It requires no changes to key management tooling beyond the rotation logic, and its gas profile is close to a standard ERC-4337 account.

## WOTS+C Mode

### Validation

The WOTS+C mode contract stores `H(pk_i)`. When `validateUserOp` is called:

1. Call the WOTS+C verifier to reconstruct `pk_i` from the signature and the UserOp hash; assert `H(pk_i)` matches the stored value.  
2. If validation passes, return `SIG_VALIDATION_SUCCESS`.  
3. Atomically rotate: overwrite the stored value with `H(pk_{i+1})`. The next public key hash must be provided by the user in the UserOp. Rotation happens during validation to ensure no authorized transaction can be finalized without advancing the key.

### Security Properties

Observing a WOTS+C signature in the mempool gives an adversary nothing actionable. Unlike ECDSA, there is no public key that can be inverted, the signature itself does not leak material that allows key recovery under any known algorithm, classical or quantum. The residual vulnerability present in the ECDSA design is eliminated.

Each key pair is still used exactly once, and in this case reuse would be catastrophic: signing two different messages with the same WOTS+C key leaks enough chain information for a classical adversary to forge signatures. The rotation-on-validation design ensures reuse cannot occur through normal contract operation.

### Backup Singers

The WOTS+C contract must support registering one or more backup signers alongside the primary WOTS+C key. A backup signer can authorize a key rotation (updating the stored `H(pk_{i+1})`) but cannot execute arbitrary calldata. This is a recovery mechanism, not an alternative execution path.

Several backup signer types are supported:

**Additional WOTS+C keys.** A secondary OTS key stored under a separate commitment. Provides the same quantum-safety guarantees as the primary signer. Multiple OTS keys can be committed this way to allow multiple recovery attempts.

**Stateless post-quantum signatures.** A backup signer using a stateless PQ scheme such as SLH-DSA. Unlike WOTS+C, a stateless scheme has no key rotation requirement and no reuse risk, making it well suited as a last-resort recovery key. The tradeoff is larger signature size and higher verification gas cost, manageable for a rare recovery operation.

**ECDSA backup.** A backup signer using a standard secp256k1 key. This is the lowest-friction option, using a fresh ECDSA key for recovery has the same vulnerabilities as the ECDSA signing mechanism, as well as the same mitigation being private mempools for this rare recovery operation.

The choice of backup signer type is left to the user. Multiple backup signers of different types can be registered simultaneously.

### Key Rotation

Key rotation is done inside the `validateUserOp`, this way no authorized transaction can be finalized without advancing the key, reducing the possibility of user error.  
If one of the UserOps reverts, the rotation must go through independently. This is possible in ERC-4337, where single userOps can revert while the parent transaction is still successful.  
If the transaction fails entirely, for instance due to a wrong nonce in the transaction or insufficient gas being provided, the user **must** use a backup signer to rotate the main signer, since using the main signer again would reuse the same OTS and allow classical attackers to forge signatures.  
Same goes if the user has signed a transaction that never shows up onchain. This means that a node operator could have maliciously blocked the user's transaction and reusing the same OTS could make the user vulnerable. In this case too the user must use a recovery method to rotate the main signer.

To avoid potentially catastrophic reuses of OTS, wallets should burn used private keys. This way there is no possibility that the user accidentally signs two times as the same signer.

### Signature Size and Gas

| w   | l  |   Security    | Target sum | Hash (verify) | Gas (verify) | Sig (blob) |
|-----|----|---------------|------------|---------------|--------------|------------|
| 4   | 64 | NIST Level 1  | 96         | 96            | ~31k         | 1076B      |
| 8   | 44 | NIST Level 1  | 154        | 154           | ~43k         | 756B       |
| 16  | 32 | NIST Level 1  | 240        | 240           | ~60k         | 564B       |
| 32  | 26 | NIST Level 1  | 403        | 403           | ~93k         | 468B       |
| 64  | 22 | NIST Level 1  | 693        | 693           | ~151k        | 404B       |
| 128 | 20 | NIST Level 1  | 1270       | 1270          | ~266k        | 372B       |
| 256 | 16 | NIST Level 1  | 2040       | 2040          | ~420k        | 308B       |

### Multi-Wallet compatibility

A WOTS+C wallet rotates signing keys after each use. 
If two wallets share the same seed and derivation path, they generate identical key sequences. 
Any independent advancement of the epoch counter on either wallet risks reusing the same one-time key, which breaks the scheme entirely.
We developed a way to deal with this involving separate signers assigned to each wallet, derived from completely different derivation paths. 
More details can be found in [Annex B](https://github.com/conor-deegan/ephemeral-keys/blob/cd-sec-analysis-1/protocol-spec-annex-b.md).

## ERC Compatibility

### ERC-4337 Conformance

Both the ECDSA and WOTS+C contracts implement the `IAccount` interface defined by ERC-4337. A notable deviation from common implementations is that both contracts write state during `validateUserOp`: the signer commitment is rotated atomically at validation time rather than during execution. This is intentional and does not break ERC-4337 conformance, but has two consequences worth documenting:

- **Revert behavior:** if the inner transaction reverts, the key rotation has already occurred. A failed transaction consumes a key just as a successful one does.  
- **Bundler compatibility:** bundlers simulate `validateUserOp` before inclusion. Since state written during simulation is not visible to subsequent simulations in the same bundle, bundlers must not include more than one pending UserOp per sender in a bundle. This is already standard bundler behavior and is not a new constraint introduced by NiceTry.

Both contracts access only their own storage during `validateUserOp`, satisfying ERC-7562 storage access rules.

#### Current adoption of private mempools

On many L2s bundlers already use private mempools, so the trust assumption for the ECDSA mode is restricted to the mempool owner. On Ethereum L1 there's a project for a shared mempool, but it's not used by every bundler yet.

### ERC-7579 Module Interface

The validation logic for both modes is additionally packaged as an ERC-7579 `IValidator` module. Users with an existing compliant modular account can install either validator without deploying a new NiceTry account. Module state is keyed by account address as the outermost mapping key, satisfying ERC-7562 requirements for module storage access.

### EIP-1271 Limitations

Neither ECDSA nor WOTS+C mode implements EIP-1271 directly. In the WOTS+C case this is a fundamental incompatibility: verifying a signature must rotate the key, making it a state-mutating operation that cannot be expressed as a view function. To overcome this it might be possible to use a statless backup signer (if available) for this scope too. In the ECDSA case it is a current limitation rather than a fundamental one. Applications requiring off-chain signature verification are not supported in either mode at this time. This topic is covered in detail in [Annex A](https://github.com/conor-deegan/ephemeral-keys/blob/cd-sec-analysis-1/protocol-spec-annex-a.md).

### ERC-7702 Relevance

ERC-7702 allows an EOA to delegate execution to a smart contract implementation. If adopted, it could allow users to use NiceTry's validation logic without deploying a new account or transferring assets to a new address. The NiceTry contract interfaces are compatible with ERC-7702 delegation in principle, but a key piece of the puzzle is missing: the original EOA signer can always sign a transaction to change the EOA implementation. For Nicetry and ERC-7702 to be fully compatible it is needed what is described in [EIP-7851](https://eips.ethereum.org/EIPS/eip-7851) (EOA deactivation).

## Reference implementations

Work in progress

