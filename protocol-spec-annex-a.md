# EIP-1271 Compatibility: Off-Chain Signatures with Ephemeral Key Rotation

**Status: Work in progress. Subject to revision.**

## Scope

The viability of Permits, SIWE, WalletConnect, and other off-chain signature flows with NiceTry depends on a variety of factors and circumstances. This document describes usage scenarios, known constraints, and the proposed solution for maintaining EIP-1271 compatibility alongside ephemeral key rotation. Multisig wallet composition (e.g., Safe) is excluded from this analysis and requires separate treatment.

Permit2 in particular warrants dedicated analysis: its security assumptions are more specific than those of generic offchain signature verification, involving persistent onchain allowance state, ERC-20 approval prerequisites, and protocol-controlled expiration parameters.

## Applicability

The ephemeral key rotation protocol can be implemented across various custody scenarios that may require post-quantum guarantees. In the case of wallet infrastructure for large-scale asset holdings, it is unlikely that the implementation would allow or require off-chain signing scenarios. The solutions discussed in this document are therefore most relevant to a wallet that aims to maintain backward compatibility with Permits and other mechanisms as adopted by dapps today.

## Off-Chain Signature Standards in a Post-Quantum Context

Post-quantum signature schemes face significant barriers on the EVM today. WOTS+C signatures are approximately 500 bytes, Dilithium approximately 2,400 bytes, Falcon 600 to 1,200 bytes and SPHINCS+ around 8000 bytes. These translate directly to calldata costs (16 gas per non-zero byte), without even accounting for the cost of onchain signature verification.

Given these constraints, we consider it more likely that new off-chain authorization standards will emerge in the post-quantum era rather than existing standards continuing to operate as they do today. Permit2's reliance on ECDSA at the EOA level, and the gas impracticality of PQ verification at the smart account level, suggest that the current off-chain signing landscape could not survive the transition to post-quantum cryptography unchanged. The solution described below is designed for the present environment and the transitional period in which ECDSA-based off-chain standards remain dominant.

## The Problem

NiceTry's ephemeral key rotation advances the active signer (currentSigner) on every transaction. Any EIP-1271 signature issued by a previous currentSigner becomes unverifiable the moment the next rotation occurs, because isValidSignature would check against a signer that no longer matches.

This breaks any protocol that performs deferred signature verification: Permit2 allowance signatures, Seaport orders, SIWE session re-verification, and any flow where the signature is created at one point in time and verified at another.

## Solution: Dedicated Permit Signer

The account maintains two isolated signing domains:

```
address public currentSigner;   // Ephemeral. Rotates every transaction. Validates onchain execution.
address public permitSigner;    // Rotated on-demand. Validates EIP-1271 only.
```

validateUserOp checks currentSigner exclusively. isValidSignature checks permitSigner exclusively. The two verification paths never cross.

permitSigner has no authority over the account. It cannot submit UserOperations, install or remove modules, move funds, or rotate itself. Its sole capability is producing signatures that pass EIP-1271 verification.

## Permit Signer Rotation

permitSigner is rotated via a UserOperation authorized by currentSigner

The rotation policy is determined by the wallet implementation:

- **Per-Tx rotation:** permitSigner rotates alongside currentSigner on every transaction. This provides the tightest security bound: any compromised permitSigner is invalidated on the next operation, and any forged EIP-1271 signature produced with the old key will fail verification from that point forward.
- **Periodic rotation:** permitSigner rotates every N operations or every T hours.
- **On-demand rotation:** The user explicitly triggers rotation when desired.

## Permit Signer Generation

permitSigner should be derived from a completely separate derivation path than the currentSigner.

For instance, one could use two separate BIP44 account indexes, producing two different derivation paths: currentSigner lives under m/44'/60'/0'/0/0/ while permitSigner draws from m/44'/60'/1'/0/0/. Since changing the account index produces an entirely independent key stream, the two signers never overlap and permitSigner gets its own clean sequence of addresses that are fully isolated from the main signing path.
