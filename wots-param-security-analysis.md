# WOTS+C Parameter Security Review

**Last updated**: 2026-04-22

---

## Classical

The WOTS+C security proof (Theorem B.2, Hülsing et al., 2022) reduces to EU-CMA security of the underlying WOTS+ scheme. The dominant reduction loss comes from guessing which of `l · (w−1)` chain positions the forger inverts. Approximate classical security: `128 − log₂(l · (w−1))` bits.

| w | l | l · (w−1) | Classical |
|---|---|-----------|-----------|
| 4 | 64 | 192 | ~120 bits |
| 8 | 44 | 308 | ~120 bits |
| 16 | 32 | 480 | ~119 bits |
| 32 | 26 | 806 | ~118 bits |
| 64 | 22 | 1386 | ~118 bits |
| 128 | 20 | 2540 | ~117 bits |
| 256 | 16 | 4080 | ~116 bits |

## Quantum

Grover reduces preimage resistance from `2^128` to `2^64`. Multi-target Grover across `l · (w−1)` positions gives a further `√(l · (w−1))` speedup. Approximate quantum security: `64 − log₂(l · (w−1)) / 2` bits.

| w | l | Quantum |
|---|---|---------|
| 4 | 64 | ~60 bits |
| 8 | 44 | ~60 bits |
| 16 | 32 | ~60 bits |
| 32 | 26 | ~59 bits |
| 64 | 22 | ~59 bits |
| 128 | 20 | ~58 bits |
| 256 | 16 | ~58 bits |

## Notes

- All seven rows are effectively equivalent on security (~4-bit classical spread, ~2-bit quantum spread). Parameter selection is purely a gas-vs-signature-size engineering decision.
- On L1 where gas and calldata are both expensive: w=8 or w=16. On L2s where signature size dominates: w=64 or higher.
- Quantum estimates are my own derivation applying Grover bounds to the reduction structure.
- Security proof: Theorem B.2 in "SPHINCS+C: Compressing SPHINCS+ With (Almost) No Cost" (Hülsing, Kudinov, Ronen, Yogev, 2022).
