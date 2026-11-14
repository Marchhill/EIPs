# Recognized signature programs

These profiles define native checks for EIP-8437 mode 2. They are mempool policy, not consensus scheme identifiers. Each enabled descriptor needs an exact EIP-8288 verification-key hash, its own claim definition and a reproducible leaf program. Native acceptance must imply that the leaf can prove the same claim; the converse is not required.

The initial programs target the [batched generic proof statement](https://github.com/ethereum/EIPs/pull/12664), including for singleton proofs. They cannot be enabled under a bare-claim-only setup. The transport does not require batching, but these programs require that consensus statement and its verifier to be active.

## Initial profiles

| Profile name | Signature verification | Public key bytes | Signature bytes | Verification-key hash |
| --- | --- | --- | --- | --- |
| `mldsa44-pure-v1` | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), ML-DSA-44, pure mode, empty context | 1,312 | 2,420 | TBD |
| `falcon512-padded-v1` | [Falcon-512](https://falcon-sign.info/), [PADDED encoding](https://falcon-sign.info/impl/falcon.h.html) | 897 | 666 | TBD |
| `slhdsa-shake128s-pure-v1` | [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), SLH-DSA-SHAKE-128s, pure mode, empty context | 32 | 7,856 | TBD |

All profiles sign exactly the 32-byte `message` in the raw witness. Prehash modes, nonempty contexts and other parameter sets are not these profiles. Falcon uses the fixed-size padded encoding, not arbitrary variable-length compressed encodings. Native implementations may impose stricter encoding checks than their leaf programs, including Falcon padding and ML-DSA hint canonicality.

Each program definition fixes the claim's domain, fields, ordering and hashing, and how it binds the credential and message. There is no common network-level claim formula. Its native verifier computes that program's claim and compares it with the declared dependency. Pin the claim definition and the leaf public statement alongside the key.

## Signing pattern

Accounts should sign a domain-separated intent containing the chain, account, nonce, expiry, fee and payer constraints, ordered actions and required policy. Exclude the resulting claim and signature bytes from that intent, but bind the expected dependency scheme, verifier key and declaration position. The account's validation code recomputes the intent and program-defined claim for an authorized credential, checks the declaration, and rejects uncommitted actions or changes to protected fields.

This is an account-defined digest, not the unmodified transaction signature hash covering its own claim-bearing frame. Mode 2 neither changes EIP-8141's signing hash nor supplies account authorization. These profiles do not parse WebAuthn assertions; a WebAuthn transcript and policy require a separate program descriptor.

## Enabling a descriptor

The exact keys, program-specific claim definitions and cryptographic conformance vectors are outstanding. No TBD key is enabled. Each descriptor must publish:

- The exact key hash, canonical key encoding and reproducible program source/build, including the claim encoding, active generic statement and resource bounds it targets.
- Vectors showing that every native-accepted witness produces the same claim in the leaf. Cover altered keys, messages, signatures, claims and parameters; wrong lengths; context and prehash confusion; Falcon padding and ML-DSA hint-encoding edge cases. Record stricter native rejections separately; they need not be leaf rejections.
- Native verification and proving benchmarks within the active resource bounds, including malformed-input rejection. Recognition does not promise a particular batch size or proving deadline.

Adding a profile or changing a program uses a new descriptor and, when the proven predicate changes, a new key. Clients opt into recognized keys through software or configuration updates. Existing transactions still name their original key; supporting a replacement does not rewrite them. Programs outside active consensus resource bounds require a consensus change before this transport can make them usable.
