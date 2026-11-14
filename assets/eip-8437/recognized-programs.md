# Recognized signature programs

These profiles define native checks for EIP-8437 mode 2. They are mempool policy, not consensus scheme identifiers. Each enabled descriptor needs an exact EIP-8288 verification-key hash and a reproducible leaf program implementing the predicate below under the active generic proof statement.

## Initial profiles

| Profile name | Signature verification | Public key bytes | Signature bytes | Verification-key hash |
| --- | --- | --- | --- | --- |
| `mldsa44-pure-v1` | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), ML-DSA-44, pure mode, empty context | 1,312 | 2,420 | TBD |
| `falcon512-padded-v1` | [Falcon-512](https://falcon-sign.info/), [PADDED encoding](https://falcon-sign.info/impl/falcon.h.html) | 897 | 666 | TBD |
| `slhdsa-shake128s-pure-v1` | [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), SLH-DSA-SHAKE-128s, pure mode, empty context | 32 | 7,856 | TBD |

All profiles sign exactly the 32-byte `message` in the raw witness. Prehash modes, nonempty contexts and other parameter sets are not these profiles. Falcon uses the fixed-size padded encoding, including its padding checks, not arbitrary variable-length compressed encodings. The standard's full verification predicate and encoding checks apply.

For each profile, the native check and leaf program compute:

```text
claim = keccak256("EIP8437:raw:v1" || rlp([profile_name, public_key, message]))
```

The tag and profile name are ASCII bytes with no terminator. A successful check establishes exactly this claim under the descriptor's pinned key. The descriptor also specifies how that claim is represented in the active generic verifier's public statement; recognition cannot change that statement.

`message` is an account-defined authorization digest. Account validation must bind it to the intended chain, account, replay protection and actions, and check the authorized credential. It must not assume that an arbitrary signed message authorizes the enclosing transaction. These profiles do not define a transaction signing algorithm or require a circular hash of a transaction containing its own claim. They also do not parse WebAuthn assertions: a WebAuthn transcript and policy require a separate program descriptor.

## Enabling a descriptor

The keys above and cryptographic conformance vectors are outstanding. No TBD key is enabled. Each descriptor must publish:

- The exact key hash, canonical key encoding and reproducible program source/build, including the active generic statement and resource bounds it targets.
- Positive and negative vectors checked by both the native verifier and leaf program: altered key, message, signature, claim and parameter set; wrong lengths; noncanonical encodings; context and prehash confusion; Falcon padding and ML-DSA hint-encoding edge cases.
- Native verification and proving benchmarks within the active resource bounds, including malformed-input rejection. Recognition does not promise a particular batch size or proving deadline.

Adding a profile or changing a program uses a new descriptor and, when the proven predicate changes, a new key. Clients opt into recognized keys through software or configuration updates. Existing transactions still name their original key; supporting a replacement does not rewrite them. Programs outside active consensus resource bounds require a consensus change before this transport can make them usable.
