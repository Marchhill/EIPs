"""Synthetic encoding helpers for EIP-8518 vectors; no execution or proof checks."""
from hashlib import sha256
from Crypto.Hash import keccak
from rlp import decode

SOFT_RESPONSE_LIMIT = 2**21
FRAME_TX_TYPE = b"\x06"
CELLS_PER_EXT_BLOB = 128
SYNTHETIC_FRAME_GAS = 100000

def h(data):
    return keccak.new(digest_bits=256, data=data).digest()

def uint(value, width):
    return value.to_bytes(width, "big")

def rlp(value):
    if isinstance(value, int):
        if value < 0:
            raise ValueError("negative integer")
        return rlp(uint(value, (value.bit_length() + 7) // 8))
    if isinstance(value, list):
        payload = b"".join(rlp(item) for item in value)
        offset = 0xc0
    else:
        payload = value
        offset = 0x80
        if len(payload) == 1 and payload[0] < 0x80:
            return payload
    if len(payload) < 56:
        return bytes([offset + len(payload)]) + payload
    size = uint(len(payload), (len(payload).bit_length() + 7) // 8)
    return bytes([offset + 55 + len(size)]) + size + payload

def pattern(size):
    return (bytes(range(251)) * ((size + 250) // 251))[:size]

def versioned_hash(commitment):
    return b"\x01" + sha256(commitment).digest()[1:]

# Test-only verifier addresses: the core proposal has not assigned them.
NATIVE = bytes.fromhex("11" * 20)
CUSTOM = bytes.fromhex("22" * 20)

def transaction_body(nonce, commitments=()):
    native = [NATIVE, h(b"key"), h(b"message" + uint(nonce, 4)), 0, 0]
    custom = [CUSTOM, h(b"other key"), h(b"other message"), 10000, 4]
    return [1, nonce, bytes(20), [native, native, custom], [], [1, 1, 1],
            [versioned_hash(c) for c in commitments]]

def transaction(nonce=0, blob=False):
    commitments = [bytes([1]) * 48] if blob else []
    sidecar = [[], commitments, [bytes(48)] * CELLS_PER_EXT_BLOB] if blob else []
    return FRAME_TX_TYPE + rlp([transaction_body(nonce, commitments), 0,
                              [b"signature" * 8, b"signature" * 8, b"test"], sidecar])

def pooled_parts(encoded):
    assert isinstance(encoded, bytes) and encoded[:1] == FRAME_TX_TYPE, "transaction envelope"
    parts = decode(encoded[1:], strict=True)
    assert isinstance(parts, list) and len(parts) == 4, "pooled fields"
    body, version, witnesses, sidecar = parts
    assert isinstance(body, list) and len(body) == 7, "transaction body"
    assert version == b"", "pooled version"
    assert isinstance(witnesses, list) and len(witnesses) == len(body[3]), "witness count"
    assert all(isinstance(w, bytes) for w in witnesses), "witness encoding"
    if body[6]:
        assert isinstance(sidecar, list) and len(sidecar) == 3, "blob sidecar"
        blobs, commitments, proofs = sidecar
        assert blobs == [], "blob data elision"
        assert len(commitments) == len(body[6]), "commitment count"
        assert all(isinstance(c, bytes) and len(c) == 48 for c in commitments), "commitment encoding"
        assert [versioned_hash(c) for c in commitments] == body[6], "commitment hash"
        assert len(proofs) == len(commitments) * CELLS_PER_EXT_BLOB, "cell proof count"
        assert all(isinstance(p, bytes) and len(p) == 48 for p in proofs), "cell proof encoding"
    else:
        assert sidecar == [], "unexpected sidecar"
    return parts

def transaction_hash(encoded):
    return h(FRAME_TX_TYPE + rlp(pooled_parts(encoded)[0]))

def aggregatable(claim):
    # Fixture mapping only. Activation requires the core fork's actual mapping.
    return claim[0] == NATIVE

def dependencies(encoded):
    # Fixtures use explicit 32-byte keys/messages; core resolution is not tested.
    return sorted(set(uint(0x10, 32) + c[2] + c[1]
                      for c in pooled_parts(encoded)[0][3] if aggregatable(c)))

def normalize(encoded):
    body, version, witnesses, sidecar = pooled_parts(encoded)
    return FRAME_TX_TYPE + rlp([body, version,
        [b"" if aggregatable(c) else w for c, w in zip(body[3], witnesses)], sidecar])

def reply_for(request_id, wrappers):
    return [request_id, [[h(rlp(item)), item] for item in wrappers]]

def answer_request(request_id, requested, held, announced):
    return wrappers_response(request_id, [held[digest] for digest in requested
                                         if digest in announced and digest in held])

def wrappers_response(request_id, wrappers):
    # A wrapper is embedded as its RLP item: splice its exact bytes into the list.
    served = []
    for wrapper in wrappers:
        if len(splice(request_id, served)) >= SOFT_RESPONSE_LIMIT:
            break
        served.append(wrapper)
    return splice(request_id, served)

def splice(request_id, encoded_items):
    entries = b"".join(rlp_list(rlp(h(item)) + item) for item in encoded_items)
    return rlp_list(rlp(request_id) + rlp_list(entries))

def rlp_list(payload):
    if len(payload) < 56:
        return bytes([0xc0 + len(payload)]) + payload
    size = uint(len(payload), (len(payload).bit_length() + 7) // 8)
    return bytes([0xf7 + len(size)]) + size + payload

def expect_error(reason, fn, *args):
    try:
        fn(*args)
    except (ValueError, AssertionError) as error:
        assert str(error) == reason, (reason, str(error))
        return
    raise AssertionError("accepted invalid input: " + reason)
