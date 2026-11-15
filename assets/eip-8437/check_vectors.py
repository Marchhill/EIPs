#!/usr/bin/env python3
"""Check EIP-8437 encoding fixtures and message rules on decoded values.

Scalars are represented as Python integers. This checks encoding and blob
metadata binding, not transaction execution, proof validity or client state.

Requires Python 3.9+, pycryptodome and rlp. Run with:
    python3 assets/eip-8437/check_vectors.py
"""

import json
from hashlib import sha256
from pathlib import Path

from Crypto.Hash import keccak
from rlp import decode

SOFT_RESPONSE_LIMIT = 2097152
MAX_WRAPPER_BYTES = SOFT_RESPONSE_LIMIT
MAX_ANNOUNCEMENTS = 64
MAX_WRAPPERS_PER_REQUEST = 32
LEANSPHINCS_SCHEME = 0x10
LEANSTARK_SCHEME = 0x11
MAX_RAW_WITNESS_BYTES = 16 * 1024
MAX_RAW_ENTRIES = 16
MAX_RAW_TRANSACTIONS = 64
FRAME_TX_TYPE = b"\x06"
CELLS_PER_EXT_BLOB = 128


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


def describe(mode, body, deps_hash, txs_hash):
    # Each entry is [mode, length, hash, deps-hash, txs-hash].
    if mode not in (0, 1, 2):
        raise ValueError("wrapper mode")
    if not 1 <= len(body) <= MAX_WRAPPER_BYTES:
        raise ValueError("wrapper size")
    return [mode, len(body), h(body), deps_hash, txs_hash]


def versioned_hash(commitment):
    return b"\x01" + sha256(commitment).digest()[1:]


def transaction_body(nonce, commitments=()):
    # Structurally encoded frame payload, not an executable valid transaction.
    return [1, nonce, bytes(20), [bytes(32)], [], [1, 1, int(bool(commitments))],
            [versioned_hash(c) for c in commitments]]


def transaction(nonce):
    return FRAME_TX_TYPE + rlp(transaction_body(nonce))


def blob_transaction(nonce=2):
    # Synthetic KZG encodings: these are not curve points or valid cell proofs.
    commitments = [bytes([i + 1]) * 48 for i in range(2)]
    proofs = [bytes([i % 251]) * 48 for i in range(2 * CELLS_PER_EXT_BLOB)]
    return [transaction_body(nonce, commitments), 1, [], commitments, proofs]


def transaction_hash(encoded):
    assert isinstance(encoded, bytes) and len(encoded) > 1 and encoded[:1] == FRAME_TX_TYPE, "transaction envelope"
    payload = decode(encoded[1:], strict=True)
    assert isinstance(payload, list), "transaction payload"
    if len(payload) == 5:
        body, version, blobs, commitments, proofs = payload
        assert isinstance(body, list) and len(body) == 7, "transaction payload"
        assert version == b"\x01", "blob wrapper version"
        assert blobs == [], "blob data elision"
        hashes = body[6]
        assert isinstance(hashes, list) and hashes, "blob hashes"
        assert isinstance(commitments, list) and len(commitments) == len(hashes), "commitment count"
        assert all(isinstance(c, bytes) and len(c) == 48 for c in commitments), "commitment encoding"
        assert [versioned_hash(c) for c in commitments] == hashes, "commitment hash"
        assert isinstance(proofs, list) and len(proofs) == CELLS_PER_EXT_BLOB * len(commitments), "cell proof count"
        assert all(isinstance(p, bytes) and len(p) == 48 for p in proofs), "cell proof encoding"
    else:
        body = payload
        assert len(body) == 7, "transaction payload"
        assert body[6] == [], "missing blob metadata"
    return h(FRAME_TX_TYPE + rlp(body))


def wrapper_items():
    deps = sorted(bytes(31) + bytes([LEANSPHINCS_SCHEME]) + h(b"message %d" % i) + uint(i + 1, 32)
                  for i in range(2))
    envelopes = sorted((transaction(i) for i in range(2)), key=transaction_hash)
    return {
        "mode0": [envelopes, 0, [deps, [b"witness 0", b"witness 1"]]],
        "mode1": [envelopes, 1, [deps, b"aggregate proof"]],
        "blob_mode1": [sorted(envelopes + [FRAME_TX_TYPE + rlp(blob_transaction())],
                              key=transaction_hash), 1, [deps, b"aggregate proof"]],
    }


def coverage(item):
    # Wire hints bind full triples, independently of the circuit digest.
    deps_hash = h(b"".join(item[2][0]))
    txs_hash = h(b"".join(transaction_hash(tx) for tx in item[0]))
    return deps_hash, txs_hash


def metadata_for(item):
    return (item[1], len(rlp(item)), *coverage(item))


def may_skip_fetch(announcement, held_valid_wrappers):
    # Caller supplies only wrappers valid under the current rules.
    # Native-validated raw witnesses cannot suppress proof-backed coverage.
    return any((item[1] != 2 or announcement[0] == 2)
               and tuple(announcement[3:]) == coverage(item)
               for item in held_valid_wrappers)


def wrapper_vectors():
    items = wrapper_items()
    out = {
        "deps": [d.hex() for d in items["mode0"][2][0]],
        "transactions": [x.hex() for x in items["mode0"][0]],
    }
    for name, item in items.items():
        body = rlp(item)
        announcement = describe(item[1], body, *coverage(item))
        out[name] = {
            "body": body.hex(),
            "content_hash": announcement[2].hex(),
            "deps_hash": announcement[3].hex(),
            "txs_hash": announcement[4].hex(),
            "announcement_rlp": rlp(announcement).hex(),
            "response_rlp": rlp(reply_for(7, [item])).hex(),
            "compact_response_rlp": rlp([7, [[announcement[2], compact_wrapper(item, {h(tx) for tx in item[0]})]]]).hex(),
            "compact_request_rlp": rlp([7, 1, [announcement[2]]]).hex(),
            "full_request_rlp": rlp([8, 0, [announcement[2]]]).hex(),
            "encoding_hashes": [h(tx).hex() for tx in item[0]],
            "transaction_hashes": [transaction_hash(tx).hex() for tx in item[0]],
        }
    return out


def check_announcements(entries, supported_modes=(0, 1, 2), recognized_keys=None):
    assert 1 <= len(entries) <= MAX_ANNOUNCEMENTS, "announcement count"
    for entry in entries:
        assert isinstance(entry, list) and len(entry) == 5, "announcement fields"
        mode, length, digest, deps_hash, txs_hash = entry
        assert isinstance(mode, int) and mode >= 0, "announcement mode"
        assert isinstance(length, int) and 1 <= length <= MAX_WRAPPER_BYTES, "announcement length"
        assert isinstance(digest, bytes) and len(digest) == 32, "announcement hash"
        assert isinstance(deps_hash, bytes) and len(deps_hash) == 32, "announcement dependency hash"
        assert isinstance(txs_hash, bytes) and len(txs_hash) == 32, "announcement transaction hash"
    hashes = [entry[2] for entry in entries]
    assert hashes == sorted(set(hashes)), "announcement order"
    return [entry for entry in entries if entry[0] in supported_modes
            and (entry[0] != 2 or recognized_keys is None or recognized_keys)]


def check_request(request_id, hashes, received_announcements, compact=0):
    assert type(compact) is int and compact in (0, 1), "request compact flag"
    assert isinstance(request_id, int) and 0 <= request_id < 2**64, "request id"
    assert 1 <= len(hashes) <= MAX_WRAPPERS_PER_REQUEST, "request count"
    assert all(isinstance(digest, bytes) and len(digest) == 32 for digest in hashes), "request hash"
    assert len(set(hashes)) == len(hashes), "request duplicates"
    assert all(digest in received_announcements for digest in hashes), "unannounced wrapper"


def check_wrapper_shape(item):
    # Envelope structure and blob metadata binding are checked; EIP-8141
    # execution, dependency-union equality and cryptographic validity are not.
    assert isinstance(item, list) and len(item) == 3, "wrapper fields"
    envelopes, mode, content = item
    assert isinstance(content, list) and len(content) == 2, "wrapper content"
    deps, proof = content
    assert isinstance(mode, int) and mode in (0, 1, 2), "wrapper mode"
    assert isinstance(deps, list) and deps, "wrapper dependencies"
    assert all(isinstance(dep, bytes) and len(dep) == 96 for dep in deps), "dependency length"
    assert deps == sorted(set(deps)), "dependency order"
    if mode in (0, 2):
        assert isinstance(proof, list) and len(proof) == len(deps), "witness count"
        raw_count = 0
        for dep, witness in zip(deps, proof):
            if mode == 2 and isinstance(witness, list):
                assert dep[:32] == uint(LEANSTARK_SCHEME, 32), "raw dependency scheme"
                assert len(witness) == 3 and all(isinstance(v, bytes) for v in witness), "raw witness fields"
                assert len(witness[1]) == 32, "raw message length"
                assert len(rlp(witness)) <= MAX_RAW_WITNESS_BYTES, "raw witness length"
                raw_count += 1
            else:
                assert isinstance(witness, bytes), "direct witness"
        if mode == 2:
            assert raw_count, "missing raw witness"
            assert raw_count <= MAX_RAW_ENTRIES, "raw entry count"
    else:
        assert isinstance(proof, bytes) and proof, "aggregate proof"
    assert isinstance(envelopes, list) and envelopes, "wrapper envelopes"
    if mode == 2:
        assert len(envelopes) <= MAX_RAW_TRANSACTIONS, "raw transaction count"
    hashes = [transaction_hash(tx) for tx in envelopes]
    assert hashes == sorted(set(hashes)), "transaction order"


def check_direct_witness_limits(item):
    # EIP-8288 direct-witness limits; these are validation, not RLP errors.
    # Raw entries have their separate mode 2 limits, checked above.
    assert item[1] in (0, 2)
    direct = [dep for dep, witness in zip(*item[2]) if isinstance(witness, bytes)]
    assert sum(dep[:32] == uint(LEANSPHINCS_SCHEME, 32) for dep in direct) <= 16, "native witness limit"
    assert sum(dep[:32] == uint(LEANSTARK_SCHEME, 32) for dep in direct) <= 1, "generic proof limit"


def reply_for(request_id, wrappers):
    return [request_id, [[h(rlp(item)), item] for item in wrappers]]


def compact_wrapper(item, delivered):
    # delivered tracks exact encodings sent in full on this connection.
    txs = [[h(tx)] if h(tx) in delivered and len(rlp([h(tx)])) < len(rlp(tx)) else tx
           for tx in item[0]]
    return [txs, *item[1:]]


def reconstruct(item, compact, cache, length):
    assert isinstance(item, list) and len(item) == 3, "wrapper fields"
    assert isinstance(item[0], list), "wrapper envelopes"
    assert 1 <= len(rlp(item)) <= length <= MAX_WRAPPER_BYTES, "wrapper length"
    txs = []
    missing = False
    expanded_size = len(rlp(item))
    for entry in item[0]:
        if isinstance(entry, list):
            assert compact == 1, "reference in full response"
            assert len(entry) == 1 and isinstance(entry[0], bytes) and len(entry[0]) == 32, "encoding reference"
            tx = cache.get(entry[0])
            if tx is None:
                missing = True
                continue
            assert isinstance(tx, bytes) and h(tx) == entry[0], "encoding hash"
            assert len(rlp(entry)) < len(rlp(tx)), "reference size"
            expanded_size += len(rlp(tx)) - len(rlp(entry))
            assert expanded_size <= length, "wrapper length"
        else:
            tx = entry
        txs.append(tx)
    if missing:
        return None
    result = [txs, *item[1:]]
    assert len(rlp(result)) <= length, "wrapper length"
    return result


def check_wrapper_response(request_id, requested, announced_metadata, reply, compact=0, cache=None, verify=None):
    assert isinstance(reply, list) and len(reply) == 2, "response fields"
    assert reply[0] == request_id, "response id"
    assert isinstance(reply[1], list), "response fields"
    positions = {digest: i for i, digest in enumerate(requested)}
    previous = -1
    retries = []
    for entry in reply[1]:
        assert isinstance(entry, list) and len(entry) == 2, "response entry"
        digest, wire_item = entry
        assert isinstance(digest, bytes) and digest in positions, "response hash"
        assert positions[digest] > previous, "response order"
        previous = positions[digest]
        mode, length, deps_hash, txs_hash = announced_metadata[digest]
        item = reconstruct(wire_item, compact, cache or {}, length)
        assert wire_item[1] == mode, "announced mode"
        if item is None:
            retries.append(digest)
            continue
        body = rlp(item)
        assert h(body) == digest, "response hash"
        check_wrapper_shape(item)
        assert len(body) == length, "announced length"
        # Check wire hints before any proof-verification work.
        actual_deps, actual_txs = coverage(item)
        assert actual_deps == deps_hash, "announced dependency hash"
        assert actual_txs == txs_hash, "announced transaction hash"
        if verify is not None:
            assert verify(item), "proof verification"
    return retries


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


def vector(mode, size):
    # Pattern bytes test hash and length encoding, not wrapper validity.
    announcement = describe(mode, pattern(size), h(b"dependency hint"), h(b"transaction hint"))
    return {
        "mode": mode,
        "size": size,
        "content_hash": announcement[2].hex(),
        "deps_hash": announcement[3].hex(),
        "txs_hash": announcement[4].hex(),
        "announcement_rlp": rlp(announcement).hex(),
    }


def expect_error(reason, fn, *args):
    try:
        fn(*args)
    except (ValueError, AssertionError) as error:
        assert str(error) == reason, (reason, str(error))
        return
    raise AssertionError("accepted invalid input: " + reason)


def check_raw_witness_cases():
    # Synthetic keys/signatures exercise transport, not cryptographic validity
    # or native/leaf equivalence. No production program keys are assigned here.
    profiles = [(b"mldsa44-pure-v1", 1312, 2420),
                (b"falcon512-padded-v1", 897, 666),
                (b"slhdsa-shake128s-pure-v1", 32, 7856)]
    for profile, pk_size, sig_size in profiles:
        pk, message, signature = pattern(pk_size), bytes(32), pattern(sig_size)
        # Opaque synthetic claim: production claim encoding is program-defined.
        claim = h(b"synthetic claim:" + profile)
        key = h(b"synthetic key:" + profile)
        dep = uint(LEANSTARK_SCHEME, 32) + claim + key
        witness = [pk, message, signature]
        raw = [[transaction(1)], 2, [[dep], [witness]]]
        body = rlp(raw)
        announcement = describe(2, body, *coverage(raw))
        assert check_announcements([announcement]) == [announcement]
        assert check_announcements([announcement], (0, 1)) == []
        # A mode-2-capable peer with no recognized programs neither fetches nor
        # reports an error; it still validates the announcement's wire fields.
        assert check_announcements([announcement], recognized_keys=set()) == []
        bad_length = [2, MAX_WRAPPER_BYTES + 1, *announcement[2:]]
        expect_error("announcement length", check_announcements,
                     [bad_length], (0, 1, 2), set())
        check_wrapper_response(7, [h(body)], {h(body): metadata_for(raw)}, reply_for(7, [raw]))

        # Mode changes preserve coverage hints but never confer proof coverage.
        proven = [raw[0], 1, [[dep], b"synthetic aggregate proof"]]
        direct = [raw[0], 0, [[dep], [b"synthetic singleton proof"]]]
        for other in (direct, proven):
            other_announcement = describe(other[1], rlp(other), *coverage(other))
            assert not may_skip_fetch(other_announcement, [raw])
            assert may_skip_fetch(announcement, [other])
        assert may_skip_fetch(announcement, [raw])

        # Mixed native and raw witnesses, under the separate direct/raw limits.
        native_dep = uint(LEANSPHINCS_SCHEME, 32) + bytes(64)
        mixed = [raw[0], 2, [[native_dep, dep], [b"synthetic signature", witness]]]
        check_wrapper_shape(mixed)
        check_direct_witness_limits(mixed)
        second_raw = uint(LEANSTARK_SCHEME, 32) + h(b"second raw") + key
        proof_dep = uint(LEANSTARK_SCHEME, 32) + h(b"proven claim") + key
        pairs = sorted([(dep, witness), (second_raw, witness),
                        (proof_dep, b"synthetic singleton proof")])
        mixed_generic = [sorted([transaction(i) for i in range(3)], key=transaction_hash),
                         2, [[pair[0] for pair in pairs], [pair[1] for pair in pairs]]]
        check_wrapper_shape(mixed_generic)
        check_direct_witness_limits(mixed_generic)
        too_many_proofs = [mixed_generic[0], 2,
                          [mixed_generic[2][0], [witness, b"proof A", b"proof B"]]]
        check_wrapper_shape(too_many_proofs)
        expect_error("generic proof limit", check_direct_witness_limits, too_many_proofs)

        # A shared dependency does not exempt additional transactions from the cap.
        many_txs = sorted([transaction(i) for i in range(65)], key=transaction_hash)
        check_wrapper_shape([many_txs[:64], 2, raw[2]])
        expect_error("raw transaction count", check_wrapper_shape, [many_txs, 2, raw[2]])
        many_deps = sorted(uint(LEANSTARK_SCHEME, 32) + h(uint(i, 4)) + key for i in range(17))
        check_wrapper_shape([many_txs[:16], 2, [many_deps[:16], [witness] * 16]])
        expect_error("raw entry count", check_wrapper_shape,
                     [many_txs[:17], 2, [many_deps, [witness] * 17]])

        # Dependency/witness count mismatches are malformed in both modes.
        for item in (raw, direct):
            for entries in ([], item[2][1] * 2):
                expect_error("witness count", check_wrapper_shape,
                             [item[0], item[1], [item[2][0], entries]])
        expect_error("raw dependency scheme", check_wrapper_shape,
                     [raw[0], 2, [[native_dep], [witness]]])
        expect_error("direct witness", check_wrapper_shape, [raw[0], 0, raw[2]])
        expect_error("missing raw witness", check_wrapper_shape, [raw[0], 2, direct[2]])
        expect_error("raw witness fields", check_wrapper_shape,
                     [raw[0], 2, [[dep], [witness[:2]]]])
        expect_error("raw message length", check_wrapper_shape,
                     [raw[0], 2, [[dep], [[pk, bytes(31), signature]]]])
        expect_error("raw witness length", check_wrapper_shape,
                     [raw[0], 2, [[dep], [[pk, message, bytes(MAX_RAW_WITNESS_BYTES)]]]])

        # Announcement length cannot reveal body-level mode 2 limits. Reject
        # these bodies before calling any signature/proof verifier.
        verification_calls = []
        def verify_stub(item):
            verification_calls.append(item)
            return True
        oversized_items = [
            ("raw transaction count", [many_txs, 2, raw[2]]),
            ("raw entry count", [many_txs[:17], 2, [many_deps, [witness] * 17]]),
            ("raw witness length", [raw[0], 2, [[dep], [[pk, message, bytes(MAX_RAW_WITNESS_BYTES)]]]]),
        ]
        for reason, item in oversized_items:
            item_body = rlp(item)
            digest = h(item_body)
            assert check_announcements([describe(2, item_body, *coverage(item))])
            expect_error(reason, check_wrapper_response, 7, [digest],
                         {digest: metadata_for(item)}, reply_for(7, [item]),
                         0, None, verify_stub)
        assert verification_calls == []

        # Transaction omission also round-trips mode 2; witnesses stay in full.
        tx = raw[0][0]
        compact = compact_wrapper(raw, {h(tx)})
        assert compact[2] == raw[2]
        assert reconstruct(compact, 1, {h(tx): tx}, len(body)) == raw
        assert reconstruct(compact, 1, {}, len(body)) is None
        altered = [raw[0], 2, [[dep], [[pk, message, signature[:-1] + b"x"]]]]
        assert h(rlp(altered)) != h(body)
        assert coverage(altered) == coverage(raw)  # Hints cannot prove validity.


def main():
    check_raw_witness_cases()
    assert h(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert rlp(0) == b"\x80" and rlp([]) == b"\xc0"
    assert rlp(b"dog").hex() == "83646f67"
    assert rlp([0, 1, bytes(32)]).hex() == "e38001a0" + "00" * 32
    assert rlp([1, 1, bytes(32)]).hex() == "e30101a0" + "00" * 32
    vectors = json.loads(Path(__file__).with_name("announcement-vectors.json").read_text())
    for expected in vectors:
        assert vector(expected["mode"], expected["size"]) == expected, expected["size"]
    wrappers = json.loads(Path(__file__).with_name("wrapper-vectors.json").read_text())
    assert wrapper_vectors() == wrappers

    # RLP prefix expansion makes the maximum entry 106 bytes in all three modes.
    assert MAX_WRAPPER_BYTES == SOFT_RESPONSE_LIMIT
    for mode in (0, 1, 2):
        assert len(rlp([mode, MAX_WRAPPER_BYTES, bytes(32), bytes(32), bytes(32)])) == 106

    # Announcement count, fields and strict hash ordering.
    announced = [[i % 2, MAX_WRAPPER_BYTES, uint(i + 1, 32), bytes(32), bytes(32)] for i in range(65)]
    check_announcements([[0, 1, bytes(32), bytes(32), bytes(32)]])
    check_announcements(announced[:64])
    expect_error("announcement count", check_announcements, [])
    expect_error("announcement count", check_announcements, announced)
    expect_error("announcement order", check_announcements, announced[:2][::-1])
    expect_error("announcement order", check_announcements, announced[:1] * 2)
    for length in (0, MAX_WRAPPER_BYTES + 1):
        expect_error("announcement length", check_announcements, [[0, length, bytes(32), bytes(32), bytes(32)]])
    for mode in (-1, b"\x01"):
        expect_error("announcement mode", check_announcements, [[mode, 1, bytes(32), bytes(32), bytes(32)]])
    for mode in (3, 256):
        unknown = [mode, 1, bytes(32), bytes(32), bytes(32)]
        known = [0, 1, bytes([1]) * 32, bytes(32), bytes(32)]
        assert check_announcements([unknown]) == []
        assert check_announcements([unknown, known]) == [known]
        expect_error("announcement count", check_announcements, [unknown] * 65)
        expect_error("announcement order", check_announcements, [known, unknown])
        expect_error("announcement length", check_announcements,
                     [[mode, MAX_WRAPPER_BYTES + 1, *unknown[2:]]])
    expect_error("announcement hash", check_announcements, [[0, 1, bytes(31), bytes(32), bytes(32)]])
    expect_error("announcement fields", check_announcements, [[0, 1, bytes(32), b""]])
    expect_error("announcement fields", check_announcements, [[1, bytes(32)]])

    expect_error("announcement dependency hash", check_announcements,
                 [[0, 1, bytes(32), bytes(31), bytes(32)]])
    expect_error("announcement transaction hash", check_announcements,
                 [[0, 1, bytes(32), bytes(32), bytes(31)]])

    # Request bounds, uniqueness and received announcements; IDs need not increase.
    assert rlp([7, 0, [bytes(32)]]).hex() == "e40780e1a0" + "00" * 32
    for flag in (0, 1):
        check_request(7, [bytes(32)], {bytes(32)}, flag)
    for flag in (-1, 2, b"", True):
        expect_error("request compact flag", check_request, 7, [bytes(32)], {bytes(32)}, flag)
    max_id = 2**64 - 1
    hashes = [entry[2] for entry in announced]
    check_request(max_id, hashes[:32], set(hashes))
    check_request(0, hashes[:2][::-1], set(hashes))  # Requests need not be sorted.
    for request_id in (-1, 2**64):
        expect_error("request id", check_request, request_id, hashes[:1], set(hashes))
    expect_error("request count", check_request, 7, [], set(hashes))
    expect_error("request count", check_request, 7, hashes[:33], set(hashes))
    expect_error("request duplicates", check_request, 7, hashes[:1] * 2, set(hashes))
    expect_error("request hash", check_request, 7, [bytes(31)], set(hashes))
    expect_error("unannounced wrapper", check_request, 7, [bytes(32)], set(hashes))
    assert len(rlp(announced[:64])) == 6787
    assert len(rlp([max_id, 1, hashes[:32]])) == 1072

    # Complete envelopes are part of the canonical wrapper and its identity.
    mode0, mode1, blob_mode1 = wrapper_items().values()
    for item in (mode0, mode1, blob_mode1):
        check_wrapper_shape(item)
        decoded = decode(rlp(item), strict=True)
        assert len(decoded) == 3 and decoded[0] == item[0]
        assert decoded[1] == (b"\x01" if item[1] else b"")
        assert decoded[2] == item[2]
    expect_error("wrapper fields", check_wrapper_shape, mode1[:2])
    expect_error("wrapper content", check_wrapper_shape, [mode1[0], 1, mode1[2][:1]])
    expect_error("wrapper fields", check_wrapper_shape, [1, mode1[2][0], mode1[2][1], mode1[0]])
    expect_error("wrapper envelopes", check_wrapper_shape, [[], *mode1[1:]])
    expect_error("transaction envelope", check_wrapper_shape, [[bytes(32)], *mode1[1:]])
    expect_error("transaction envelope", check_wrapper_shape, [[[1, 2]], *mode1[1:]])
    expect_error("transaction order", check_wrapper_shape, [mode1[0][::-1], *mode1[1:]])
    expect_error("transaction order", check_wrapper_shape, [[mode1[0][0]] * 2, *mode1[1:]])
    expect_error("wrapper dependencies", check_wrapper_shape, [mode1[0], 1, [[], mode1[2][1]]])

    # Decoded response items, correlation, hashes, lengths and ordering.
    items = [mode0, mode1, blob_mode1]
    encoded = [rlp(item) for item in items]
    requested = [h(body) for body in encoded]
    metadata = {h(body): metadata_for(item) for item, body in zip(items, encoded)}
    check_request(7, requested, set(requested))
    expect_error("unannounced wrapper", check_request, 7, requested, {requested[0]})
    held = dict(zip(requested, encoded))
    assert answer_request(7, requested, held, set(requested)) == rlp(reply_for(7, items))
    assert answer_request(7, requested, held, {requested[1]}) == rlp(reply_for(7, items[1:2]))
    assert answer_request(7, [bytes(32)], held, set(requested)) == rlp([7, []])
    assert answer_request(7, requested, {}, set(requested)) == rlp([7, []])
    for returned in (items, items[:1], items[1:], []):
        check_wrapper_response(7, requested, metadata, reply_for(7, returned))
    expect_error("response id", check_wrapper_response, 7, requested, metadata, reply_for(8, items))
    expect_error("response fields", check_wrapper_response, 7, requested, metadata, [7, items, b""])
    expect_error("response entry", check_wrapper_response, 7, requested, metadata, [7, encoded])
    expect_error("response order", check_wrapper_response, 7, requested, metadata, reply_for(7, items[::-1]))
    expect_error("response order", check_wrapper_response, 7, requested, metadata, reply_for(7, [mode0, mode0]))
    for altered in ([mode1[0], 1, [mode1[2][0], b"aggregate proog"]],
                    [[transaction(99)], *mode1[1:]],
                    [mode1[0][:1], *mode1[1:]]):
        expect_error("response hash", check_wrapper_response, 7, requested, metadata, reply_for(7, [altered]))
    wrong_length = {**metadata, requested[0]: (0, len(encoded[0]) + 1, *coverage(mode0))}
    expect_error("announced length", check_wrapper_response, 7, requested, wrong_length, reply_for(7, [mode0]))
    for i, item in enumerate(items):
        wrong_mode = {**metadata, requested[i]: (1 - item[1], len(encoded[i]), *coverage(item))}
        expect_error("announced mode", check_wrapper_response, 7, requested, wrong_mode, reply_for(7, [item]))
    # Distinct proof bytes can cover identical transactions and dependencies.
    alternative = [mode1[0], 1, [mode1[2][0], b"another aggregate proof"]]
    alt_announcement = describe(1, rlp(alternative), *coverage(alternative))
    assert h(rlp(alternative)) != h(rlp(mode1))
    assert may_skip_fetch(alt_announcement, [mode1])
    # Equal dependencies do not establish equal transaction coverage.
    different_txs = [[transaction(99)], *mode1[1:]]
    different_announcement = describe(1, rlp(different_txs), *coverage(different_txs))
    assert coverage(different_txs)[0] == coverage(mode1)[0]
    assert not may_skip_fetch(different_announcement, [mode1])
    assert not may_skip_fetch(alt_announcement, [])  # No validated coverage.
    for index, reason in [(2, "announced dependency hash"), (3, "announced transaction hash")]:
        wrong = list(metadata[requested[1]])
        wrong[index] = bytes(32)
        expect_error(reason, check_wrapper_response, 7, requested,
                     {**metadata, requested[1]: tuple(wrong)}, reply_for(7, [mode1]))
    # A false hint is rejected even when the proof would fail verification.
    # Stubs test ordering only, not cryptographic correctness.
    verification_calls = []
    def invalid_proof(item):
        verification_calls.append(item)
        return False
    for index, reason in [(2, "announced dependency hash"), (3, "announced transaction hash")]:
        wrong = list(metadata[requested[1]])
        wrong[index] = bytes(32)
        expect_error(reason, check_wrapper_response, 7, requested,
                     {**metadata, requested[1]: tuple(wrong)}, reply_for(7, [mode1]),
                     0, None, invalid_proof)
        assert verification_calls == []
    expect_error("proof verification", check_wrapper_response, 7, requested, metadata,
                 reply_for(7, [mode1]), 0, None, invalid_proof)
    assert verification_calls == [mode1]
    # Changing a scheme changes the wire digest, even if claim/key bytes match.
    changed_deps = [bytes(31) + b"\x11" + dep[32:] for dep in mode1[2][0]]
    changed_scheme = [mode1[0], 1, [changed_deps, mode1[2][1]]]
    assert coverage(changed_scheme)[0] != coverage(mode1)[0]
    # Different verifier outcomes cannot change hints over the same bytes.
    check_wrapper_response(7, requested, metadata, reply_for(7, [mode1]),
                           verify=lambda item: True)
    assert wrappers_response(7, encoded) == rlp(reply_for(7, items))

    # A full 32-hash request can be satisfied in one response for small wrappers.
    small_items = [[[transaction(i)], 0, mode0[2]] for i in range(32)]
    small = [rlp(item) for item in small_items]
    small_hashes = [h(body) for body in small]
    small_metadata = {h(body): metadata_for(item) for item, body in zip(small_items, small)}
    check_request(7, small_hashes, set(small_hashes))
    assert len(splice(7, small)) < SOFT_RESPONSE_LIMIT
    assert wrappers_response(7, small) == splice(7, small)
    check_wrapper_response(7, small_hashes, small_metadata, reply_for(7, small_items))

    # Byte-derived transaction count: no independent 4,096-envelope ceiling.
    many_envelopes = sorted((transaction(i) for i in range(4097)), key=transaction_hash)
    many = [many_envelopes, 1, mode1[2]]
    many_body = rlp(many)
    check_wrapper_response(7, [h(many_body)], {h(many_body): metadata_for(many)}, reply_for(7, [many]))

    # Five fixtures with 1,000,000-byte synthetic proofs; none is a valid proof.
    large_items = [[mode1[0], 1, [mode1[2][0], bytes([i]) * 1_000_000]] for i in range(5)]
    large = [rlp(item) for item in large_items]
    assert all(len(body) <= MAX_WRAPPER_BYTES for body in large)
    assert len(splice(7, large[:2])) <= SOFT_RESPONSE_LIMIT < len(splice(7, large[:3]))
    assert wrappers_response(7, large) == splice(7, large[:3])
    assert len(wrappers_response(max_id, large)) < SOFT_RESPONSE_LIMIT + MAX_WRAPPER_BYTES
    large_hashes = [h(body) for body in large]
    large_metadata = {h(body): metadata_for(item) for item, body in zip(large_items, large)}
    check_wrapper_response(7, large_hashes, large_metadata, reply_for(7, large_items[:2]))
    check_wrapper_response(7, large_hashes, large_metadata, reply_for(7, large_items[:3]))
    # The soft limit is not a receiver-side 4 MiB limit.
    assert len(splice(7, large)) > SOFT_RESPONSE_LIMIT + MAX_WRAPPER_BYTES
    check_wrapper_response(7, large_hashes, large_metadata, reply_for(7, large_items))

    # Fill the wrapper to exactly 2 MiB with proof and synthetic envelope bytes.
    # Use a 1.5 MiB proof fixture; only the complete wrapper has a byte ceiling.
    proof = bytes(1_572_864)
    payload_size = MAX_WRAPPER_BYTES - len(proof) - 1024
    for _ in range(5):
        tx_body = transaction_body(0)
        tx_body[3] = [bytes(payload_size)]
        at_limit = [[FRAME_TX_TYPE + rlp(tx_body)], 1, [mode1[2][0], proof]]
        body = rlp(at_limit)
        if len(body) == MAX_WRAPPER_BYTES:
            break
        payload_size += MAX_WRAPPER_BYTES - len(body)
    assert len(body) == MAX_WRAPPER_BYTES
    check_wrapper_response(7, [h(body)], {h(body): metadata_for(at_limit)}, reply_for(7, [at_limit]))
    assert wrappers_response(max_id, [body, encoded[0]]) == splice(max_id, [body])
    assert len(splice(max_id, [body])) > SOFT_RESPONSE_LIMIT  # Response framing only.
    tx_body[3] = [bytes(payload_size + 1)]
    oversized = [[FRAME_TX_TYPE + rlp(tx_body)], 1, [mode1[2][0], proof]]
    assert len(rlp(oversized)) == MAX_WRAPPER_BYTES + 1
    expect_error("wrapper length", check_wrapper_response, 7, [h(rlp(oversized))],
                 {h(rlp(oversized)): metadata_for(oversized)}, reply_for(7, [oversized]))

    # Blob metadata is inside wrapper identity; cells are retrieved separately.
    blob = blob_transaction()
    blob_encoded = FRAME_TX_TYPE + rlp(blob)
    tx_hash = transaction_hash(blob_encoded)
    assert tx_hash == h(FRAME_TX_TYPE + rlp(blob[0])) != h(blob_encoded)
    altered_proofs = [bytes([42]) * 48] + blob[4][1:]
    altered_blob = FRAME_TX_TYPE + rlp(blob[:4] + [altered_proofs])
    assert transaction_hash(altered_blob) == tx_hash
    assert h(rlp([[blob_encoded], *mode1[1:]])) != h(rlp([[altered_blob], *mode1[1:]]))
    expect_error("transaction order", check_wrapper_shape, [[blob_encoded, altered_blob], *mode1[1:]])
    for nonce in range(2, 100):
        blob_items = sorted(mode1[0] + [FRAME_TX_TYPE + rlp(blob_transaction(nonce))], key=transaction_hash)
        raw_hash_order = sorted(blob_items, key=h)
        if raw_hash_order != blob_items:
            break
    assert raw_hash_order != blob_items
    expect_error("transaction order", check_wrapper_shape, [raw_hash_order, *mode1[1:]])
    for value in (b"", [bytes(131072)]):
        expect_error("blob data elision", transaction_hash, FRAME_TX_TYPE + rlp(blob[:2] + [value] + blob[3:]))
    expect_error("missing blob metadata", transaction_hash, FRAME_TX_TYPE + rlp(blob[0]))
    expect_error("blob wrapper version", transaction_hash, FRAME_TX_TYPE + rlp([blob[0], 0] + blob[2:]))
    expect_error("commitment count", transaction_hash, FRAME_TX_TYPE + rlp(blob[:3] + [blob[3][:1], blob[4]]))
    expect_error("commitment encoding", transaction_hash, FRAME_TX_TYPE + rlp(blob[:3] + [[bytes(47)] * 2, blob[4]]))
    expect_error("commitment hash", transaction_hash, FRAME_TX_TYPE + rlp(blob[:3] + [blob[3][::-1], blob[4]]))
    for proofs in (blob[4][:-1], blob[4] + [bytes(48)]):
        expect_error("cell proof count", transaction_hash, FRAME_TX_TYPE + rlp(blob[:4] + [proofs]))
    expect_error("cell proof encoding", transaction_hash, FRAME_TX_TYPE + rlp(blob[:4] + [[bytes(47)] * len(blob[4])]))

    # Compact transport preserves full identity, including blob metadata.
    for item in (mode0, mode1, blob_mode1):
        cache = {h(tx): tx for tx in item[0]}
        digest = h(rlp(item))
        meta = {digest: metadata_for(item)}
        compact = compact_wrapper(item, set(cache))
        assert len(rlp(compact)) < len(rlp(item))
        reply = [7, [[digest, compact]]]
        assert reconstruct(compact, 1, cache, meta[digest][1]) == item
        assert check_wrapper_response(7, [digest], meta, reply, compact=1, cache=cache) == []
        assert check_wrapper_response(7, [digest], meta, reply, compact=1) == [digest]
        # Eviction leads to a fresh full request, not a transaction fetch.
        check_request(8, [digest], {digest}, compact=0)
        for flag in (0, 1):
            # A minimal client can serve full bytes and receive without a cache.
            assert check_wrapper_response(8, [digest], meta, reply_for(8, [item]), compact=flag) == []
        decoded_compact = decode(rlp(compact), strict=True)
        decoded_full = decode(rlp(item), strict=True)
        assert all(isinstance(entry, list) and len(entry) == 1 for entry in decoded_compact[0])
        assert all(isinstance(entry, bytes) for entry in decoded_full[0])
        expect_error("reference in full response", check_wrapper_response, 7, [digest], meta, reply, 0, cache)
        assert compact_wrapper(item, set()) == item
        mixed = compact_wrapper(item, {h(item[0][0])})
        assert isinstance(mixed[0][0], list) and isinstance(mixed[0][1], bytes)
        assert check_wrapper_response(7, [digest], meta, [7, [[digest, mixed]]], compact=1, cache=cache) == []
        partial_cache = dict(cache)
        del partial_cache[h(item[0][0])]
        assert check_wrapper_response(7, [digest], meta, reply, compact=1, cache=partial_cache) == [digest]
        wrong_cache = {**cache, h(item[0][0]): transaction(999)}
        expect_error("encoding hash", check_wrapper_response, 7, [digest], meta, reply, 1, wrong_cache)
        malformed = [[[bytes(31)], *compact[0][1:]], *compact[1:]]
        expect_error("encoding reference", check_wrapper_response, 7, [digest], meta,
                     [7, [[digest, malformed]]], 1, cache)
        false_digest = h(b"false canonical wrapper")
        expect_error("response hash", check_wrapper_response, 7, [false_digest],
                     {false_digest: meta[digest]}, [7, [[false_digest, compact]]], 1, cache)
    # Same consensus transaction hash does not identify the exact blob encoding.
    assert h(blob_encoded) != h(altered_blob)
    assert compact_wrapper([[blob_encoded], *mode1[1:]], {h(altered_blob)})[0] == [blob_encoded]
    # The compact byte count cannot bypass the canonical 2 MiB bound.
    compact_oversized = compact_wrapper(oversized, {h(tx) for tx in oversized[0]})
    assert len(rlp(compact_oversized)) < MAX_WRAPPER_BYTES
    expect_error("wrapper length", reconstruct, compact_oversized, 1,
                 {h(tx): tx for tx in oversized[0]}, MAX_WRAPPER_BYTES)

    print("PASS: announcement, full-envelope and sparse-blob wrapper encoding vectors; "
          "mode 2 raw-witness encodings and proof-coverage suppression; "
          "compact reconstruction and full retries, message counts, ordering, metadata matching, byte limits and response packing. "
          "Transaction/proof/signature validity, native-to-leaf conformance, KZG verification and client-state sequences are not tested.")


if __name__ == "__main__":
    main()
