#!/usr/bin/env python3
"""Check EIP-8518 Bloom coverage and wrapper encoding fixtures.

Use --write to refresh the vectors. Scalars are represented as Python integers. This checks encoding and blob
metadata binding, not transaction execution, proof validity or client state.

Requires Python 3.9+, pycryptodome and rlp. Run with:
    python3 assets/eip-8518/check_vectors.py
"""

import json
import sys
from copy import deepcopy
from pathlib import Path

from rlp import decode

# Wrapper-specific fixtures live with this EIP.
from encoding import (h, uint, rlp, pattern, versioned_hash, transaction_body,
                      transaction, blob_transaction, transaction_hash, frame_payload,
                      frame_gas, check_claims, reply_for, answer_request,
                      wrappers_response, splice, rlp_list, expect_error)

SOFT_RESPONSE_LIMIT = 2097152
MAX_WRAPPER_BYTES = SOFT_RESPONSE_LIMIT
MAX_ANNOUNCEMENT_BYTES = 2**18
MAX_ANNOUNCEMENTS = 64
MAX_WRAPPERS_PER_REQUEST = 32
LEANSPHINCS_SCHEME = 0x10
FRAME_TX_TYPE = b"\x06"
CELLS_PER_EXT_BLOB = 128
# Inline-metadata threshold, independent of fork-specific validity limits.
MAX_INLINE_TRANSACTIONS = 17
METADATA_FIELDS = 5
SYNTHETIC_FRAME_GAS = 100000


def connection_salt(initiator_nonce, recipient_nonce):
    assert len(initiator_nonce) == len(recipient_nonce) == 32
    return h(b"EIP8518:coverage:v1" + initiator_nonce + recipient_nonce)


def bloom_size(count):
    assert count >= 1
    return min(8192, (10 * count + 7) // 8)


def positions(txhash, salt, size):
    assert isinstance(salt, bytes) and len(salt) == 32
    digest = h(salt + txhash)
    return [int.from_bytes(digest[4*i:4*i+4], "big") % (8 * size) for i in range(7)]


def bloom(hashes, salt):
    bits = bytearray(bloom_size(len(hashes)))
    for txhash in hashes:
        for b in positions(txhash, salt, len(bits)):
            bits[b // 8] |= 1 << (b % 8)
    return bytes(bits)


def positive(bits, txhash, salt):
    return all(bits[b // 8] & (1 << (b % 8)) for b in positions(txhash, salt, len(bits)))


def transaction_metadata(envelopes):
    # All wrappers carry EIP-8141 frame transactions; no type or nonce hint.
    payloads = [frame_payload(tx) for tx in envelopes]
    return [[len(tx) for tx in envelopes],
            [transaction_hash(tx) for tx in envelopes],
            [payload[2] for payload in payloads],
            [[int.from_bytes(fee, "big") for fee in payload[5]] for payload in payloads],
            [frame_gas(payload) for payload in payloads]]

def mismatched_held_transactions(meta, held):
    # Source, fees and gas are hash-bound; the pooled encoding's size is not.
    mismatches = []
    for i, digest in enumerate(meta[1]):
        if digest not in held:
            continue
        envelope = held[digest]
        assert transaction_hash(envelope) == digest, "held transaction hash"
        expected = transaction_metadata([envelope])
        if any(meta[field][i] != expected[field][0] for field in (2, 3, 4)):
            mismatches.append(digest)
    return mismatches

def inline_metadata(item):
    if item[1] == 0 and len(item[0]) <= MAX_INLINE_TRANSACTIONS:
        return transaction_metadata(item[0])
    return []


def describe(mode, body, deps_hash, txs_hash, txs_meta=(), tx_count=1, coverage_filter=b""):
    # Each entry appends transaction count and a connection-specific filter.
    if mode not in (0, 1):
        raise ValueError("wrapper mode")
    if not 1 <= len(body) <= MAX_WRAPPER_BYTES:
        raise ValueError("wrapper size")
    return [mode, len(body), h(body), deps_hash, txs_hash, list(txs_meta), tx_count, coverage_filter]


# Synthetic fixtures use three fees; transport accepts other fee-list lengths.
FIXTURE_FEE_FIELDS = 3


def check_metadata(meta, txs_hash, length, limit):
    assert isinstance(meta, list) and len(meta) == METADATA_FIELDS, "metadata fields"
    sizes, hashes, sources, fees, gas = meta
    assert isinstance(hashes, list) and 1 <= len(hashes) and (limit is None or len(hashes) <= limit), "metadata count"
    assert all(isinstance(field, list) and len(field) == len(hashes) for field in meta), "metadata lengths"
    assert all(isinstance(size, int) and size >= 1 for size in sizes) and sum(sizes) < length, "metadata size"
    assert all(isinstance(digest, bytes) and len(digest) == 32 for digest in hashes), "metadata hash"
    assert hashes == sorted(set(hashes)), "metadata order"
    assert h(b"".join(hashes)) == txs_hash, "metadata transaction hash"
    assert all(isinstance(source, bytes) and len(source) == 20 for source in sources), "metadata source"
    assert all(isinstance(fee, list)
               and all(isinstance(value, int) and 0 <= value < 2**256 for value in fee) for fee in fees), "metadata fees"
    assert all(isinstance(value, int) and 0 <= value < 2**64 for value in gas), "metadata gas"


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


def metadata_for(item, salt):
    hashes = [transaction_hash(tx) for tx in item[0]]
    return (item[1], len(rlp(item)), *coverage(item), inline_metadata(item), len(hashes),
            bloom(hashes, salt) if item[1] == 1 else b"")


def announce(item, salt):
    mode, length, deps_hash, txs_hash, meta, count, bits = metadata_for(item, salt)
    return [mode, length, h(rlp(item)), deps_hash, txs_hash, meta, count, bits]


def may_skip_fetch(announcement, held_valid_wrappers, needs_direct=False):
    # Caller supplies only wrappers valid under the current rules.
    return any(tuple(announcement[3:5]) == coverage(item)
               for item in held_valid_wrappers if not (needs_direct and announcement[0] == 0 and item[1] != 0))


def check_announcement_size(payload):
    assert len(payload) <= MAX_ANNOUNCEMENT_BYTES, "announcement bytes"


def check_announcements(entries):
    assert 1 <= len(entries) <= MAX_ANNOUNCEMENTS, "announcement count"
    for entry in entries:
        assert isinstance(entry, list) and len(entry) == 8, "announcement fields"
        mode, length, digest, deps_hash, txs_hash, txs_meta, count, bits = entry
        assert isinstance(mode, int) and mode >= 0, "announcement mode"
        assert isinstance(length, int) and 1 <= length <= MAX_WRAPPER_BYTES, "announcement length"
        assert isinstance(digest, bytes) and len(digest) == 32, "announcement hash"
        assert isinstance(deps_hash, bytes) and len(deps_hash) == 32, "announcement dependency hash"
        assert isinstance(txs_hash, bytes) and len(txs_hash) == 32, "announcement transaction hash"
        assert isinstance(txs_meta, list), "announcement metadata"
        assert type(count) is int and 1 <= count <= length, "announcement transaction count"
        assert isinstance(bits, bytes) and len(bits) <= 8192, "filter size"
        if mode == 0:
            assert bits == b"", "mode 0 filter"
        elif mode == 1:
            assert len(bits) == bloom_size(count), "filter length"
        if txs_meta and mode in (0, 1):
            assert mode == 0, "metadata mode"
            check_metadata(txs_meta, txs_hash, length, MAX_INLINE_TRANSACTIONS)
            assert len(txs_meta[1]) == count, "metadata transaction count"
    hashes = [entry[2] for entry in entries]
    assert hashes == sorted(set(hashes)), "announcement order"
    check_announcement_size(rlp(entries))
    return [entry for entry in entries if entry[0] in (0, 1)]


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
    assert isinstance(mode, int) and mode in (0, 1), "wrapper mode"
    assert isinstance(deps, list) and deps, "wrapper dependencies"
    assert all(isinstance(dep, bytes) and len(dep) == 96 for dep in deps), "dependency length"
    assert deps == sorted(set(deps)), "dependency order"
    if mode == 0:
        assert isinstance(proof, list) and len(proof) == len(deps), "direct proofs"
        assert all(isinstance(witness, bytes) for witness in proof), "direct witness"
    else:
        assert isinstance(proof, bytes) and proof, "aggregate proof"
    assert isinstance(envelopes, list) and envelopes, "wrapper envelopes"
    hashes = [transaction_hash(tx) for tx in envelopes]
    assert hashes == sorted(set(hashes)), "transaction order"


def compact_wrapper(item, expected_known):
    # Expected cache hits can be inferred from any prior wrapper announcements.
    txs = [[h(tx)] if h(tx) in expected_known and len(rlp([h(tx)])) < len(rlp(tx)) else tx
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


def check_wrapper_response(request_id, requested, announced_metadata, reply, compact=0, cache=None, verify=None,
                           salt=None):
    # Announcements and salt belong to the serving connection.
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
        mode, length, deps_hash, txs_hash, txs_meta, count, bits = announced_metadata[digest]
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
        assert txs_meta == inline_metadata(item), "announced transaction metadata"
        assert count == len(item[0]), "announced transaction count"
        actual_filter = bloom([transaction_hash(tx) for tx in item[0]], salt) if mode == 1 else b""
        assert bits == actual_filter, "announced coverage filter"
        if verify is not None:
            assert verify(item), "proof verification"
    return retries


def check_versioned_shape(version, code, message):
    assert version == 76, "message version"
    if code == 0x18:
        assert isinstance(message, list) and all(isinstance(e, list) and len(e) == 8 for e in message), "announcement fields"
    elif code == 0x19:
        assert isinstance(message, list) and len(message) == 3, "request fields"
    else:
        assert code == 0x1a, "message code"


def can_send_wrapper(version, item, enabled_schemes):
    schemes = {int.from_bytes(dep[:32], "big") for dep in item[2][0]}
    return version == 76 and item[1] in (0, 1) and schemes <= enabled_schemes


def main():
    salt = connection_salt(bytes(range(32)), bytes(range(32, 64)))
    other_salt = connection_salt(bytes(range(32)), bytes([99]) * 32)
    items = list(wrapper_items().values())
    metadata = {h(rlp(item)): metadata_for(item, salt) for item in items}
    requested = list(metadata)
    vectors = {}
    for name, item in wrapper_items().items():
        vectors[name] = {
            "body": rlp(item).hex(), "announcement_rlp": rlp(announce(item, salt)).hex(),
            "response_rlp": rlp(reply_for(7, [item])).hex(),
            "compact_response_rlp": rlp([7, [[h(rlp(item)), compact_wrapper(item, {h(tx) for tx in item[0]})]]]).hex(),
        }
    hashes = [h(uint(i, 4)) for i in range(256)]
    bits = bloom(hashes, salt)
    announcement_vectors = {
        "initiator_nonce": bytes(range(32)).hex(), "recipient_nonce": bytes(range(32, 64)).hex(),
        "salt": salt.hex(), "transaction_hashes": [v.hex() for v in hashes], "filter": bits.hex(),
        "announcements": [rlp(announce(item, salt)).hex() for item in items],
    }
    for filename, expected in (("wrapper-vectors.json", vectors), ("announcement-vectors.json", announcement_vectors)):
        path = Path(__file__).with_name(filename)
        if "--write" in sys.argv:
            path.write_text(json.dumps(expected, indent=2) + "\n")
        assert json.loads(path.read_text()) == expected
    assert len(bits) == 320
    assert all(positive(bits, txhash, salt) for txhash in hashes)
    assert bloom(hashes[::-1], salt) == bits
    assert bloom(hashes, other_salt) != bits
    assert bloom_size(6554) == bloom_size(100000) == 8192
    # A deterministic false-positive example demonstrates why hints cannot suppress.
    false_positive = next(h(b"absent" + uint(i, 4)) for i in range(10000)
                          if positive(bits, h(b"absent" + uint(i, 4)), salt))
    assert false_positive not in hashes
    assert positive(bytes([255]) * 8192, false_positive, salt)
    for item in items:
        entry = announce(item, salt)
        check_announcements([entry])
        check_wrapper_shape(item)
        check_wrapper_response(7, requested, metadata, reply_for(7, [item]), salt=salt)
        # A filter is never consulted by exact validated-coverage suppression.
        assert not may_skip_fetch(entry, [])
        assert may_skip_fetch(entry, [item])
        assert announce(item, salt)[1:5] == announce(item, other_salt)[1:5]
    entry = announce(items[1], salt)
    for field, value, reason in ((6, 0, "announcement transaction count"),
                                 (6, entry[1] + 1, "announcement transaction count"),
                                 (7, b"", "filter length"), (7, entry[7] + b"\x00", "filter length"),
                                 (7, bytes(8193), "filter size")):
        bad = deepcopy(entry)
        bad[field] = value
        expect_error(reason, check_announcements, [bad])
    bad = announce(items[0], salt)
    bad[7] = b"\x00"
    expect_error("mode 0 filter", check_announcements, [bad])
    bad[7] = b""
    bad[6] += 1
    expect_error("metadata transaction count", check_announcements, [bad])
    # Unsupported modes remain cheaply bounded before being ignored.
    bad = deepcopy(entry)
    bad[0] = 99
    assert check_announcements([bad]) == []
    bad[7] = bytes(8193)
    expect_error("filter size", check_announcements, [bad])
    # Large filters can force splitting well before the 64-entry limit.
    wide = [[1, MAX_WRAPPER_BYTES, uint(i, 32), bytes(32), bytes(32), [], 100000, bytes(8192)] for i in range(64)]
    fit = next(i - 1 for i in range(1, 65) if len(rlp(wide[:i])) > MAX_ANNOUNCEMENT_BYTES)
    check_announcements(wide[:fit])
    expect_error("announcement bytes", check_announcements, wide[:fit+1])
    expect_error("announcement count", check_announcements, wide + wide[:1])
    expect_error("announcement order", check_announcements, wide[:2][::-1])
    for flag in (0, 1):
        check_request(7, requested, set(requested), flag)
        check_wrapper_response(7, requested, metadata, reply_for(7, items), flag, salt=salt)
    for returned in ([], items[:1], items[1:]):
        check_wrapper_response(7, requested, metadata, reply_for(7, returned), salt=salt)
    expect_error("response order", check_wrapper_response, 7, requested, metadata, reply_for(7, items[::-1]), 0, None, None, salt)
    expect_error("response order", check_wrapper_response, 7, requested, metadata, reply_for(7, items[:1]*2), 0, None, None, salt)
    expect_error("response hash", check_wrapper_response, 7, requested, metadata, [7, [[bytes(32), items[0]]]])
    # Cache can originate from any peer; a miss is a full-fetch retry, not blame.
    item = items[1]
    cache = {h(tx): tx for tx in item[0]}
    compact_reply = [7, [[requested[1], compact_wrapper(item, set(cache))]]]
    assert not check_wrapper_response(7, requested, metadata, compact_reply, 1, cache, salt=salt)
    assert check_wrapper_response(7, requested, metadata, compact_reply, 1, {}, salt=salt) == requested[1:2]
    expect_error("reference in full response", check_wrapper_response, 7, requested, metadata, compact_reply, 0, cache)
    expect_error("encoding hash", check_wrapper_response, 7, requested, metadata, compact_reply, 1, {key: b"bad" for key in cache})
    calls = []
    def invalid(item):
        calls.append(item)
        return False
    for index, value, reason in ((5, 3, "announced transaction count"),
                                 (6, bytes(len(metadata[requested[1]][6])), "announced coverage filter"),
                                 (2, bytes(32), "announced dependency hash"),
                                 (3, bytes(32), "announced transaction hash")):
        false = dict(metadata)
        fields = list(false[requested[1]])
        fields[index] = value
        false[requested[1]] = fields
        expect_error(reason, check_wrapper_response, 7, requested, false, reply_for(7, [item]), 0, None, invalid, salt)
        assert not calls
    expect_error("proof verification", check_wrapper_response, 7, requested, metadata, reply_for(7, [item]), 0, None, invalid, salt)
    assert calls == [item]
    # A correctly served wrapper on a different connection must use that connection's salt.
    other_metadata = {requested[1]: metadata_for(item, other_salt)}
    check_wrapper_response(7, requested, other_metadata, reply_for(7, [item]), salt=other_salt)
    expect_error("announced coverage filter", check_wrapper_response, 7, requested, metadata,
                 reply_for(7, [item]), 0, None, None, other_salt)
    # Unknown scheme identifiers are wire data; the proof verifier decides support.
    unknown = deepcopy(item)
    unknown[2][0] = [bytes(31) + b"\xfe" + d[32:] for d in unknown[2][0]]
    check_wrapper_shape(unknown)
    for code in (0x1b, 0x1c):
        expect_error("message code", check_versioned_shape, 76, code, [])
    print(f"Bloom vectors passed; 256 transactions: {len(bits)} filter bytes; {fit} capped filters fit per announcement")


if __name__ == "__main__":
    main()
