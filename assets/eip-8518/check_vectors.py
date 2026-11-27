#!/usr/bin/env python3
"""Synthetic aggregate-only wire checks, not core execution or proof verification.

Requires pycryptodome and rlp. --write refreshes the checked-in encoding vectors.
The native verifier address and claim mapping are fixtures, not assigned values.
"""
import json
import sys
from copy import deepcopy
from pathlib import Path
from encoding import (h, rlp, uint, transaction, pooled_parts, transaction_hash,
                      dependencies, aggregatable, normalize, FRAME_TX_TYPE,
                      reply_for, wrappers_response, expect_error)

MAX_WRAPPER_BYTES = 2**21
MAX_ANNOUNCEMENTS = 64
MAX_ANNOUNCEMENT_BYTES = 6723
MAX_REQUESTS = 32


def make_wrapper(nonces=(0, 1), blob=False):
    txs = sorted([normalize(transaction(n, blob)) for n in nonces], key=transaction_hash)
    deps = sorted(set(d for tx in txs for d in dependencies(tx)))
    return [txs, deps, b"synthetic aggregate proof"]


def coverage(item):
    return h(b"".join(item[1])), h(b"".join(transaction_hash(tx) for tx in item[0]))


def announce(item):
    body = rlp(item)
    return [len(body), h(body), *coverage(item)]


def check_announcement_size(payload):
    assert len(payload) <= MAX_ANNOUNCEMENT_BYTES, "announcement bytes"


def check_announcements(entries):
    assert 1 <= len(entries) <= MAX_ANNOUNCEMENTS, "announcement count"
    for entry in entries:
        assert isinstance(entry, list) and len(entry) == 4, "announcement fields"
        length, digest, deps_hash, txs_hash = entry
        assert type(length) is int and 1 <= length <= MAX_WRAPPER_BYTES, "announcement length"
        assert all(isinstance(v, bytes) and len(v) == 32 for v in entry[1:]), "announcement hash"
    assert [e[1] for e in entries] == sorted(set(e[1] for e in entries)), "announcement order"
    check_announcement_size(rlp(entries))


def check_request(request_id, requested, compact=0):
    assert type(request_id) is int and 0 <= request_id < 2**64, "request id"
    assert type(compact) is int and compact in (0, 1), "compact flag"
    assert 1 <= len(requested) <= MAX_REQUESTS, "request count"
    assert all(isinstance(v, bytes) and len(v) == 32 for v in requested), "request hash"
    assert len(set(requested)) == len(requested), "request duplicates"


def check_shape(item):
    assert isinstance(item, list) and len(item) == 3, "wrapper fields"
    txs, deps, proof = item
    assert isinstance(txs, list) and txs, "wrapper transactions"
    assert isinstance(deps, list) and deps, "wrapper dependencies"
    assert all(isinstance(d, bytes) and len(d) == 96 for d in deps), "dependency encoding"
    assert deps == sorted(set(deps)), "dependency order"
    assert isinstance(proof, bytes) and proof, "aggregate proof"
    hashes = [transaction_hash(tx) for tx in txs]
    assert hashes == sorted(set(hashes)), "transaction order"
    expected = set()
    for tx in txs:
        body, _, witnesses, _ = pooled_parts(tx)
        assert dependencies(tx), "uncovered transaction"
        for claim, witness in zip(body[3], witnesses):
            if aggregatable(claim):
                assert witness == b"", "covered witness"
            else:
                assert len(witness) == int.from_bytes(claim[4], "big"), "retained witness length"
        expected.update(dependencies(tx))
    assert deps == sorted(expected), "dependency union"
    assert len(rlp(item)) <= MAX_WRAPPER_BYTES, "wrapper size"


def compact(item):
    return [[[h(tx)] if len(rlp([h(tx)])) < len(rlp(tx)) else tx for tx in item[0]], *item[1:]]


def reconstruct(item, flag, cache, length):
    assert isinstance(item, list) and len(item) == 3, "wrapper fields"
    assert isinstance(item[0], list), "wrapper transactions"
    assert 1 <= len(rlp(item)) <= length <= MAX_WRAPPER_BYTES, "wrapper length"
    txs = []
    missing = False
    size = len(rlp(item))
    for entry in item[0]:
        if isinstance(entry, list):
            assert flag == 1, "reference in full response"
            assert len(entry) == 1 and isinstance(entry[0], bytes) and len(entry[0]) == 32, "encoding reference"
            tx = cache.get(entry[0])
            if tx is None:
                missing = True
                continue
            assert isinstance(tx, bytes) and h(tx) == entry[0], "encoding hash"
            assert len(rlp(entry)) < len(rlp(tx)), "reference size"
            size += len(rlp(tx)) - len(rlp(entry))
            assert size <= length, "wrapper length"
        else:
            assert isinstance(entry, bytes), "transaction encoding"
            tx = entry
        txs.append(tx)
    if missing:
        return None
    result = [txs, *item[1:]]
    assert len(rlp(result)) <= length, "wrapper length"
    return result


def check_response(request_id, requested, announcements, reply, flag=0, cache=None, manifests=None, verify=None):
    assert isinstance(reply, list) and len(reply) == 2 and isinstance(reply[1], list), "response fields"
    assert reply[0] == request_id, "response id"
    positions = {v: i for i, v in enumerate(requested)}
    previous = -1
    missing = []
    for entry in reply[1]:
        assert isinstance(entry, list) and len(entry) == 2, "response entry"
        digest, wire = entry
        assert isinstance(digest, bytes) and digest in positions, "response hash"
        assert positions[digest] > previous, "response order"
        previous = positions[digest]
        length, _, deps_hash, txs_hash = announcements[digest]
        item = reconstruct(wire, flag, cache or {}, length)
        if item is None:
            missing.append(digest)
            continue
        assert h(rlp(item)) == digest, "response hash"
        assert len(rlp(item)) == length, "announced length"
        check_shape(item)
        assert coverage(item) == (deps_hash, txs_hash), "coverage hint"
        if manifests and digest in manifests:
            assert manifests[digest] == [transaction_hash(tx) for tx in item[0]], "manifest mismatch"
        if verify:
            assert verify(item), "proof verification"
    return missing


def manifest(item):
    return [h(rlp(item)), [transaction_hash(tx) for tx in item[0]]]


def check_manifests(request_id, requested, announcements, reply):
    assert reply[0] == request_id, "response id"
    previous = -1
    positions = {v: i for i, v in enumerate(requested)}
    for digest, hashes in reply[1]:
        assert digest in positions, "response hash"
        assert positions[digest] > previous, "response order"
        previous = positions[digest]
        assert isinstance(hashes, list) and hashes, "manifest hashes"
        assert all(isinstance(v, bytes) and len(v) == 32 for v in hashes), "manifest hash"
        assert hashes == sorted(set(hashes)), "manifest order"
        assert len(rlp(hashes)) < announcements[digest][0], "manifest size"
        assert h(b"".join(hashes)) == announcements[digest][3], "manifest hash"


def main():
    items = [make_wrapper(), make_wrapper((2,), True)]
    announcements = {announce(w)[1]: announce(w) for w in items}
    requested = list(announcements)
    vectors = {}
    for name, item in zip(("aggregate", "mixed_blob"), items):
        check_shape(item)
        vectors[name] = {
            "wrapper_rlp": rlp(item).hex(), "announcement_rlp": rlp(announce(item)).hex(),
            "response_rlp": rlp(reply_for(7, [item])).hex(),
            "compact_response_rlp": rlp([7, [[h(rlp(item)), compact(item)]]]).hex(),
            "manifest_response_rlp": rlp([9, [manifest(item)]]).hex(),
            "pooled_transaction": transaction(2 if name == "mixed_blob" else 0, name == "mixed_blob").hex(),
        }
    announcement_vectors = [{"announcement_rlp": rlp(e).hex(), "wrapper_hash": e[1].hex()}
                            for e in announcements.values()]
    for filename, expected in (("wrapper-vectors.json", vectors), ("announcement-vectors.json", announcement_vectors)):
        path = Path(__file__).with_name(filename)
        if "--write" in sys.argv:
            path.write_text(json.dumps(expected, indent=2) + "\n")
        assert json.loads(path.read_text()) == expected
    maximum = [[MAX_WRAPPER_BYTES, uint(i, 32), bytes(32), bytes(32)] for i in range(64)]
    check_announcements(maximum)
    assert len(rlp(maximum)) == MAX_ANNOUNCEMENT_BYTES
    expect_error("announcement bytes", check_announcement_size, bytes(MAX_ANNOUNCEMENT_BYTES + 1))
    expect_error("announcement count", check_announcements, [])
    expect_error("announcement count", check_announcements, maximum + maximum[:1])
    expect_error("announcement order", check_announcements, maximum[::-1])
    expect_error("announcement fields", check_announcements, [[1, *maximum[0]]])
    expect_error("announcement length", check_announcements, [[MAX_WRAPPER_BYTES + 1, *maximum[0][1:]]])
    for flag in (0, 1):
        check_request(7, requested, flag)
        check_response(7, requested, announcements, reply_for(7, items), flag)
    expect_error("compact flag", check_request, 7, requested, 2)
    expect_error("request count", check_request, 7, [uint(i, 32) for i in range(33)])
    expect_error("request duplicates", check_request, 7, requested[:1] * 2)
    for returned in ([], items[:1], items[1:]):
        check_response(7, requested, announcements, reply_for(7, returned))
    expect_error("response order", check_response, 7, requested, announcements, reply_for(7, items[::-1]))
    expect_error("response order", check_response, 7, requested, announcements, reply_for(7, items[:1] * 2))
    expect_error("response id", check_response, 7, requested, announcements, reply_for(8, items))
    expect_error("response hash", check_response, 7, requested, announcements, [7, [[bytes(32), items[0]]]])
    # Consensus hash stays fixed while raw witnesses are normalized away.
    raw = transaction()
    normal = normalize(raw)
    assert transaction_hash(raw) == transaction_hash(normal)
    parts = pooled_parts(raw)
    parts[2][0] = b"a different native signature"
    assert normalize(FRAME_TX_TYPE + rlp(parts)) == normal
    assert len(dependencies(normal)) == 1  # Repeated claim, two witness positions.
    assert pooled_parts(normal)[2] == [b"", b"", b"test"]
    # All references can be resolved from independently received pooled transactions.
    cache = {h(normalize(transaction(n))): normalize(transaction(n)) for n in (0, 1)}
    wire = [7, [[requested[0], compact(items[0])]]]
    assert not check_response(7, requested, announcements, wire, 1, cache)
    assert check_response(7, requested, announcements, wire, 1, {}) == requested[:1]
    expect_error("reference in full response", check_response, 7, requested, announcements, wire, 0, cache)
    wrong_cache = {k: b"wrong" for k in cache}
    expect_error("encoding hash", check_response, 7, requested, announcements, wire, 1, wrong_cache)
    expect_error("wrapper length", reconstruct, compact(items[0]), 1, cache, len(rlp(compact(items[0]))))
    expect_error("wrapper length", reconstruct, items[0], 0, {}, MAX_WRAPPER_BYTES + 1)
    # Nonaggregatable witnesses and blob metadata remain bound to encoding identity.
    for raw, field in ((transaction(), 2), (transaction(2, True), 3)):
        parts = pooled_parts(normalize(raw))
        if field == 2:
            parts[2][2] = b"else"
        else:
            parts[3][2][0] = bytes([1]) * 48
        changed = FRAME_TX_TYPE + rlp(parts)
        assert transaction_hash(changed) == transaction_hash(raw)
        assert h(changed) != h(normalize(raw))
    for mutation, reason in (("count", "witness count"), ("covered", "covered witness"), ("missing", "retained witness length")):
        item = deepcopy(items[0])
        parts = pooled_parts(item[0][0])
        if mutation == "count":
            parts[2].pop()
        elif mutation == "covered":
            parts[2][0] = b"raw signature"
        else:
            parts[2][2] = b""
        item[0][0] = FRAME_TX_TYPE + rlp(parts)
        expect_error(reason, check_shape, item)
    calls = []
    def invalid(item):
        calls.append(item)
        return False
    false = deepcopy(announcements)
    false[requested[0]][2] = bytes(32)
    expect_error("coverage hint", check_response, 7, requested, false, reply_for(7, items[:1]), 0, None, None, invalid)
    assert not calls
    expect_error("proof verification", check_response, 7, requested, announcements, reply_for(7, items[:1]), 0, None, None, invalid)
    manifests = [9, [manifest(w) for w in items]]
    check_manifests(9, requested, announcements, manifests)
    expect_error("response order", check_manifests, 9, requested, announcements, [9, manifests[1][::-1]])
    bad = deepcopy(manifests)
    bad[1][0][1].reverse()
    expect_error("manifest order", check_manifests, 9, requested, announcements, bad)
    expect_error("manifest mismatch", check_response, 7, requested, announcements, reply_for(7, items[:1]), 0, None, {requested[0]: [bytes(32)]})
    alternative = [*items[0][:2], b"another proof"]
    assert coverage(alternative) == coverage(items[0]) and announce(alternative)[1] != requested[0]
    # Soft response overshoot keeps the final wrapper complete.
    large = [items[0][0], items[0][1], bytes(2**20)]
    packed = wrappers_response(7, [rlp(large)] * 3)
    assert packed == rlp(reply_for(7, [large] * 2))
    print(f"aggregate-only vectors passed; maximum announcement {len(rlp(maximum))} bytes")


if __name__ == "__main__":
    main()
