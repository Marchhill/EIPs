#!/usr/bin/env python3
"""EIP-8437 RS coding and manifest checks, not a broadcast implementation.

Requires Python 3.9+ and pycryptodome. Run with:
    python3 assets/eip-8437/check_broadcast.py

Synthetic bodies test coding/commitments, not valid block or IL packages.
Profile authorization, signatures, timing and network integration are out of scope.
"""

from copy import deepcopy
from hashlib import sha256
import unittest
from unittest.mock import patch

from check_vectors import commit, h, rlp


DATA, TOTAL, MAX_BODY = 16, 32, 2**20


def require(condition, message):
    if not condition:
        raise ValueError(message)


def mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 256:
            a ^= 0x11d
        b >>= 1
    return result


def power(a, exponent):
    result = 1
    for _ in range(exponent):
        result = mul(result, a)
    return result


def invert(matrix):
    size = len(matrix)
    rows = [row[:] + [int(i == j) for j in range(size)]
            for i, row in enumerate(matrix)]
    for column in range(size):
        pivot = next((i for i in range(column, size) if rows[i][column]), None)
        require(pivot is not None, "singular matrix")
        rows[column], rows[pivot] = rows[pivot], rows[column]
        scale = power(rows[column][column], 254)
        rows[column] = [mul(value, scale) for value in rows[column]]
        for i in range(size):
            if i != column:
                scale = rows[i][column]
                rows[i] = [left ^ mul(scale, right)
                           for left, right in zip(rows[i], rows[column])]
    return [row[size:] for row in rows]


def mix(row, shards):
    output = bytearray(len(shards[0]))
    for coefficient, shard in zip(row, shards):
        for index, value in enumerate(shard):
            output[index] ^= mul(coefficient, value)
    return bytes(output)


VANDERMONDE = [[power(row, column) for column in range(DATA)] for row in range(TOTAL)]
INVERSE = invert(VANDERMONDE[:DATA])
GENERATOR = [list(mix(row, [bytes(part) for part in INVERSE])) for row in VANDERMONDE]


def encode(body):
    require(1 <= len(body) <= MAX_BODY, "body length")
    width = (len(body) + DATA - 1) // DATA
    padded = body.ljust(DATA * width, b"\0")
    data = [padded[i * width:(i + 1) * width] for i in range(DATA)]
    return data + [mix(row, data) for row in GENERATOR[DATA:]]


def coding_for(body, shards):
    return [DATA, DATA, len(shards[0]), sha256(body).digest(),
            [sha256(shard).digest() for shard in shards]]


def geometry(manifest):
    require(isinstance(manifest, list) and len(manifest) == 9, "manifest fields")
    for index, size in ((0, 32), (1, 4), (5, 32)):
        require(isinstance(manifest[index], bytes) and len(manifest[index]) == size,
                "manifest hash or fork digest")
    require(all(type(value) is int and 0 <= value < 2**64 for value in manifest[2:5]),
            "manifest integer")
    descriptor, _, coding = manifest[6:]
    require(isinstance(descriptor, list) and len(descriptor) == 6, "descriptor fields")
    require(descriptor[0] in (2, 3), "broadcast kind")
    length = descriptor[3]
    require(type(length) is int and 1 <= length <= MAX_BODY, "body length")
    require(isinstance(coding, list) and len(coding) == 5, "coding fields")
    require(coding[:2] == [DATA, DATA], "RS geometry")
    require(type(coding[2]) is int and coding[2] == (length + DATA - 1) // DATA,
            "shard width")
    require(isinstance(coding[3], bytes) and len(coding[3]) == 32, "body SHA256")
    require(isinstance(coding[4], list) and len(coding[4]) == TOTAL, "shard hash count")
    require(all(isinstance(value, bytes) and len(value) == 32 for value in coding[4]),
            "shard hash length")
    return length, coding[2]


def recover(manifest, received):
    length, width = geometry(manifest)  # Before allocating a matrix or output.
    coding, descriptor = manifest[8], manifest[6]
    require(len(received) == DATA, "need sixteen distinct shards")
    indices, shards = zip(*received)
    require(all(type(i) is int and 0 <= i < TOTAL for i in indices)
            and len(set(indices)) == DATA, "shard indices")
    for index, shard in received:
        require(len(shard) == width, "shard size")
        require(sha256(shard).digest() == coding[4][index], "shard hash")
    decoded = invert([GENERATOR[i] for i in indices])
    padded = b"".join(mix(row, shards) for row in decoded)
    require(not any(padded[length:]), "nonzero padding")
    body = padded[:length]
    require(sha256(body).digest() == coding[3], "body SHA256")
    require(h(body) == descriptor[4], "original content commitment")
    rebuilt, _, _ = commit(body, descriptor[0], descriptor[1], descriptor[2])
    require(rebuilt == descriptor, "original chunk commitment")
    require(coding_for(body, encode(body)) == coding, "noncanonical parity commitment")
    return body


def manifest_id(chain, genesis, manifest):
    return h(b"lean/1/broadcast\0" + rlp([chain, genesis, manifest]))


def channel(chain, genesis, manifest):
    descriptor = manifest[6]
    scope = [chain, genesis, manifest[0], descriptor[0], descriptor[1]]
    return "lean/1/rs/" + h(b"lean/1/channel\0" + rlp(scope)).hex()


def preamble(manifest, signature=b"", authorization=b""):
    # Encoding bounds only; an empty or arbitrary signature is NOT authenticated.
    geometry(manifest)
    encoded = rlp([manifest, signature, authorization])
    require(len(encoded) <= 65536, "preamble length")
    return encoded


def shard_id(index):
    require(type(index) is int and 0 <= index < TOTAL, "shard index")
    return b"" if index == 0 else bytes([0x08, index])


def parse_shard_id(encoded):
    if encoded == b"":
        return 0
    require(len(encoded) == 2 and encoded[0] == 8 and 1 <= encoded[1] < TOTAL,
            "noncanonical shard ID")
    return encoded[1]


def bitmap(indices):
    bits = 0
    for index in indices:
        shard_id(index)
        bits |= 1 << index
    return bits.to_bytes(4, "little")


def parse_bitmap(encoded):
    require(len(encoded) == 4, "bitmap length")
    bits = int.from_bytes(encoded, "little")
    return [index for index in range(TOTAL) if bits & (1 << index)]


BODY, GENESIS = b"12345678901234567", b"\x55" * 32


def fixture(body=BODY):
    shards = encode(body)
    descriptor, _, _ = commit(body, kind=3, profile=b"\x22" * 32, context=[h(body)])
    manifest = [b"\x11" * 32, b"\x33" * 4, 42, 3, 9, b"\x44" * 32,
                descriptor, b"", coding_for(body, shards)]
    return manifest, shards


class BroadcastChecks(unittest.TestCase):
    def test_fixed_vectors(self):
        manifest, shards = fixture()
        self.assertEqual(GENERATOR[:DATA], [[int(i == j) for j in range(DATA)]
                                           for i in range(DATA)])
        # Generator coefficients were cross-checked by Lagrange interpolation.
        self.assertEqual(b"".join(shards).hex(),
                         "3132333435363738393031323334353637000000000000000000000000000000"
                         "4bd4aac40d61cd1a263e9124244a226b2c9a469b7059d630312ef292f501538d")
        self.assertEqual(sha256(BODY).hexdigest(),
                         "97f40b8ae3e4d3118bb4afb623d3e768f04d9bc2f913bd64296ebcd53386c1ac")
        self.assertEqual(manifest_id(1, GENESIS, manifest).hex(),
                         "e6f86470166cc46f3acdc1d0efd7f1b594e2209b0c917fb1becc4058be46fdab")
        self.assertEqual(channel(1, GENESIS, manifest),
                         "lean/1/rs/6305cd9070a21d6be6be82a0e4ef98f2019641ab7f65de36d6a5de8889781744")

    def test_reconstruction_with_data_loss(self):
        for body in (b"x", bytes(range(16)), BODY, bytes(range(127)), bytes(range(251)) * 3):
            manifest, shards = fixture(body)
            for indices in (range(16), range(16, 32), range(0, 32, 2), range(31, 15, -1)):
                self.assertEqual(recover(manifest, [(i, shards[i]) for i in indices]), body)

    def test_geometry_before_decoder_initialization(self):
        manifest, shards = fixture()
        invalid = []
        for length in (0, -1, MAX_BODY + 1, 2**64):
            candidate = deepcopy(manifest)
            candidate[6][3] = length
            invalid.append(candidate)
        for field, value in ((0, 15), (1, 17), (2, 0), (2, 65537), (4, [])):
            candidate = deepcopy(manifest)
            candidate[8][field] = value
            invalid.append(candidate)
        with patch(__name__ + ".invert", side_effect=AssertionError("decoder initialized")):
            for candidate in invalid:
                with self.assertRaises(ValueError):
                    recover(candidate, list(enumerate(shards[:16])))
        largest = deepcopy(manifest)
        largest[6][3], largest[8][2] = MAX_BODY, 65536
        self.assertEqual(geometry(largest), (MAX_BODY, 65536))
        with self.assertRaisesRegex(ValueError, "preamble length"):
            preamble(manifest, authorization=bytes(65536))

    def test_padding_and_commitment_failures(self):
        manifest, shards = fixture()
        received = list(enumerate(shards[:16]))
        for field in (3, 4):
            altered = deepcopy(manifest)
            if field == 3:
                altered[8][3] = bytes(32)
            else:
                altered[8][4][0] = bytes(32)
            with self.assertRaises(ValueError):
                recover(altered, received)
        for field in (4, 5):
            altered = deepcopy(manifest)
            altered[6][field] = bytes(32)
            with self.assertRaises(ValueError):
                recover(altered, received)
        altered = deepcopy(manifest)
        altered[8][4][31] = bytes(32)
        with self.assertRaisesRegex(ValueError, "parity commitment"):
            recover(altered, received)
        # Authenticate a modified padding shard: padding must fail independently
        # of its shard hash and the hash of the truncated original body.
        altered = deepcopy(manifest)
        bad = shards[15][:-1] + b"\x01"
        altered[8][4][15] = sha256(bad).digest()
        with self.assertRaisesRegex(ValueError, "padding"):
            recover(altered, received[:-1] + [(15, bad)])
        with self.assertRaises(ValueError):
            recover(manifest, received[:-1] + [received[0]])

    def test_manifest_domain_binding(self):
        manifest, _ = fixture()
        original = manifest_id(1, GENESIS, manifest)
        for field in range(9):
            altered = deepcopy(manifest)
            value = altered[field]
            altered[field] = value + 1 if isinstance(value, int) else [value]
            self.assertNotEqual(manifest_id(1, GENESIS, altered), original)
        self.assertNotEqual(manifest_id(2, GENESIS, manifest), original)
        self.assertNotEqual(manifest_id(1, bytes(32), manifest), original)
        self.assertNotEqual(h(rlp([1, GENESIS, manifest])), original)
        self.assertLessEqual(len(preamble(manifest)), 65536)

    def test_shard_ids_and_bitmaps(self):
        self.assertEqual(shard_id(0), b"")
        self.assertEqual(shard_id(1).hex(), "0801")
        self.assertEqual(shard_id(31).hex(), "081f")
        for index in range(TOTAL):
            self.assertEqual(parse_shard_id(shard_id(index)), index)
        for encoded in (b"\x08\x00", b"\x08\x20", b"\x08\x81\x00",
                        b"\x08\x01\x08\x01", b"\x10\x01", b"\x08"):
            with self.assertRaises(ValueError):
                parse_shard_id(encoded)
        self.assertEqual(bitmap([0, 7, 8, 31]).hex(), "81010080")
        self.assertEqual(parse_bitmap(bytes.fromhex("81010080")), [0, 7, 8, 31])
        for size in (0, 3, 5):
            with self.assertRaises(ValueError):
                parse_bitmap(bytes(size))


if __name__ == "__main__":
    unittest.main()
