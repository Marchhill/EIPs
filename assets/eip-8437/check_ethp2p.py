#!/usr/bin/env python3
"""EIP-8437 ethp2p framing checks; not a production stream parser.

Run with Python 3.9+ and pycryptodome:
    python3 assets/eip-8437/check_ethp2p.py

Checks framing, canonical RLP and selected message structure. Does not test
QUIC/TLS, discovery, timers, peer budgets, request credit, or object/proof validity.
"""

import unittest

from check_vectors import rlp, uint


MAX_MESSAGE_BYTES = 131072
MAX_RLP_DEPTH = 8
CEILINGS = {3: 65536, 9: 65536}
FIELDS = {0: 6, 2: 2, 3: 2, 4: 3, 5: 5, 6: 3, 7: 1, 8: 2, 9: 2}
RESPONSES = {2: {3}, 4: {5, 6}, 8: {9}}


class Invalid(ValueError):
    """Protocol violation in the framing checks covered here."""


class Incomplete(ValueError):
    """FIN before a complete response; not successful delivery."""


def require(condition, message):
    if not condition:
        raise Invalid(message)


def decode(payload):
    """Bounded canonical RLP; list depth counts the outer list as one."""
    def item(pos, end, depth):
        require(pos < end, "truncated RLP")
        tag = payload[pos]
        pos += 1
        if tag < 0x80:
            return bytes([tag]), pos
        is_list = tag >= 0xc0
        base = 0xc0 if is_list else 0x80
        size = tag - base
        if size > 55:
            width = size - 55
            require(pos + width <= end, "truncated RLP length")
            require(payload[pos] != 0, "leading zero in RLP length")
            size = int.from_bytes(payload[pos:pos + width], "big")
            require(size >= 56, "nonminimal RLP length")
            pos += width
        limit = pos + size
        require(limit <= end, "truncated RLP value")
        if not is_list:
            require(size != 1 or payload[pos] >= 0x80, "nonminimal RLP string")
            return payload[pos:limit], limit
        require(depth < MAX_RLP_DEPTH, "RLP depth")
        values = []
        while pos < limit:
            # Every decoded transport list has at most 64 members. Envelopes
            # and proofs are byte strings and are deliberately not decoded.
            require(len(values) < 64, "RLP list count")
            value, pos = item(pos, limit, depth + 1)
            values.append(value)
        return values, pos

    value, end = item(0, len(payload), 0)
    require(end == len(payload), "trailing RLP bytes")
    require(isinstance(value, list), "message must be an RLP list")
    return value


def number(value, width=8):
    require(isinstance(value, bytes), "integer must be a byte string")
    require(len(value) <= width and (not value or value[0] != 0), "integer encoding")
    return int.from_bytes(value, "big")


def frame(message_id, value):
    payload = rlp(value)
    return bytes([message_id]) + uint(len(payload), 4) + payload


class Stream:
    """Incremental framing model; payload work starts only after header checks."""

    def __init__(self, request_type=4, highest=7, live=None):
        self.request_type = request_type
        self.highest = highest
        self.live = {7} if live is None else live
        self.stage, self.want = "role", 1
        self.buffer = bytearray()
        self.role = self.request_id = self.message_id = None
        self.status_seen = self.terminal = self.retired = False
        self.messages = []
        self.payload_bytes_read = 0

    def feed(self, data):
        cursor = 0
        while cursor < len(data):
            if self.stage == "discard":
                return  # Retired prefix: no framing, RLP or payload work.
            require(not self.terminal, "bytes after terminal response")
            count = min(self.want - len(self.buffer), len(data) - cursor)
            self.buffer.extend(data[cursor:cursor + count])
            cursor += count
            if self.stage == "payload":
                self.payload_bytes_read += count
            if len(self.buffer) == self.want:
                value = bytes(self.buffer)
                self.buffer.clear()
                self.consume(value)

    def consume(self, value):
        if self.stage == "role":
            self.role = value[0]
            require(self.role in (0, 1), "stream type")
            self.stage, self.want = ("request", 8) if self.role else ("header", 5)
        elif self.stage == "request":
            self.request_id = int.from_bytes(value, "big")
            require(0 < self.request_id <= self.highest, "response request ID")
            self.stage = "header" if self.request_id in self.live else "discard"
            self.want = 5
        elif self.stage == "header":
            self.message_id = value[0]
            require(self.message_id < 10, "message ID")
            allowed = ({0} if not self.status_seen else {1, 2, 4, 7, 8})
            if self.role == 1:
                allowed = RESPONSES[self.request_type]
            require(self.message_id in allowed, "message stream role or response type")
            size = int.from_bytes(value[1:], "big")
            require(1 <= size <= CEILINGS.get(self.message_id, MAX_MESSAGE_BYTES),
                    "payload length")
            self.stage, self.want = "payload", size
        else:
            fields = decode(value)
            if self.message_id in FIELDS:
                require(len(fields) == FIELDS[self.message_id], "field count")
            if self.message_id in (2, 3, 4, 5, 6, 7, 8, 9):
                request_id = number(fields[0])
                if self.role == 1:
                    require(request_id == self.request_id, "frame/prefix ID mismatch")
            if self.message_id == 0:
                require(number(fields[0]) == 1, "Status version")
                self.status_seen = True
            if self.message_id in (3, 9):
                require(isinstance(fields[1], list) and len(fields[1]) <= 16,
                        "response result list")
            if self.message_id in (5, 6):
                require(isinstance(fields[1], bytes) and len(fields[1]) == 32,
                        "object ID shape")
                number(fields[2], 4 if self.message_id == 5 else 1)
            self.messages.append((self.message_id, fields))
            self.terminal = self.role == 1 and self.message_id in (3, 6, 9)
            self.stage, self.want = "header", 5

    def fin(self):
        if self.stage == "discard":
            return
        require(self.role != 0, "control stream closed")
        if not self.terminal or self.buffer:
            raise Incomplete("FIN before complete terminal response")
        self.retired = True


STATUS = frame(0, [1, 1, bytes(32), [bytes(32)], 1, MAX_MESSAGE_BYTES])
CONTROL = b"\x00" + STATUS
PREFIX = b"\x01" + uint(7, 8)
COMPLETE = frame(6, [7, bytes(32), 1])  # Unavailable: zero chunks is allowed.


class FramingChecks(unittest.TestCase):
    def test_fixed_encodings(self):
        self.assertEqual(frame(7, [7]).hex(), "0700000002c107")
        self.assertEqual(CONTROL[:1].hex(), "00")
        self.assertEqual(PREFIX.hex(), "010000000000000007")

    def test_fragmentation(self):
        cases = ((CONTROL + frame(7, [7]), 0), (PREFIX + COMPLETE, 1),
                 (PREFIX + frame(3, [7, [[2, b"", b""]]]), 1),
                 (PREFIX + frame(9, [7, [[2, b""]]]), 1))
        for wire, role in cases:
            request_type = {3: 2, 9: 8}.get(wire[9] if role else 0, 4)
            for split in range(len(wire) + 1):
                stream = Stream(request_type)
                stream.feed(wire[:split])
                stream.feed(wire[split:])
                self.assertEqual(stream.role, role)
                if role:
                    self.assertFalse(stream.retired)
                    stream.fin()
                    self.assertTrue(stream.retired)
            stream = Stream(request_type)
            for byte in wire:
                stream.feed(bytes([byte]))
            self.assertEqual(stream.messages[-1][0], wire[9] if role else 7)

    def test_header_rejection_before_payload(self):
        cases = [(CONTROL, 10, 1, 4), (CONTROL, 5, 1, 4),
                 (PREFIX, 7, 1, 4), (PREFIX, 3, 1, 4),
                 (CONTROL, 7, 0, 4), (CONTROL, 7, MAX_MESSAGE_BYTES + 1, 4),
                 (PREFIX, 3, 65537, 2), (PREFIX, 9, 65537, 8)]
        for prefix, message_id, size, request_type in cases:
            stream = Stream(request_type)
            stream.feed(prefix)
            already_read = stream.payload_bytes_read
            with self.assertRaises(Invalid):
                stream.feed(bytes([message_id]) + uint(size, 4) + b"unread payload")
            self.assertEqual(stream.payload_bytes_read, already_read)
        for bad_prefix in (b"\x02", b"\x01" + bytes(8), b"\x01" + uint(8, 8)):
            with self.assertRaises(Invalid):
                Stream().feed(bad_prefix)

    def test_exact_payload_ceilings(self):
        # Stop at the header: its declared length is not a request to allocate
        # or a claim that a payload of that size is a valid message.
        for message_id, request_type, limit in ((5, 4, MAX_MESSAGE_BYTES),
                                                (3, 2, 65536), (9, 8, 65536)):
            stream = Stream(request_type)
            stream.feed(PREFIX + bytes([message_id]) + uint(limit, 4))
            self.assertEqual(stream.want, limit)
            self.assertEqual(stream.buffer, b"")
            self.assertEqual(stream.payload_bytes_read, 0)

    def test_rlp_rejections(self):
        malformed = (b"\xc1\x81", b"\xf8\x01\x07", b"\xf9\x00\x01\x07",
                     b"\xc2\x81\x07", b"\xc1\x07\x00", b"\x07",
                     rlp([]), rlp([7, 8]), rlp([b"\x00"]), rlp([b"\x00\x07"]),
                     rlp([[]]), rlp([2**64]), rlp([7] * 65))
        for payload in malformed:
            with self.assertRaises(Invalid):
                Stream().feed(CONTROL + b"\x07" + uint(len(payload), 4) + payload)
        nested = []
        for _ in range(MAX_RLP_DEPTH - 1):
            nested = [nested]
        self.assertEqual(decode(rlp(nested)), nested)
        with self.assertRaises(Invalid):
            decode(rlp([nested]))

    def test_truncation_and_terminal(self):
        wire = PREFIX + COMPLETE
        for end in range(len(wire)):
            stream = Stream()
            stream.feed(wire[:end])
            with self.assertRaises(Incomplete):
                stream.fin()
            self.assertFalse(stream.retired)
        for suffix in (b"\x00", COMPLETE):
            with self.assertRaises(Invalid):
                Stream().feed(wire + suffix)
        stream = Stream()
        stream.feed(CONTROL)
        with self.assertRaises(Invalid):
            stream.fin()

    def test_roles_ids_and_retired_prefix(self):
        for wire in (b"\x00" + frame(7, [7]), CONTROL + STATUS,
                     PREFIX + frame(6, [6, bytes(32), 1])):
            with self.assertRaises(Invalid):
                Stream().feed(wire)
        stream = Stream(live=set())
        stream.feed(PREFIX + b"not parsed as a frame or RLP")
        self.assertEqual(stream.stage, "discard")
        self.assertEqual(stream.payload_bytes_read, 0)
        self.assertEqual(stream.messages, [])

    def test_chunk_then_terminal(self):
        chunk = frame(5, [7, bytes(32), 0, b"opaque chunk", []])
        stream = Stream()
        for byte in PREFIX + chunk + COMPLETE:
            stream.feed(bytes([byte]))
        self.assertEqual([item[0] for item in stream.messages], [5, 6])
        self.assertFalse(stream.retired)
        stream.fin()
        self.assertTrue(stream.retired)
        incomplete = Stream()
        incomplete.feed(PREFIX + chunk)
        with self.assertRaises(Incomplete):
            incomplete.fin()
        self.assertEqual(len(incomplete.messages), 1)


if __name__ == "__main__":
    unittest.main()
