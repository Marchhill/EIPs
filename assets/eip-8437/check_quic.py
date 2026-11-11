#!/usr/bin/env python3
"""Check the experimental QUIC binding, not QUIC/TLS or proof validity.

Run with Python 3.9+ and pycryptodome:
    python3 assets/eip-8437/check_quic.py

Message semantics beyond the stream role and request ID are covered by the
base vectors. This small incremental framing model is not a production parser.
"""

import unittest

from check_vectors import MAX_WRAPPER_BYTES, rlp, uint

MAX_FRAME_BYTES = 10 * 1024 * 1024
RESPONSES = {0x09: 0x0a, 0x17: 0x18}


class Invalid(ValueError):
    pass


class Incomplete(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def decode(payload):
    def item(pos, end, depth=0):
        require(pos < end and depth < 32, "truncated or deeply nested RLP")
        tag = payload[pos]
        pos += 1
        if tag < 0x80:
            return bytes([tag]), pos
        is_list = tag >= 0xc0
        size = tag - (0xc0 if is_list else 0x80)
        if size > 55:
            width = size - 55
            require(pos + width <= end and payload[pos] != 0, "RLP length")
            size = int.from_bytes(payload[pos:pos + width], "big")
            require(size >= 56, "nonminimal RLP length")
            pos += width
        limit = pos + size
        require(limit <= end, "truncated RLP value")
        if not is_list:
            require(size != 1 or payload[pos] >= 0x80, "nonminimal RLP string")
            return payload[pos:limit], limit
        values = []
        while pos < limit:
            value, pos = item(pos, limit, depth + 1)
            values.append(value)
        return values, pos

    value, end = item(0, len(payload))
    require(end == len(payload) and isinstance(value, list), "message RLP")
    return value


def number(value):
    require(isinstance(value, bytes) and len(value) <= 8
            and (not value or value[0] != 0), "integer encoding")
    return int.from_bytes(value, "big")


def frame(message_id, value):
    payload = rlp(value)
    return bytes([message_id]) + uint(len(payload), 4) + payload


class Stream:
    def __init__(self, role, request=None):
        self.role, self.request = role, request
        self.buffer = bytearray()
        self.want, self.header = 5, True
        self.message_id = None
        self.messages = []
        self.finished = False
        self.payload_bytes_read = 0

    def feed(self, data):
        cursor = 0
        while cursor < len(data):
            require(not self.finished and (self.role == "control" or not self.messages),
                    "bytes after request or response")
            count = min(self.want - len(self.buffer), len(data) - cursor)
            self.buffer.extend(data[cursor:cursor + count])
            cursor += count
            if not self.header:
                self.payload_bytes_read += count
            if len(self.buffer) != self.want:
                continue
            value = bytes(self.buffer)
            self.buffer.clear()
            if self.header:
                self.message_id = value[0]
                allowed = {0x00} if not self.messages else {0x16}
                if self.role == "request":
                    allowed = set(RESPONSES)
                elif self.role == "response":
                    allowed = {RESPONSES[self.request[0]]}
                require(self.message_id in allowed, "message stream role")
                self.want = int.from_bytes(value[1:], "big")
                require(1 <= self.want <= MAX_FRAME_BYTES, "frame size")
                self.header = False
            else:
                fields = decode(value)
                if self.message_id == 0x00:
                    require(len(fields) == 7 and number(fields[0]) == 73, "Status shape")
                elif self.role != "control":
                    require(len(fields) == 2 and isinstance(fields[1], list), "message shape")
                    request_id = number(fields[0])
                    if self.role == "response":
                        require(request_id == self.request[1], "response request ID")
                self.messages.append((self.message_id, fields))
                self.header, self.want = True, 5

    def fin(self):
        require(self.role != "control", "control closure terminates binding")
        if not self.messages or self.buffer or not self.header:
            raise Incomplete("FIN before complete frame")
        self.finished = True

    def reset(self):
        raise Incomplete("reset is not a complete response")


STATUS = frame(0x00, [73, 1, bytes(32), [bytes(4), 0], 0, 1, bytes(32)])
ANNOUNCEMENT = frame(0x16, [[123, bytes(32)]])


class FramingChecks(unittest.TestCase):
    def test_fixed_encodings(self):
        self.assertEqual(frame(0x17, [7, [bytes(32)]]).hex(),
                         "1700000024e307e1a0" + "00" * 32)
        self.assertEqual(frame(0x18, [7, []]).hex(), "1800000003c207c0")

    def test_fragmentation(self):
        cases = [("control", None, STATUS + ANNOUNCEMENT),
                 ("request", None, frame(0x17, [7, [bytes(32)]])),
                 ("response", (0x17, 7), frame(0x18, [7, []])),
                 ("request", None, frame(0x09, [0, [bytes(32)]])),
                 ("response", (0x09, 0), frame(0x0a, [0, []]))]
        for role, request, wire in cases:
            for split in range(len(wire) + 1):
                stream = Stream(role, request)
                stream.feed(wire[:split])
                stream.feed(wire[split:])
                self.assertTrue(stream.messages)
                if role != "control":
                    self.assertFalse(stream.finished)
                    stream.fin()
                    self.assertTrue(stream.finished)

    def test_role_and_type_rejection_before_payload(self):
        for role, request, message_id in [("control", None, 0x16),
                                          ("control", None, 0xff),
                                          ("request", None, 0x18),
                                          ("response", (0x17, 7), 0x0a)]:
            stream = Stream(role, request)
            with self.assertRaises(Invalid):
                stream.feed(bytes([message_id]) + uint(1, 4) + b"x")
            self.assertEqual(stream.payload_bytes_read, 0)

    def test_size_boundaries_before_payload(self):
        for size in (0, MAX_FRAME_BYTES + 1):
            stream = Stream("response", (0x17, 7))
            with self.assertRaises(Invalid):
                stream.feed(b"\x18" + uint(size, 4) + b"unread")
            self.assertEqual(stream.payload_bytes_read, 0)
        stream = Stream("response", (0x17, 7))
        stream.feed(b"\x18" + uint(MAX_FRAME_BYTES, 4))
        self.assertEqual(stream.want, MAX_FRAME_BYTES)
        self.assertEqual(stream.buffer, b"")

    def test_maximum_wrapper_and_message_overhead(self):
        # A structurally encoded wrapper at the byte ceiling; no proof validity claim.
        wrapper = [[bytes(32)], 1, [[bytes(96)], b"x" * (MAX_WRAPPER_BYTES - 147)]]
        self.assertEqual(len(rlp(wrapper)), MAX_WRAPPER_BYTES)
        wire = frame(0x18, [2**64 - 1, [wrapper]])
        self.assertEqual(len(wire), MAX_WRAPPER_BYTES + 17 + 5)
        stream = Stream("response", (0x17, 2**64 - 1))
        for offset in range(0, len(wire), 65536):
            stream.feed(wire[offset:offset + 65536])
        stream.fin()

    def test_wrong_id_and_noncanonical_rlp(self):
        for payload in (rlp([6, []]), rlp([b"\x00", []]), b"\xf8\x02\x07\xc0",
                        rlp([7, []]) + b"\x80", rlp([7, [], []])):
            with self.assertRaises(Invalid):
                Stream("response", (0x17, 7)).feed(b"\x18" + uint(len(payload), 4) + payload)

    def test_incomplete_and_extra_responses(self):
        wire = frame(0x18, [7, []])
        for end in range(len(wire)):
            stream = Stream("response", (0x17, 7))
            stream.feed(wire[:end])
            with self.assertRaises(Incomplete):
                stream.fin()
        for suffix in (b"\x00", wire):
            with self.assertRaises(Invalid):
                Stream("response", (0x17, 7)).feed(wire + suffix)
        stream = Stream("response", (0x17, 7))
        stream.feed(wire)
        with self.assertRaises(Incomplete):
            stream.reset()

    def test_status_and_control_lifetime(self):
        for wire in (STATUS + STATUS, frame(0, [73]),
                     frame(0, [72, 1, bytes(32), [bytes(4), 0], 0, 1, bytes(32)])):
            with self.assertRaises(Invalid):
                Stream("control").feed(wire)
        stream = Stream("control")
        stream.feed(STATUS + ANNOUNCEMENT)
        with self.assertRaises(Invalid):
            stream.fin()

    def test_independent_response_completion(self):
        requests = (0, 99, 2)
        streams = {i: Stream("response", (0x17, i)) for i in requests}
        streams[0].feed(frame(0x18, [0, []])[:3])
        for i in (2, 99):
            streams[i].feed(frame(0x18, [i, []]))
            streams[i].fin()
        self.assertFalse(streams[0].finished)
        streams[0].feed(frame(0x18, [0, []])[3:])
        streams[0].fin()


if __name__ == "__main__":
    unittest.main()
