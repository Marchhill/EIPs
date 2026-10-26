# Experimental QUIC retrieval

## Motivation

Large responses on a TCP connection can delay unrelated requests. QUIC gives each request an independent stream while preserving EIP-8437's announcement, retrieval and validation rules. This experiment covers proof wrappers and their transaction envelopes; block synchronization and blob-cell retrieval require their existing transports.

The [ethp2p transport](https://github.com/ethp2p/ethp2p/blob/78452f02c9724d7b7fb05a5847d6321381e4e172/specs/001-ethp2p.md#transport) is still being designed. The isolated binding below permits testing without assigning ethp2p protocol selectors or assuming compatibility with its evolving wire format. Production integration should use the common ethp2p transport once specified.

## Specification

The key words MUST, MUST NOT, SHOULD and MAY are interpreted as in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174). They apply only to this experimental binding.

### Connection

- Use QUIC v1 with TLS 1.3 and the experimental ALPN `eth-proof/1`.
- Advertise `ethproof = 1` in a signed EIP-778 v4 ENR, with nonzero UDP ports in `quic` for `ip` and `quic6` for `ip6`.
- Authenticate both peers using [libp2p TLS peer authentication](https://github.com/libp2p/specs/blob/f201689524a23af835119834d7db75bbc71c3549/tls/tls.md#peer-authentication). The authenticated secp256k1 identity from the certificate extension MUST match the dialed ENR key and identify the same node across its transports.
- Application data MUST NOT be sent or processed before TLS authentication completes; 0-RTT application data is prohibited.

### Messages

Use the `eth/73` encodings, message IDs and validation rules from [EIP-8437](../../EIPS/eip-8437.md), including its envelope-serving obligation. Wrapper identity is unchanged across transports.

| Stream | Initiator sends | Receiver sends |
| --- | --- | --- |
| First unidirectional stream from each peer | Status (`0x00`), then NewProofWrapperHashes (`0x16`) | — |
| Bidirectional wrapper request | GetProofWrappers (`0x17`) | ProofWrappers (`0x18`) |
| Bidirectional envelope request | GetPooledTransactions (`0x09`) | PooledTransactions (`0x0a`) |

- Each peer MUST open exactly one unidirectional control stream, identified by QUIC stream index zero for that direction. Its first message is the unchanged `eth/73` Status, with version 73 and the usual network, genesis and fork checks. A second Status or another unidirectional stream is invalid.
- Peers MUST send and validate Status before sending other messages. Messages arriving on other streams before the peer's Status is validated MAY be buffered within local limits or refused without penalty; they MUST NOT be processed first.
- Each bidirectional stream carries exactly one request followed by FIN in the initiating direction and one matching response followed by FIN in the other direction. No other message types are permitted.
- The response MUST match the request's type and `request-id`. IDs are scoped to the connection and initiating peer and MUST distinguish outstanding requests; zero, gaps and responses completing out of order are allowed.

### Framing

`message-id: B_1 || length: B_4 || rlp-message: B_length`

- `length` is the RLP payload's byte length, encoded as an unsigned big-endian integer, from 1 to 10 MiB. Message-specific limits also apply; the wrapper response's 2 MiB soft limit permits its first wrapper plus response overhead.
- The payload is the unchanged canonical RLP message, without compression. Wrappers remain embedded RLP items, and pooled transactions retain their existing network encodings.
- Unknown IDs, invalid stream roles, malformed payloads, mismatched responses or bytes after a request or response are protocol violations. The receiver MUST discard the message and SHOULD close the binding.
- A response is complete only after its full frame and FIN. A premature FIN or reset leaves the request incomplete. Cancellation uses QUIC `STOP_SENDING` and `RESET_STREAM` as appropriate, with application error code zero; it asserts no data validity.
- Closing either control stream terminates this binding. Validated wrappers remain usable through other connections.

## Rationale

Bidirectional request streams associate responses without a second stream header, application chunks or completion messages. Keeping the existing message bodies also preserves envelope recovery and deduplication across transports. The 10 MiB frame ceiling follows the practical `eth` message limit; it is not a wrapper-size increase.

Independent streams remove TCP's cross-stream delivery blocking. They still share congestion control and connection flow control, and full wrapper validation still precedes relay. Benefits therefore depend on loss, concurrent traffic, response sizes and verification time.

## Deployment and security

This binding is opt-in for experiments. EIP-8437's standard `eth/73` path remains available to peers that do not implement it. Replacing that path requires a coordinated common transport for wrappers, envelopes and the other `eth` services; this experiment does not establish such a migration.

Clients should share per-node accounting across transports and bound streams, buffered bytes, incomplete messages and verification work. Flow-control credit and scheduling should preserve control progress. Retries and reconnects should not reset local recovery budgets. QUIC stream isolation does not prevent withholding or invalid-proof floods.

Before deployment, measure tail latency and total bandwidth against RLPx under packet loss, competing traffic and adversarial peers, including envelope recovery and proof verification. QUIC/TLS interoperability and identity checks need independent implementations.

## Test cases

[Framing checks](./check_quic.py) cover fragmented reads, stream roles, request/response correlation, FIN handling and size boundaries. The [base vectors](./check_vectors.py) cover announcement and wrapper encodings and pooled-envelope matching. These checks do not establish QUIC/TLS interoperability or proof validity.

Connection tests additionally need wrong ENR identities, invalid certificates, wrong ALPN, prohibited early data, cross-stream arrival before Status, duplicate control streams and cancellation under flow-control pressure.
