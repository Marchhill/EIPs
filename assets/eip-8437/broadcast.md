# Block-proof broadcast design note

## Motivation

EIP-8288's block proof may be large enough for erasure-coded broadcast to reduce propagation latency: a relay can forward authenticated shards before receiving the whole proof, and receivers can reconstruct from several peers. The proof already travels in the block body, so a second delivery path is useful only if it improves block validation without routinely transferring the proof twice.

This note records an experiment to evaluate with ethp2p's [broadcast framework](https://github.com/ethp2p/ethp2p/blob/78452f02c9724d7b7fb05a5847d6321381e4e172/specs/002-ec-broadcast.md) and [Reed-Solomon strategy](https://github.com/ethp2p/ethp2p/blob/78452f02c9724d7b7fb05a5847d6321381e4e172/specs/003-ec-broadcast-rs.md). It defines no wire extension or activation requirement for EIP-8437.

## Scope

- Compare broadcasting the complete execution payload, including its proof, with separate proof delivery. Prefer the complete payload path unless separating the proof produces a measured benefit.
- A separate path needs a block-acquisition plan that avoids duplicate proof bytes in successful operation, reconstructs the ordinary block body and preserves its availability. Failure recovery can still require duplicate transfers.
- Use this path for a proof bound to an authenticated block proposal. Peer identity alone does not authorize early forwarding of arbitrary mempool-wrapper shards.

## Authentication and validation

- Define how the consensus layer authenticates the proposer or selected builder for the target block and exposes that authorization to the receiver. Builder registration alone does not establish a proposal duty.
- Authenticate the chain, fork, slot, block identity, proof commitment and coding commitment before forwarding shards. Specify replay and conflicting-manifest handling per authorized proposal, across connections and transports.
- Verify each shard against the authenticated coding commitment before forwarding it. A producer's signature authenticates the source; it does not establish a valid codeword or proof.
- On reconstruction, check codeword consistency and the proof's header commitment. Full EIP-8288 validation still requires the dependencies derived from the block's transactions; early delivery does not establish block validity.
- Attribute corrupt shards to their sender and inconsistent committed coding to the producer. A failed broadcast should not suppress independent block retrieval or penalize relays that forwarded correctly authenticated shards.

## Measurements and decision

Compare the existing payload path, erasure-coded whole-payload delivery and separate proof broadcast under the same topology, bandwidth and loss conditions. Measure:

- Time until the complete block is available and validated, including transaction recovery and proof verification.
- Total bytes and peak memory per node, including coding redundancy, duplicate delivery and fallback.
- Tail latency under withholding, producer equivocation, invalid proofs, churn and competing traffic.
- Performance on nodes near the supported hardware and bandwidth minimums.

Retain a separate proof-broadcast protocol only if these measurements justify its additional authorization, acquisition and recovery machinery. Otherwise carry the proof through the common payload-broadcast path. Coding parameters, manifests and stream assignments should then be specified with that transport rather than independently in the wrapper EIP.

## Why not broadcast mempool wrappers this way?

Mempool wrappers have no consensus-assigned producer duty. Allowing any peer to trigger early shard forwarding would amplify invalid-proof traffic before EIP-8288 validation. Requiring a fully validated wrapper before forwarding preserves the existing defense but gives up the principal latency advantage of early relay. A permissionless admission or anti-abuse mechanism would need a separate justification.

## Test requirements

Any concrete binding needs cross-client tests for producer authorization, replay and conflicts; invalid shard commitments and inconsistent codewords; proof/header mismatches; and fallback without lost body availability. Coding tests alone cannot establish those properties.
