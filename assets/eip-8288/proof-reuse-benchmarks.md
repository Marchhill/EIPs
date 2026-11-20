# Proof-reuse benchmarks

Compare fresh aggregation with proof reuse on the same transaction workload, peer graph and network conditions. These are measurements, not additional validity rules.

Use identical and partially overlapping mempool views, transaction arrivals and evictions, different transaction sets sharing dependencies, and unavailable or invalid reuse offers. Vary the number of aggregators and transaction-hash prefix length; report bucket subdivision policy and wrapper/circuit bounds. Each node runs its own aggregation timer without coordinated phases.

Use the current EIP-8437 announcement, retrieval and suppression rules as the transport baseline. Account for announcements, manifests when supported, requests, transactions and proofs against link capacity; distinguish metadata known before a fetch from coverage learned after validation. Compare proposed coordination or richer metadata against this baseline, not only against full-proof flooding.

Include relay-only nodes, uneven proving capacity, overlapping and multi-claim dependencies, withholding aggregators, identity churn and partition changes. Model how participants discover and select each other rather than assuming a globally known honest membership. Compare multiple merge-tree depths, with builder and client work sharing the stated CPU and memory resources.

Report:

- **Proofs produced per transaction network-wide:** total completed recursive proofs across all participating aggregators, including intermediate and discarded results, divided by distinct valid transactions introduced during the measured run. Relaying or verifying a proof does not count as producing one; input witnesses and user-produced proofs are excluded.
- Total proving time, including abandoned work; native and recursive verification work; exact-set reuse and partial-coverage merge rates.
- Bytes transferred and transaction propagation latency, including fetches that fail or return invalid data.
- Coverage of the eligible transaction set by the block deadline, separately from eventual inclusion and inclusion latency. Count inclusion only when the complete block proof finishes in time, including direct inputs, pruning, intermediate merges and finalization.
- Builder makespan, critical-path latency, peak memory, contention with client work and fallback cost when an aggregator withholds its result.
- Workload duration, warm-up and drain periods, transaction count, dependency counts, node hardware, peer topology, aggregator count, network conditions and partition parameters. Run multiple seeds and report their dispersion; distinguish simulation outputs from measured costs.

Use the same observation window and drain policy for both runs. Lower proof counts alone do not establish an improvement if transactions propagate later or less reliably.
