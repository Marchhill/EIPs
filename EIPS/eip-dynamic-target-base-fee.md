---
title: Dynamic target base fee
description: 
author: Marc Harvey-Hill (@Marchhill)
discussions-to: <URL>
status: Draft
type: Standards Track
category: Core
created: 2024-10-15
requires: 7742
---

## Abstract

This EIP proposes to make the target blob count adjust dynamically up to a safe maximum target. This adjustment will target a constant price in ETH for blobs, aiming for consistent costs for L2 transactions.

## Motivation

Ethereum currently uses a target of 50% capacity for blob count, with EIP-1559 smoothing out short term spikes and pushing average throughput towards the target. A dynamic target is orthogonal to EIP-1559, tweaking the target itself over a longer timescale to aim for some desired transaction cost.

Having a static target has a disadvantage the target may be higher than the actual demand, so the protocol undercharges for block or blob space. This decreases the amount of fees burned, negatively affecting the price of ETH and total network security.

As an example consider what would happen if there was a large increase in max blob count due to DAS implementation, but the target remains at 50%. It is unlikely that demand would immediately jump to anywhere near the target, and so for months or years the protocol would effectively charge nothing for L2 transactions. With a dynamic target, the target blob count would drop until the cost of blobspace for an L2 transaction approximated some affordable constant value. In this way, some fees are still burned by the protocol, but new L2s are not discouraged from using Ethereum blobspace, knowing that the target will increase in response to an increase in demand and blob fees will remain reasonably consisent.

While the max blob count, and max target are hard constraints based on resource utilisation limits, setting the target itself is far more subjective. Rather than core developers tweaking the target, a dynamic target optimising for constant transaction costs is a more credibly neutral option.

## Specification

### Parameters

| Parameter | Value |
| - | - |
| `FORK_TIMESTAMP` | TBD |
| `TARGET_BLOB_COUNT_CHANGE_RATE` | `1` |
| `MAX_TARGET_BLOB_COUNT` | 3 |
| `BLOB_COST_CHANGE_MARGIN` | TBD |
| `TARGET_BLOB_COST` | TBD |

### Dynamic targeting

The target blob count changes each epoch based on the mean blob cost over the previous epoch. If the average cost exceeds the desired amount beyond some margin then the target is increased; likewise if it is below the desired amount by some margin the target will decrease. The target can increase up to some cap that is deemed to be a safe average throughput for the network.

Calculating targets:

```python
meanBlobCost = average(blobCostsForLastEpoch)
blobCostDiff = meanBlobCost - TARGET_BLOB_COST
targetBlobCountDirection = -1 if blobCostDiff < -BLOB_COST_CHANGE_MARGIN else (1 if blobCostDiff > BLOB_COST_CHANGE_MARGIN else 0)
nextEpochBlobCount = min(MAX_TARGET_BLOB_COUNT, previousEpochTargetBlobCount + (targetBlobCountDirection * TARGET_BLOB_COUNT_CHANGE_RATE))
```

## Reference Implementation

todo

## Rationale

### Constant target tx cost

A constant blob cost target can keep L2 transaction costs for end users affordable. Volatility in the price of ETH would affect affordability, but is unlikely to be significant compared to normal fluctuations in gas costs due to spikes in activity. In future the costs could be adjusted in the case of changes in the order of magnitude of ETH price.

An alternative approach would be to track a target transaction cost in fiat, but chosing a specific fiat currency is not credibly neutral, and introducing exchange rate oracles into the protocol could be an attack vector. Yet another alternative could be to have validators vote on the target transaction cost, but they may have conflicts of interest (for example if they are blobspace consumers) so again this is not credibly neutral.

### Target gas limit

The same logic could be applied to the target gas limit, but generally blockspace is in high demand so the target should be set to the maximum safe amount. A dynamic target is unlikely to have a significant effect.

## Backwards Compatibility

todo

## Test Cases

todo

## Security Considerations

todo

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).