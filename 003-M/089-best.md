Steep Teal Osprey

high

# Malicious frontrunner can censor any proposal from being executed due to tx hash collisions

## Summary

A malicious frontrunner can prevent any proposal from being executed through a somewhat complicated attack, that is a result of collisions in the tx hash due to how it is calculated. 

## Vulnerability Detail

First, let's say that there's a proposal that the frontrunner doesn't want to be executed. The frontrunner first makes the exact same proposal (i.e. signature, data, etc). 

The frontrunner requires that both their proposal and the other proposal they don't want to be executed pass. With this assumption, the frontrunner can do the following:

1. Wait for the other party to queue up their proposal
2. Frontrun this with the following actions:
3. Malicious attacker queues up their own proposal which has passed. This will add the txHash, which is calculated as follows, `keccak256(abi.encode(target, value, signature, data, eta))` to `queuedTransactions` and will also add the right `eta` to the proposal. 
4. Malicious attacker cancels their own proposal so it is removed from queuedTransactions, but the eta on the proposal is still there. 
5. Now the malicious attacker allows the other party's proposal to be queued up, and note that it has the same eta. 
6. Malicious attacker calls cancel again (because the code allows re-cancelling an already cancelled txHash), but this time it cancels the other party's proposal due to the tx hash collision. 

The other party now cannot ever requeue their proposal since it is forever in the Queue (and eventually Expired) state, so the proposal has effectively been cancelled. 

Another case where this tx hash collision could cause problems is if the same transaction (target, value, signature, data all same) was queued up in the past, but then cancelled. Later on, the timelock delay was changed so the `eta` of the two end up coinciding. In this case, the proposer of the original cancelled transaction can call cancel again and cancel the new proposal after it is queued up (and it will be put in a state where it can never be queued up again).  

## Impact

Malicious frontrunner can censor any proposal, with some assumptions

## Code Snippet

https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L284

## Tool used

Manual Review

## Recommendation
Add proposal ID to the tx hash calculation