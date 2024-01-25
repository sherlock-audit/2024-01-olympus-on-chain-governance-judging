Savory Rusty Parrot

high

# Proposals can be pre-canceled

## Summary

An attacker can cancel a proposal before it has been created


## Vulnerability Detail

The `propose()` function individually sets the fields of the `Proposal` struct when it's constructed. It does this via a `storage` pointer, rather than assigning the full struct from memory. This means the fields that are not set, have whatever value they previously had. The `cancel()` function has no checks on whether the proposal is real, so the `canceled` boolean can be set to false, and that `Proposal` field is never re-initialized in `propose()`


## Impact

All proposal creation can be DOSed indefinitely. An attacker can continuously pre-cancel all of the proposal IDs until the end of time. There is no way for legitimate users to un-cancel proposals, and in order to move to the next proposal ID, they need to create an actual proposal, which is more costly and takes more time and block space than the attacker's task.


## Code Snippet

A storage pointer is used, and `newProposal.canceled` is never set to `false`:
```solidity
// File: src/external/governance/GovernorBravoDelegate.sol : GovernorBravoDelegate.propose()   #1

175 @>            Proposal storage newProposal = proposals[newProposalID];
176               // This should never happen but add a check in case.
177               if (newProposal.id != 0) revert GovernorBravo_Proposal_IdCollision();
178   
179   
180               newProposal.id = newProposalID;
181               newProposal.proposer = msg.sender;
182               newProposal.proposalThreshold = proposalThresholdVotes;
183               newProposal.quorumVotes = quorumVotes;
184               newProposal.targets = targets;
185               newProposal.values = values;
186               newProposal.signatures = signatures;
187               newProposal.calldatas = calldatas;
188               newProposal.startBlock = startBlock;
189               newProposal.endBlock = endBlock;
190   
191   
192:              latestProposalIds[newProposal.proposer] = newProposal.id;
```
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L175-L192

[`cancel()`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L284) doesn't have any validity checks, and [`state()`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L820-L826) will report canceled



## Tool used

Manual Review


## Recommendation

Clear all fields during proposal creation
