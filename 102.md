Savory Rusty Parrot

medium

# Post-proposal vote quorum/threshold checks use a stale total supply value

## Summary

The pessimistic vote casting [approach](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/tree/main/bophades/audit/2024-01_governance#vote-casting) stores its cutoffs based on the total supply during proposal creation, rather than looking up the current value for each check.


## Vulnerability Detail

`gOHM token holders can delegate their voting rights either to themselves or to an address of their choice. Due to the elasticity in the gOHM supply, and unlike the original implementation of Governor Bravo, the Olympus governance system relies on dynamic thresholds based on the total gOHM supply. This mechanism sets specific thresholds for each proposal, based on the current supply at that time, ensuring that the requirements (in absolute gOHM terms) for proposing and executing proposals scale with the token supply.`
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/tree/main/bophades/audit/2024-01_governance#olympus-governor-bravo-implementation

The above means that over time, due to dynamic minting and burning, the total supply will be different at different times, whereas the thresholds/quorums checked against are solely the ones set during proposal creation.


## Impact

DoS of the voting system, preventing proposals from ever passing, under certain circumstances

Consider the case of a bug where there is some sort of runaway death spiral bug or attack in the dymamic burning of gOHM (e.g. opposite of Terra/Luna), and the only fix is to pass a proposal to disable the module(s) causing a problem where everyone is periodically having their tokens [`burn()`-from-ed](https://etherscan.io/token/0x0ab87046fBb341D058F17CBC4c1133F25a20a52f#code#L654). At proposal creation there are sufficient votes to pass the threshold, but after the minimum [3-day](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L25-L31) waiting period, the total supply has been halved, and the original proposer no longer has a sufficient quorum to execute the proposal (or some malicious user decides to cancel it, and there is no user for which `isWhitelisted()` returns true). No proposal can fix the issue, since no proposal will have enough votes to pass, by the time it's time to vote. Finally, once the total supply reaches low wei amounts, the treasury can be stolen by any remaining holders, due to loss of precision:

* `getProposalThresholdVotes()`: min threshold is 1_000, so if supply is <100, don't need any votes to pass anything
* `getQuorumVotes()`: quorum percent is hard-coded to 20_000 (20%), so if supply drops below 5, quorum is zero
* `getHighRiskQuorumVotes()`: high percent is hard-coded to 30_000 (30%), so if supply drops below 4, quorum is zero for high risk


## Code Snippet

The quorum comes from the total supply...
```solidity
// File: src/external/governance/GovernorBravoDelegate.sol : GovernorBravoDelegate.getHighRiskQuorumVotes()   #1

698        function getQuorumVotes() public view returns (uint256) {
699            return (gohm.totalSupply() * quorumPct) / 100_000;
700        }
...
706        function getHighRiskQuorumVotes() public view returns (uint256) {
707            return (gohm.totalSupply() * highRiskQuorum) / 100_000;
708:       }
```
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L696-L708

...and is set during [`propose()`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L169-L182), and checked as-is against the eventual vote:
```solidity
// File: src/external/governance/GovernorBravoDelegate.sol : GovernorBravoDelegate.getVoteOutcome()   #2

804            } else if (
805                (proposal.forVotes * 100_000) / (proposal.forVotes + proposal.againstVotes) <
806 @>             approvalThresholdPct ||
807 @>             proposal.forVotes < proposal.quorumVotes
808            ) {
809                return false;
810:           }
```
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L804-L810

## Tool used

Manual Review


## Recommendation

Always calculate the quorum and thresholds based on the current `gohm.totalSupply()` as is done in the OZ [implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/a5c4cd8182103aa96c2147433bf1bfb8fde63ca9/contracts/governance/extensions/GovernorVotesQuorumFraction.sol#L69-L74), and consider making votes based on the fraction of total supply held, rather than a raw amount, since vote tallies are affected too

