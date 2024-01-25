Cheery Bone Tiger

medium

# Strict timing constraints can cause proposals to get stuck due to missed execution windows

## Summary
The GovernorBravoDelegate contract currently lacks a mechanism to handle missed execution windows for proposals. If the execution window is missed (i.e., execute is not called in time after `eta`), the proposal might get stuck in a limbo state, neither executable nor cancellable. To address this issue, it is recommended to introduce a grace period or a mechanism to re-queue proposals under certain conditions.

## Vulnerability Detail
The vulnerability arises from the absence of a grace period or a mechanism to handle proposals that miss their execution window. As per the existing code, if the current timestamp is less than the `eta` of the proposal, the execution will be reverted. This strict timing constraint can lead to situations where proposals cannot be executed even if they are slightly delayed, which is not ideal for decentralized governance.

```solidity
function execute(uint256 proposalId) external payable {
    // Check if the proposal is in Queued state
    if (state(proposalId) != ProposalState.Queued) {
        revert GovernorBravo_Execute_NotQueued();
    }

    Proposal storage proposal = proposals[proposalId];
    // Ensure the proposal is executed only after the time lock delay
    if (block.timestamp < proposal.eta) {
        revert GovernorBravo_Execute_TimelockNotPassed();
    }

    // Execute proposal actions

}
```


## Impact
This vulnerability can result in proposals becoming unexecutable if they are even slightly delayed, leading to inefficiencies in decentralized governance.

## Code Snippet
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L255C5-L278C6

## Tool used
Manual Review

## Recommendation
To address this vulnerability and enhance proposal execution flexibility, it is recommended to introduce a Grace Period after the eta has passed. This would allow proposals to be executed within a reasonable window of time even if they slightly miss their original eta. The length of the grace period should be carefully chosen to strike a balance between flexibility and preventing misuse.

```solidity
function execute(uint256 proposalId) external payable {
    if (state(proposalId) != ProposalState.Queued) {
        revert GovernorBravo_Execute_NotQueued();
    }

    Proposal storage proposal = proposals[proposalId];
    uint256 gracePeriod = 48 hours;  // Example grace period

    // Check if current time is within the grace period after eta
    if (block.timestamp < proposal.eta || block.timestamp > proposal.eta + gracePeriod) {
        revert GovernorBravo_Execute_WindowMissed();
    }

    // Execute proposal actions
    
}
```