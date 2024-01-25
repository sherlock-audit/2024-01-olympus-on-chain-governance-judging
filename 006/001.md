Helpful Denim Salmon

medium

# Insufficient Validation in Proposal Creation

## Summary
Insufficient Validation in Proposal Creation
## Vulnerability Detail
In the propose function, there is a validation step to ensure that the proposer has enough votes and that the lengths of the proposal parameters (targets, values, signatures, calldatas) match. However, there is no validation to ensure that the targets, signatures, and calldatas are not malicious or malformed, which could lead to unintended behavior when executing the proposal.
## Impact
Malicious or incorrect input in the proposal parameters could lead to unintended contract behavior or exploitation, potentially affecting the integrity and security of the governance process.
## Code Snippet
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L127-L133

https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L225-L231
## Tool used

Manual Review

## Recommendation
Implement additional checks in the propose function to validate the format and integrity of the targets, signatures, and calldatas. Consider using a whitelist of permitted target addresses and function selectors to mitigate the risk of executing arbitrary or malicious actions through a proposal.

