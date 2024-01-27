Helpful Denim Salmon

medium

# Centralized Admin Control and Potential for Admin Role Abuse

## Summary
The **Timelock** contract has an **admin** role with extensive capabilities, including queuing, executing, and canceling transactions. This centralization of power in the hands of the admin can potentially lead to abuse or mismanagement.
## Vulnerability Detail
The contract allows the admin to manage critical functionalities. If the admin role is compromised or not governed properly, this could lead to unauthorized changes in the system, including manipulation of the governance process or introduction of malicious transactions.
## Impact
Improper or malicious use of the admin role can result in severe consequences, including unauthorized changes in the system, execution of unintended or harmful transactions, or other security breaches.
## Code Snippet
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/Timelock.sol#L108

https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/Timelock.sol#L125

https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/Timelock.sol#L140
## Tool used

Manual Review

## Recommendation
Implement a multi-signature mechanism or a decentralized governance model for critical admin actions such as queuing, executing, or canceling transactions. This reduces the risk associated with a single admin and prevents potential abuse of the admin role.

Code Snippet for Fix:

```solidity
// Add a mapping to store admin addresses and their confirmation status
mapping(address => bool) public admins;
uint256 public requiredConfirmations;

// Ensure multiple confirmations for critical functions
modifier multiSigRequired() {
    require(admins[msg.sender], "Not an admin");
    require(++confirmations[msg.sender] == requiredConfirmations, "More confirmations required");
    _;
    // Reset for next operation
    confirmations[msg.sender] = 0;
}

function queueTransaction(...) public multiSigRequired returns (bytes32) {
    ...
}

function cancelTransaction(...) public multiSigRequired {
    ...
}

function executeTransaction(...) public payable multiSigRequired returns (bytes memory) {
    ...
}
```
With the **multiSigRequired** modifier, you can ensure that critical functions require multiple confirmations from different admins, enhancing the security of the system.