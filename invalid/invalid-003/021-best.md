Helpful Denim Salmon

medium

# Lack of Input Validation in Constructor

## Summary
The **GovernorBravoDelegator** contract's constructor does not perform thorough validation on the input parameters, potentially allowing the contract to be initialized with invalid or malicious addresses.
## Vulnerability Detail
The constructor of the **GovernorBravoDelegator** contract accepts several parameters, including **timelock_**, **gohm_**, **kernel_**, and implementation_, which are critical for the contract's functionality. However, there is a lack of comprehensive validation on these inputs, which could lead to the contract being initialized with incorrect or malicious addresses.
## Impact
Initializing the contract with incorrect or malicious addresses can lead to malfunctioning governance processes, security vulnerabilities, or other operational risks.
## Code Snippet
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegator.sol#L10-L38

## Tool used

Manual Review

## Recommendation
Implement rigorous input validation in the constructor to ensure that all parameters are checked for validity before being used to initialize the contract. Consider the following validations:

- **Address Non-Zero Validation**: Ensure that the addresses for **timelock_**, **gohm_**, **kernel_**, and **implementation_** are not zero addresses.
- 
- **Parameter Range Checks**: If applicable, ensure that parameters like **votingPeriod_**, **votingDelay_**, and **proposalThreshold_** fall within expected or allowed ranges.

Here's a code snippet illustrating how you might implement input validation in the constructor:

```solidity
constructor(
    address timelock_,
    address gohm_,
    address kernel_,
    address implementation_,
    uint256 votingPeriod_,
    uint256 votingDelay_,
    uint256 proposalThreshold_
) {
    require(timelock_ != address(0), "GovernorBravoDelegator: invalid timelock address");
    require(gohm_ != address(0), "GovernorBravoDelegator: invalid gohm address");
    require(kernel_ != address(0), "GovernorBravoDelegator: invalid kernel address");
    require(implementation_ != address(0), "GovernorBravoDelegator: invalid implementation address");
    // Additional range checks for votingPeriod_, votingDelay_, proposalThreshold_ if applicable
    ...

    // Admin set to msg.sender for initialization
    admin = msg.sender;

    delegateTo(
        implementation_,
        abi.encodeWithSignature(
            "initialize(address,address,address,uint256,uint256,uint256)",
            timelock_,
            gohm_,
            kernel_,
            votingPeriod_,
            votingDelay_,
            proposalThreshold_
        )
    );

    _setImplementation(implementation_);

    admin = timelock_;
}
```
By adding these checks, you can prevent the contract from being initialized with invalid parameters, thereby reducing the risk of misconfiguration or vulnerabilities in the governance process.