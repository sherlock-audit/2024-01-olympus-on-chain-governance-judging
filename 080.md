Broad Bone Raven

high

# Upgrading `GovernorBravoDelegatorStorage` to V3 leads to storage collision

## Summary

The `GovernorBravoDelegate` inherits from `GovernorBravoDelegateStorageV2`, which should preserve all the storage properties. This architectural design allows for the addition of new storage properties in future governor implementation versions. This can be achieved by creating a new contract, `GovernorBravoDelegateStorageV3`, and adding new storage properties to it. While maintaining the storage layout from `GovernorBravoDelegateStorageV2` and previous versions, this approach ensures compatibility and scalability.

However, by implementing minor logic changes to the original [Compound's Governor Bravo](https://github.com/compound-finance/compound-protocol/tree/master/contracts/Governance), new storage properties were added directly to the `GovernorBravoDelegate`.

```solidity
    /// @notice The central hub of the Default Framework system that manages modules and policies
    /// @dev    Used in this adaptation of Governor Bravo to identify high risk proposals
    address public kernel;

    /// @notice Modules in the Default system that are considered high risk
    /// @dev    In Default Framework, Keycodes are used to uniquely identify modules. They are a
    ///         wrapper over the bytes5 data type, and allow us to easily check if a proposal is
    ///         touching any specific modules
    mapping(Keycode => bool) public isKeycodeHighRisk;
```

## Vulnerability Detail

The slot number in which the `kernel` address is stored immediately follows the slot number of the last property from the `GovernorBravoDelegateStorageV2` contract (`vetoGuardian`).

If the storage version is updated, the new properties in it will occupy the current `kernel` and `isKeycodeHighRisk` slots. Consequently, these slots will shift forward.

## Impact

Storage collision and incorrect state.

## Code Snippet

https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L55
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L61

## Tool used

Manual Review

## Recommendation

Move `kernel` and `isKeycodeHighRisk` to the `GovernorBravoDelegateStorageV2` contract.
