Savory Rusty Parrot

medium

# High-risk actions aren't all covered by the existing checks

## Summary

Things such as changing the list of high risk operations, or migrating kernels are not counted as high risk, even though they are high-risk


## Vulnerability Detail

High risk modules are checked against a mapping, but the changing of values within the mapping is not marked as high risk.

In addition, the `MigrateKernel` action is not protected, even though it can [brick the protocol](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/Kernel.sol#L338)


## Impact

Allows an attacker to brick the protocol with a low threshold, or to remove the high-risk modules from the list of high risk modules, resulting in a lower threshold
Violates invariant of high-risk actions needing to be behind a higher quorum


## Code Snippet

`MigrateKernel` isn't considered high-risk, and neither are calls to [`_setModuleRiskLevel()`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L593-L602):
```solidity
// File: src/external/governance/GovernorBravoDelegate.sol : GovernorBravoDelegate._isHighRiskProposal()   #1

647 @>                     // If the action is upgrading a module (1)
648                        if (action == 1) {
649                            // Check if the module has a high risk keycode
650                            if (isKeycodeHighRisk[Module(actionTarget).KEYCODE()]) return true;
651                        }
652 @>                     // If the action is installing (2) or deactivating (3) a policy, pull the list of dependencies
653                        else if (action == 2 || action == 3) {
654                            // Call `configureDependencies` on the policy
655                            Keycode[] memory dependencies = Policy(actionTarget)
656                                .configureDependencies();
657    
658                            // Iterate over dependencies and looks for high risk keycodes
659                            uint256 numDeps = dependencies.length;
660                            for (uint256 j; j < numDeps; j++) {
661                                Keycode dep = dependencies[j];
662                                if (isKeycodeHighRisk[dep]) return true;
663                            }
664:                       }
```
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L647-L664


## Tool used

Manual Review


## Recommendation

Add those operations to the high risk category

