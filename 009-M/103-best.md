Savory Rusty Parrot

medium

# Proposals are vulnerable to metamorphic attacks

## Summary

Proposals are vulnerable to metamorphic attacks where `create2()`/`selfdestruct()` are used to completely re-write proposal actions right before execution


## Vulnerability Detail

The timelock does not ensure that the `code` at the address of the target of the timelock's transaction hasn't changed since being proposed.


## Impact

An attacker can completely rewrite the backing logic of a proposal's external calls, as was seen in the [tornado governance attack](https://forum.tornado.ws/t/full-governance-attack-description/62), or by creating a `create2()`'d contract with a `payable fallback()` at the destination of an Eth transfer of part of a proposal


## Code Snippet

The target's code is not included in what's hashed:
```solidity
// File: src/external/governance/Timelock.sol : Timelock.queueTransaction()   #1

118:           bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));
```
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/Timelock.sol#L108-L118

and target passed in to the execution function is not verified to have the same code as during the proposal:
```solidity
// File: src/external/governance/Timelock.sol : Timelock.executeTransaction()   #2

164            // solium-disable-next-line security/no-call-value
165:           (bool success, bytes memory returnData) = target.call{value: value}(callData);
```
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/Timelock.sol#L164-L165


## Tool used

Manual Review


## Recommendation

Include the target address' [code](https://github.com/coinspect/learn-evm-attacks/tree/master/test/Business_Logic/TornadoCash_Governance#possible-mitigations) in what's hashed
