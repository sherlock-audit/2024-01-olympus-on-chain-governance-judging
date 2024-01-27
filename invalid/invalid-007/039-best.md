Main Pebble Quail

medium

# Timelock::constructor() should validate for admin parameter to be non zero address, else contract will become non-functional on deployment

## Summary
In the Timelock::constructor(), admin parameter passed is set as admin during deployment.  Incase this parameter is set to zero address, then the deployed contract will become useless.

Zero address validation for incoming parameter is critical in this case. 

## Vulnerability Detail
If the admin state variable is set to some invalid address, then most of the key functions in the contract will stop working due  to the below check.

```solidity
   if (msg.sender != admin) revert Timelock_OnlyAdmin();
```


## Impact
Deployed contract will become useless, if admin parameter was a zero address in the constructor.

## Code Snippet
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/Timelock.sol#L65-L70

Refer to the constructor() where, admin is set via the parameters. Passing zero address will make this contract non functional.

```solidity
 constructor(address admin_, uint256 delay_) {
        if (delay_ < MINIMUM_DELAY || delay_ > MAXIMUM_DELAY) revert Timelock_InvalidDelay();

        admin = admin_;
        delay = delay_;
    }
```

## Tool used

Manual Review

## Recommendation
Add zero address validation for admin parameter in the constructor as below. The require is for demonstration only, custom error can be thrown similar to how it is implemented for delay variable.

```solidity
constructor(address admin_, uint256 delay_) { 
     if (delay_ < MINIMUM_DELAY || delay_ > MAXIMUM_DELAY) revert Timelock_InvalidDelay(); 
     require(admin_!=0x0,"Invalid admin"); 
     admin = admin_; 
     delay = delay_; 
 } 
```
