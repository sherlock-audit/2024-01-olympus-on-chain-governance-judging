Sharp Seafoam Bison

high

# Unrecoverable ether when sending to Timelock.sol contract  fallback function

## Summary
The ether that is sent to Timelock.sol fallback function cant be recovered due to lacks of mechanisms to do so  

## Vulnerability Detail
This is due because the only ether outflow method in Timelock is executeTransaction method but is only callable by the admin, not by the user that sent ether.  
However in normal conditions Timelock.sol admin is GovernorBravoDelegator delegation path is the following  
```
GovernorBravoDelegator.fallback                       //payable
      |_ GovernorBravoDelegate.execute                //payable
            |_ Timelock.sol.executeTransaction        //payable
```
GovernorBravoDelegate execute function is payable 
Note that msg.value must be equal to proposal.targets total ether 
```js
//GovernorBravoDelegate.sol
    function execute(uint256 proposalId) external payable {
        if (state(proposalId) != ProposalState.Queued) revert GovernorBravo_Execute_NotQueued();
        Proposal storage proposal = proposals[proposalId];
        // Proposal checks
        //...
        proposal.executed = true;
        for (uint256 i = 0; i < proposal.targets.length; i++) {
            timelock.executeTransaction{value: proposal.values[i]}(  // ether sent 
```
So, the user must send ether to GovernorBravoDelegate.execute leaving the ether sent Timelock fallback function stuck    
because there is no other way to sent the ether out Timelock contract  

## Impact
Ether sent to Timelock.sol is unrecovereable   

## Code Snippet
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L255-L269

https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/Timelock.sol#L140-L147  
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/Timelock.sol#L165-L166

## Tool used

Manual Review

## Recommendation
Implement a mechanism to recover ether sent to Timelock.sol