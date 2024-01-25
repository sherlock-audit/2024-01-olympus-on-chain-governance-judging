Helpful Denim Salmon

medium

# Inadequate Emergency Stop Mechanisms for External Contract Integration

## Summary
While the GovernorBravoDelegate contract allows for proposals to interact with various external contracts, there are inadequate mechanisms to pause or stop interactions in case those external contracts execute emergency withdrawals or pauses, potentially putting the governed protocol at risk.
## Vulnerability Detail
The contract interacts with external contracts, particularly through the proposals that are made and executed. Given that the admin and protocols the contracts integrate with are considered TRUSTED, there is an implicit assumption of safety in these external interactions. However, the lack of explicit emergency stop mechanisms or contingency plans for handling unexpected behavior (like emergency withdrawals or pauses) in these external contracts could lead to situations where the governance system is unable to respond quickly to protect the protocol's interests.
## Impact
In the event of an emergency situation in an integrated external contract (e.g., a pause or emergency withdrawal), the lack of a rapid response mechanism in the GovernorBravoDelegate contract could result in delayed action, potentially leading to adverse effects on the protocol's functionality and stakeholder assets.
## Code Snippet
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L225-L232
## Tool used

Manual Review

## Recommendation
Consider implementing emergency stop mechanisms or circuit breakers, especially for interactions with external contracts. These mechanisms could allow trusted roles like the Veto Guardian or admin to quickly pause or stop certain actions in response to emergencies in integrated contracts. Additionally, establish clear procedures and off-chain monitoring systems to detect and respond to such emergencies promptly.