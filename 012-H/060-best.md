Curly Cloth Tarantula

high

# castVoteBySig doesn't check that signatory == msg.sender

## Summary
`castVoteBySig()` function in the GovernorBravoDelegate contract lacks a critical validation check to ensure that the `msg.sender` is the same as the signatory of the vote. 
This oversight could allow a malicious actor to exploit the signature for unauthorized voting.

## Vulnerability Detail
```solidity
function castVoteBySig(
    uint256 proposalId,
    uint8 support, // 0=against, 1=for, 2=abstain
    uint8 v, bytes32 r, bytes32 s
) external {
    // ... existing code ...

    // Recover signatory from the signature
    address signatory = ecrecover(digest, v, r, s);
    
    if (signatory == address(0)) revert GovernorBravo_InvalidSignature();
    
    // Vote casting without msg.sender validation
    emit VoteCast(
        signatory,
        proposalId,
        support,
        castVoteInternal(signatory, proposalId, support),
        ""
    );
}
```
The function retrieves the `signatory` from the provided signature but does not validate if the `msg.sender` is the same as the signatory.
A malicious user who intercepts by front-running the signatory TX or otherwise obtains a valid signature can cast a vote who support or does not support a proposal on behalf of the signatory without their consent.

## Impact
**Unauthorized Voting:** This vulnerability may lead to unauthorized voting actions, undermining the integrity of the governance process.
**Potential Front-Running Attacks:** If a transaction containing a valid signature is broadcast but not yet mined, a malicious actor could front-run this transaction with the same signature but altered support value.

## Code Snippet
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L416

## Tool used

Manual Review

## Recommendation
Include a check to ensure that the `msg.sender` is the same as the `signatory`

```solidity
function castVoteBySig(
    uint256 proposalId,
    uint8 support,
    uint8 v, bytes32 r, bytes32 s
) external {
    // ... existing code ...

    address signatory = ecrecover(digest, v, r, s);
    
    if (signatory == address(0)) revert GovernorBravo_InvalidSignature();

    // Added validation to ensure msg.sender is the signatory
+   require(msg.sender == signatory, "GovernorBravo: Signer and sender mismatch");

    emit VoteCast(
        signatory,
        proposalId,
        support,
        castVoteInternal(signatory, proposalId, support),
        ""
    );
}

```
