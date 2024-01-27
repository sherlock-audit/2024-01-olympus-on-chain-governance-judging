Dry White Okapi

medium

# Proposals can be cancelled if the proposer's voting power drops to equal the proposalThreshold, while they can't be created if the proposer's voting power **equals** this threshold

## Summary

A proposal can't be cancelled if the proposer voting power (gOHM balance/delegated power at `block.number - 1`) drops to be equal to the proposlaThreshold, while with this voting power he can't create proposals.

## Vulnerability Detail

- gOHM holder can create a proposal if his voting power at the previous `block.number` of proposal creation is **greater** than the proposalThreshold at the time of proposal creation, and he can't create a proposal if his voting power is **less than or equal** to the proposalThreshold:

  ```javascript
  // Allow addresses above proposal threshold and whitelisted addresses to propose
          if (
              gohm.getPriorVotes(msg.sender, block.number - 1) <= getProposalThresholdVotes() &&
              !isWhitelisted(msg.sender)
          ) revert GovernorBravo_Proposal_ThresholdNotMet();
  ```

- While a created proposal can be cancelled (if not created by a whitelisted user) if the proposer voting power drops **below** the proposalThreshold:

  ```javascript
  if (
      gohm.getPriorVotes(proposal.proposer, block.number - 1) >=
      proposal.proposalThreshold
      ) revert GovernorBravo_Cancel_AboveThreshold();
  ```

- So as can be noticed, there's a contradiction here:
  the proposer **can't create a proposal** if his voting power equals to the proposalThreshold, while his created proposal **can't be cancelled** if his voting power equals to the proposalThreshold

- The same issue with the voting power check in `execute` and `queue` functions, where proposals can still be queued and executed even if the voting power of the proposer drops to a value equals to the proposalThreshold.

## Impact

This will allow proposers to drop their voting power to be equal to the proposalThreshold without risking the cancellation of their proposals.

## Code Snippet

[GovernorBravoDelegate.propose function/ L134-L138](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/6171681cfeec8a24b0449f988b75908b5e640a35/bophades/src/external/governance/GovernorBravoDelegate.sol#L134-L138)

```javascript
// Allow addresses above proposal threshold and whitelisted addresses to propose
        if (
            gohm.getPriorVotes(msg.sender, block.number - 1) <= getProposalThresholdVotes() &&
            !isWhitelisted(msg.sender)
        ) revert GovernorBravo_Proposal_ThresholdNotMet();
```

[GovernorBravoDelegate.cancel function/ L299-L302](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/6171681cfeec8a24b0449f988b75908b5e640a35/bophades/src/external/governance/GovernorBravoDelegate.sol#L299-L302)

```javascript
if (
    gohm.getPriorVotes(proposal.proposer, block.number - 1) >=
    proposal.proposalThreshold
    ) revert GovernorBravo_Cancel_AboveThreshold();
```

## Tool used

Manual Review.

## Recommendation

```diff
function cancel(uint256 proposalId) external {
        if (state(proposalId) == ProposalState.Executed)
            revert GovernorBravo_Cancel_AlreadyExecuted();

        Proposal storage proposal = proposals[proposalId];

        // Proposer can cancel
        if (msg.sender != proposal.proposer) {
            // Whitelisted proposers can't be canceled for falling below proposal threshold
            if (isWhitelisted(proposal.proposer)) {
                if (
                    (gohm.getPriorVotes(proposal.proposer, block.number - 1) >=
                        proposal.proposalThreshold) || msg.sender != whitelistGuardian
                ) revert GovernorBravo_Cancel_WhitelistedProposer();
            } else {
                if (
-                   gohm.getPriorVotes(proposal.proposer, block.number - 1) >=
-                   proposal.proposalThreshold

+                   gohm.getPriorVotes(proposal.proposer, block.number - 1) >
+                   proposal.proposalThreshold
                ) revert GovernorBravo_Cancel_AboveThreshold();
            }
        }

        // the rest of the function ...
    }
```