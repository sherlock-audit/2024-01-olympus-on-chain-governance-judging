Mysterious Honey Falcon

medium

# It might be not possible to execute approved proposals

## Summary

It is possible to create proposals that consist of duplicate transactions (actions), but it will not be possible to queue these transactions due to the logic implemented in the [`_queueOrRevertInternal`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L245-L246) function. This will lead to a scenario where approved proposals cannot be queued and thus executed.

## Vulnerability Detail

The [`propose`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L127-L205) function of the `GovernorBravoDelegate` contract allows the creation of proposals with duplicate transactions (actions). This could be relevant in cases where triggering a specific function twice is necessary, for example, the claim() function. Once the transaction is approved, the [`queue`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L211-L236) function is called, which, in turn, invokes the `Timelock` to queue the transactions. The issue arises in the [`_queueOrRevertInternal`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L245-L246) function, which checks if the transaction has already been queued. If it has, the function reverts, preventing the queuing of proposals containing duplicated transactions.

The following proof of concept illustrates the issue:
```solidity
unction testQueueFailIssue() public {
    address[] memory targets = new address[](2);
    uint256[] memory values = new uint256[](2);
    string[] memory signatures = new string[](2);
    bytes[] memory calldatas = new bytes[](2);
    string memory description = "Test Proposal";

    targets[0] = address(0x1234);
    values[0] = 0 ether;
    signatures[0] = "";
    calldatas[0] = abi.encodeWithSignature("claim()");
    
    targets[1] = address(0x1234);
    values[1] = 0 ether;
    signatures[1] = "";
    calldatas[1] = abi.encodeWithSignature("claim()");

    // Create proposal
    vm.prank(alice);
    bytes memory data = address(governorBravoDelegator).functionCall(
        abi.encodeWithSignature(
            "propose(address[],uint256[],string[],bytes[],string)",
            targets,
            values,
            signatures,
            calldatas,
            description
        )
    );
    uint256 proposalId = abi.decode(data, (uint256));

    // Warp forward so voting period has started
    vm.roll(block.number + 21601);

    // Set zero address's voting power
    gohm.checkpointVotes(address(0));

    // Vote for proposal
    vm.prank(address(0));
    address(governorBravoDelegator).functionCall(
        abi.encodeWithSignature("castVote(uint256,uint8)", proposalId, 1)
    );

    // Warp forward so voting period is complete (quorum met and majority) and warp forward so that the timelock grace period has expired
    vm.roll(block.number + 21600);

    // Queue proposal
    address(governorBravoDelegator).functionCall(
        abi.encodeWithSignature("queue(uint256)", proposalId)
    );
}
```

Results:
```shell
Running 1 test for src/test/external/GovernorBravoDelegate.t.sol:GovernorBravoDelegateTest
[FAIL. Reason: GovernorBravo_Queue_AlreadyQueued()] testQueueFailIssue() (gas: 598976)
Test result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 11.61ms

Ran 1 test suites: 0 tests passed, 1 failed, 0 skipped (1 total tests)

Failing tests:
Encountered 1 failing test in src/test/external/GovernorBravoDelegate.t.sol:GovernorBravoDelegateTest
[FAIL. Reason: GovernorBravo_Queue_AlreadyQueued()] testQueueFailIssue() (gas: 598976)

Encountered a total of 1 failing tests, 0 tests succeeded
```

## Impact

The approved proposal cannot be queued and thus executed.

## Code Snippet

- https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L245-L246

## Tool used

Manual Review

## Recommendation

It is recommended to add a check in the [`propose`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L127-L205) function to prevent the creation of proposals with duplicated transactions (actions).