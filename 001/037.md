Passive Corduroy Halibut

high

# Nobody can cast for any proposal

## Summary

[[castVote](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L369)](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L369)/[[castVoteWithReason](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L385)](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L385)/[[castVoteBySig](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L403)](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L403) are used to vote for the specified proposal. These functions internally call [[castVoteInternal](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L433-L437)](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L433-L437) to perform voting logic. However, `castVoteInternal` can never be executed successfully.

## Vulnerability Detail

```solidity
File: bophades\src\external\governance\GovernorBravoDelegate.sol
433:     function castVoteInternal(
434:         address voter,
435:         uint256 proposalId,
436:         uint8 support
437:     ) internal returns (uint256) {
......
444:         // Get the user's votes at the start of the proposal and at the time of voting. Take the minimum.
445:         uint256 originalVotes = gohm.getPriorVotes(voter, proposal.startBlock);
446:->       uint256 currentVotes = gohm.getPriorVotes(voter, block.number);
447:         uint256 votes = currentVotes > originalVotes ? originalVotes : currentVotes;
......
462:     }
```

The second parameter of `gohm.getPriorVotes(voter, block.number)` can only a number smaller than `block.number`. Please see the [[code](https://etherscan.io/token/0x0ab87046fBb341D058F17CBC4c1133F25a20a52f#code#L703)](https://etherscan.io/token/0x0ab87046fBb341D058F17CBC4c1133F25a20a52f#code#L703) deployed by gOHM on the mainnet:

```solidity
function getPriorVotes(address account, uint256 blockNumber) external view returns (uint256) {
->      require(blockNumber < block.number, "gOHM::getPriorVotes: not yet determined");
......
    }
```

Therefore, L446 will always revert. Voting will not be possible.

Copy the coded POC below to one project from Foundry and run `forge test -vvv` to prove this issue.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface CheatCodes {
    function prank(address) external;
    function createSelectFork(string calldata,uint256) external returns(uint256);
}

interface IGOHM {
    function getPriorVotes(address account, uint256 blockNumber) external view returns (uint256);
}

contract ContractTest is DSTest{
    address gOHM = 0x0ab87046fBb341D058F17CBC4c1133F25a20a52f;
    CheatCodes cheats = CheatCodes(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function setUp() public {
        cheats.createSelectFork("https://rpc.ankr.com/eth", 19068280);
    }

    function testRevert() public {
        address user = address(0x12399543949349);
        cheats.prank(user);
        IGOHM(gOHM).getPriorVotes(address(0x1111111111), block.number);
    }

    function testOk() public {
        address user = address(0x12399543949349);
        cheats.prank(user);
        IGOHM(gOHM).getPriorVotes(address(0x1111111111), block.number - 1);
    }
}
/**output
[PASS] testOk() (gas: 13019)
[FAIL. Reason: revert: gOHM::getPriorVotes: not yet determined] testRevert() (gas: 10536)
Traces:
  [10536] ContractTest::testRevert()
    ├─ [0] VM::prank(0x0000000000000000000000000012399543949349)
    │   └─ ← ()
    ├─ [540] 0x0ab87046fBb341D058F17CBC4c1133F25a20a52f::getPriorVotes(0x0000000000000000000000000000001111111111, 19068280 [1.906e7]) [staticcall]  
    │   └─ ← revert: gOHM::getPriorVotes: not yet determined
    └─ ← revert: gOHM::getPriorVotes: not yet determined

Test result: FAILED. 1 passed; 1 failed; 0 skipped; finished in 1.80s
**/
```

## Impact

Nobody can cast for any proposal. Not being able to vote means the entire governance contract will be useless. Core functionality is broken.

## Code Snippet

https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L446

## Tool used

Manual Review

## Recommendation

```fix
File: bophades\src\external\governance\GovernorBravoDelegate.sol
445:         uint256 originalVotes = gohm.getPriorVotes(voter, proposal.startBlock);
446:-        uint256 currentVotes = gohm.getPriorVotes(voter, block.number);
446:+        uint256 currentVotes = gohm.getPriorVotes(voter, block.number - 1);
447:         uint256 votes = currentVotes > originalVotes ? originalVotes : currentVotes;
```

&nbsp;