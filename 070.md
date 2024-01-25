Dry White Okapi

medium

# `GovernorBravoDelegate.DOMAIN_TYPEHASH` is missing the `version` string which will result in signature replays on the new governance implementation

## Summary

`GovernorBravoDelegate.DOMAIN_TYPEHASH` doesn't consider the contract `version` when it's defined and constructed, which will result in signature replays on the new governance implementation contract.

## Vulnerability Detail

- The `GovernorBravoDelegate` contract has a functionality that enables voting by signature, where it uses `DOMAIN_TYPEHASH` to create the domainSeparator when recovering the signer of a signature:

  ```javascript
      bytes32 domainSeparator = keccak256(
              abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), getChainIdInternal(), address(this))
          );
  ```

  where `DOMAIN_TYPEHASH` is defined as follow:

  ```javascript
      /// @notice The EIP-712 typehash for the contract's domain
      bytes32 public constant DOMAIN_TYPEHASH =
          keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
  ```

- By knowing the following facts:

  1.  The implementation contract (`GovernorBravoDelegate`) can be changed by the admin of the `GovernorBravoDelegator` contract (which is the timelock via a governance proposal).

  2.  When `castVoteBySig` function is invoked; the signature becomes invalid on the same proposal that it has been signed on, and it doesn't have a time expiry.

  then defining the `DOMAIN_TYPEHASH` without the string `version` will leave the signatures being exposed to replay attacks, as the signatures created to vote on proposals on the previous `GovernorBravoDelegate` contract can still be used and replayed on the new `GovernorBravoDelegate` contract since the contract verion is not included in the signatures and `DOMAIN_TYPEHASH`.

- Following the [`EIP712`](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-domainseparator) on domainSeparator version definition:
  > `string version`: the current major version of the signing domain. Signatures from different versions are not compatible.

## Impact

Signature replay attacks on different versions of the `GovernorBravoDelegate` contract, where the same signature that was used to vote on a proposalId in the old version of the governance contract is used to vote on the same proposalId in the newest version of the governance contract without the voter consent.

## Code Snippet

[GovernorBravoDelegate.DOMAIN_TYPEHASH](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/6171681cfeec8a24b0449f988b75908b5e640a35/bophades/src/external/governance/GovernorBravoDelegate.sol#L63C1-L65C90)

```javascript
    /// @notice The EIP-712 typehash for the contract's domain
    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
```

## Tool used

Manual Review.

## Recommendation

- Add a `version` string to point to the current contract version, and modify `DOMAIN_TYPEHASH` to include the contract version:

  ```diff
  +   /// @notice The version of this contract, where it's defined in the constructor
  +   string public immutable version;

      /// @notice The EIP-712 typehash for the contract's domain
      bytes32 public constant DOMAIN_TYPEHASH =
  -       keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
  +       keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
  ```

- Update `GovernorBravoDelegate.castVoteBySig` function to consider `version` when constructing the domainSeparator:

  ```diff
  -     bytes32 domainSeparator = keccak256(
  -             abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), getChainIdInternal(), address(this))
  -         );

  +     bytes32 domainSeparator = keccak256(
  +             abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)),keccak256(bytes(version)),getChainIdInternal(), address(this))
  +         );
  ```