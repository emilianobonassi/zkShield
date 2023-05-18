// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {BaseAccount, UserOperation, UserOperationLib} from "account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {MultiTokenReceiver} from "./MultiTokenReceiver.sol";
import {ShieldErrors} from "./ShieldErrors.sol";

import {ThresholdSignature} from "./ThresholdSignature.sol";

struct Transaction {
    address payable target;
    uint256 value;
    bytes payload;
    bool delegate;
}

contract ShieldAccount is BaseAccount, MultiTokenReceiver {
    using UserOperationLib for UserOperation;

    // Membership set root.
    bytes32 public root;

    // Multisig threshold.
    uint96 public requiredSigners;
    IEntryPoint _entrypoint;

    uint256 _nonce;

    bool hasInitialized;

    function initialize(
        IEntryPoint __entryPoint,
        bytes32 _root,
        uint96 _requiredSigners
    ) external {
        if (hasInitialized) {
            revert ShieldErrors.AlreadyInitialized();
        }

        _entrypoint = __entryPoint;
        root = _root;
        requiredSigners = _requiredSigners;

        hasInitialized = true;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entrypoint;
    }

    function nonce() public view override returns (uint256) {
        return _nonce;
    }

    function _validateAndUpdateNonce(UserOperation calldata userOp)
        internal
        override
    {
        if (userOp.nonce != nonce()) {
            revert ShieldErrors.InvalidNonce();
        }
        _nonce++;
    }

    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view override returns (uint256 deadline) {
        // Only occurs during the creation of the account.
        if (userOp.initCode.length > 0) {
            return 0;
        }

        ThresholdSignature.validateSignature(getEthSignedMessageHash(userOpHash), userOp.signature, requiredSigners, root);

        return 0;
    }

    function getEthSignedMessageHash(bytes32 hash)
        public
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
            );
    }

    modifier onlyEntryPoint() {
        if (msg.sender != address(entryPoint())) {
            revert ShieldErrors.Unauthorized();
        }
        _;
    }

    function execute(Transaction calldata tx_) external onlyEntryPoint {
        (bool success, ) = tx_.delegate
            ? tx_.target.delegatecall(tx_.payload)
            : tx_.target.call{value: tx_.value}(tx_.payload);
        if (!success) {
            revert ShieldErrors.TransactionFailed();
        }
    }

    function updateRoot(bytes32 _root) external onlyEntryPoint {
        root = _root;
    }

    function updateRequiredSigners(uint96 _requiredSigners)
        external
        onlyEntryPoint
    {
        requiredSigners = _requiredSigners;
    }
}
