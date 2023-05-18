// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {ThresholdSignature} from './ThresholdSignature.sol';

contract Enum {
    enum Operation {
        Call,
        DelegateCall
    }
}

interface GnosisSafe {
    /// @dev Allows a Module to execute a Safe transaction without any further confirmations.
    /// @param to Destination address of module transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction.
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) external returns (bool success);
}

contract ShieldAccountSafeModule {
    GnosisSafe public safe;

    bytes32 public root;
    uint96 public requiredSigners;

    constructor(address _safe, bytes32 _root, uint96 _requiredSigners) {
        safe = GnosisSafe(_safe);
        root = _root;
        requiredSigners = _requiredSigners;
    }

    /// @dev Change root
    /// @param _root root
    function setRoot(bytes32 _root) public {
        require(msg.sender == address(safe), "!safe");
        root = _root;
    }

    /// @dev Change requiredSigners
    /// @param _requiredSigners requiredSigners
    function setRoot(uint96 _requiredSigners) public {
        require(msg.sender == address(safe), "!safe");
        requiredSigners = _requiredSigners;
    }

    /// @dev Exec tx using zk threshold signature proof
    /// @param to Destination address of module transaction
    /// @param value Ether value of module transaction
    /// @param data Data payload of module transaction
    /// @param operation Operation type of module transaction
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        bytes calldata signature
    ) public virtual returns (bool success) {
        //TODO: should use a nonce to avoid replay

        ThresholdSignature.validateSignature(
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", to, value, data, operation)
            ), 
            signature, 
            requiredSigners, 
            root
        );

        require(safe.execTransactionFromModule(to, value, data, operation), "Module transaction failed");

        return true;
    }
}