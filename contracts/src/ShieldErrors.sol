// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

library ShieldErrors {
    error AlreadyInitialized();
    error InvalidNonce();
    error TransactionFailed();
    error Unauthorized();
}
