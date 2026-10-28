// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Intentionally simple / low-risk reference
contract SafeCounter {
    uint256 public total;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function add(uint256 x) external {
        require(msg.sender == owner, "only owner");
        total += x;
    }
}
