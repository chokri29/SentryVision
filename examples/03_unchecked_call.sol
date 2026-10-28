// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// External call without checking success; state updated afterward
contract Payout {
    mapping(address => uint256) public owed;

    function setOwed(address user, uint256 amount) external {
        owed[user] = amount;
    }

    function claim() external {
        uint256 amount = owed[msg.sender];
        msg.sender.call{value: amount}("");
        owed[msg.sender] = 0;
    }
}
