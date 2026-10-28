// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Dangerous auth via tx.origin (phishing-prone)
contract TxOriginWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transferTo(address to, uint256 amount) external {
        require(tx.origin == owner, "not owner");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}
