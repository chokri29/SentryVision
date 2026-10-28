// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Sensitive admin function with no access control
contract OpenVault {
    address public owner;
    mapping(address => uint256) public deposits;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function emergencyWithdraw(address to, uint256 amount) external {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
