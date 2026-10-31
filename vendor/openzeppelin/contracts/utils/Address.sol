// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library Address {
    function sendValue(address payable recipient, uint256 amount) internal {
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value");
    }

    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.call(data);
        require(success, "Address: low-level call failed");
        return returndata;
    }
}
