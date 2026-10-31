// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../IERC20.sol";
import "../../../utils/Address.sol";

library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        Address.functionCall(address(token), abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        Address.functionCall(address(token), abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }
}
