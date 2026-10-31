// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract Pausable {
    bool private _paused;

    modifier whenNotPaused() {
        require(!_paused, "Pausable: paused");
        _;
    }

    function paused() public view virtual returns (bool) {
        return _paused;
    }

    function _pause() internal virtual {
        _paused = true;
    }

    function _unpause() internal virtual {
        _paused = false;
    }
}
