// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IERC20.sol";
import "./extensions/IERC20Metadata.sol";
import "../../utils/Context.sol";

contract ERC20 is Context, IERC20, IERC20Metadata {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;
    string private _name;
    string private _symbol;

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    function name() public view virtual override returns (string memory) { return _name; }
    function symbol() public view virtual override returns (string memory) { return _symbol; }
    function decimals() public view virtual override returns (uint8) { return 18; }
    function totalSupply() public view virtual override returns (uint256) { return _totalSupply; }
    function balanceOf(address account) public view virtual override returns (uint256) { return _balances[account]; }

    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), to, amount);
        return true;
    }

    function allowance(address owner_, address spender) public view virtual override returns (uint256) {
        return _allowances[owner_][spender];
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
        _spendAllowance(from, _msgSender(), amount);
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal virtual {
        require(from != address(0) && to != address(0), "ERC20: zero address");
        uint256 fromBal = _balances[from];
        require(fromBal >= amount, "ERC20: transfer exceeds balance");
        unchecked {
            _balances[from] = fromBal - amount;
            _balances[to] += amount;
        }
    }

    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: zero address");
        _totalSupply += amount;
        _balances[account] += amount;
    }

    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: zero address");
        uint256 bal = _balances[account];
        require(bal >= amount, "ERC20: burn exceeds balance");
        unchecked {
            _balances[account] = bal - amount;
            _totalSupply -= amount;
        }
    }

    function _approve(address owner_, address spender, uint256 amount) internal virtual {
        require(owner_ != address(0) && spender != address(0), "ERC20: zero address");
        _allowances[owner_][spender] = amount;
    }

    function _spendAllowance(address owner_, address spender, uint256 amount) internal virtual {
        uint256 current = _allowances[owner_][spender];
        if (current != type(uint256).max) {
            require(current >= amount, "ERC20: insufficient allowance");
            unchecked { _approve(owner_, spender, current - amount); }
        }
    }
}
