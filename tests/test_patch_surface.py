"""F3 must not treat a deleted public function as a verified patch."""

from pathlib import Path

from slither_runner import high_medium_check_names, public_entry_points, surface_gap

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _example(name: str) -> str:
    return (EXAMPLES / name).read_text(encoding="utf-8")


def test_reentrancy_surface_is_deposit_and_withdraw():
    assert public_entry_points(_example("01_reentrancy.sol")) == ["deposit()|payable|()", "withdraw(uint256)|nonpayable|()"]


def test_tx_origin_surface_includes_receive():
    assert public_entry_points(_example("04_tx_origin_auth.sol")) == ["receive()|payable|()", "transferTo(address,uint256)|nonpayable|()"]


def test_other_examples_keep_their_entry_points():
    assert public_entry_points(_example("02_missing_access_control.sol")) == ["deposit()|payable|()", "emergencyWithdraw(address,uint256)|nonpayable|()"]
    assert public_entry_points(_example("03_unchecked_call.sol")) == ["claim()|nonpayable|()", "setOwed(address,uint256)|nonpayable|()"]
    assert public_entry_points(_example("05_safe_minimal.sol")) == ["add(uint256)|nonpayable|()"]


def test_deleting_withdraw_is_a_surface_gap():
    original = _example("01_reentrancy.sol")
    patched = original.replace(
        """    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }
""",
        "",
    )
    assert surface_gap(original, patched) == ["withdraw(uint256)|nonpayable|()"]


def test_downgrade_to_internal_is_a_surface_gap():
    original = _example("01_reentrancy.sol")
    patched = original.replace("function withdraw(uint256 amount) external", "function withdraw(uint256 amount) internal")
    assert surface_gap(original, patched) == ["withdraw(uint256)|nonpayable|()"]


def test_contract_rename_and_param_rewrite_are_not_a_gap():
    original = _example("01_reentrancy.sol")
    patched = original.replace("contract VulnerableBank", "contract FixedBank")
    patched = patched.replace("function withdraw(uint256 amount)", "function withdraw(uint256 _amount)")
    assert surface_gap(original, patched) == []


def test_comment_and_interface_decoys_are_ignored():
    source = """
    interface IBank { function withdraw(uint256 amount) external; }
    contract Bank {
        // function hidden() external {}
        function deposit() external { }
        function helper() internal { }
    }
    """
    assert public_entry_points(source) == ["deposit()|nonpayable|()"]


def test_high_medium_names_ignore_informational_detectors():
    detectors = [
        {"check": "reentrancy-eth", "impact": "High"},
        {"check": "naming-convention", "impact": "Informational"},
        {"check": "tx-origin", "impact": "Medium"},
        {"check": "solc-version", "impact": "Informational"},
    ]
    assert high_medium_check_names(detectors) == ["reentrancy-eth", "tx-origin"]


def test_arity_change_is_a_surface_gap():
    """withdraw(uint256) → withdraw() must not pass the surface check."""
    original = _example("01_reentrancy.sol")
    patched = original.replace(
        "function withdraw(uint256 amount) external",
        "function withdraw() external",
    )
    assert "withdraw(uint256)|nonpayable|()" in surface_gap(original, patched)


def test_mutability_change_is_a_surface_gap():
    original = """pragma solidity ^0.8.0; contract C { function withdraw(uint256 amount) external {} }"""
    patched = original.replace("external {}", "external payable {}")
    assert public_entry_points(original) == ["withdraw(uint256)|nonpayable|()"]
    assert "withdraw(uint256)|nonpayable|()" in surface_gap(original, patched)


def test_return_type_change_is_a_surface_gap():
    original = """pragma solidity ^0.8.0; contract C { function balance() external view returns (uint) { return 1; } }"""
    patched = original.replace("returns (uint)", "returns (bool)").replace("return 1;", "return true;")
    assert public_entry_points(original) == ["balance()|view|(uint256)"]
    assert "balance()|view|(uint256)" in surface_gap(original, patched)


def test_surface_canonicalizes_aliases_and_keeps_overloads_distinct():
    source = """pragma solidity ^0.8.0; contract C {
      function f(uint x) external {}
      function f(uint256 x) external payable {}
      function g() external pure returns (bool ok) { return true; }
    }"""
    assert public_entry_points(source) == [
      "f(uint256)|nonpayable|()", "f(uint256)|payable|()", "g()|pure|(bool)"
    ]
