"""F3 must not treat a deleted public function as a verified patch."""

from pathlib import Path

from slither_runner import high_medium_check_names, public_entry_points, surface_gap

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _example(name: str) -> str:
    return (EXAMPLES / name).read_text(encoding="utf-8")


def test_reentrancy_surface_is_deposit_and_withdraw():
    assert public_entry_points(_example("01_reentrancy.sol")) == ["deposit", "withdraw"]


def test_tx_origin_surface_includes_receive():
    assert public_entry_points(_example("04_tx_origin_auth.sol")) == ["receive", "transferTo"]


def test_other_examples_keep_their_entry_points():
    assert public_entry_points(_example("02_missing_access_control.sol")) == ["deposit", "emergencyWithdraw"]
    assert public_entry_points(_example("03_unchecked_call.sol")) == ["claim", "setOwed"]
    assert public_entry_points(_example("05_safe_minimal.sol")) == ["add"]


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
    assert surface_gap(original, patched) == ["withdraw"]


def test_downgrade_to_internal_is_a_surface_gap():
    original = _example("01_reentrancy.sol")
    patched = original.replace("function withdraw(uint256 amount) external", "function withdraw(uint256 amount) internal")
    assert surface_gap(original, patched) == ["withdraw"]


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
    assert public_entry_points(source) == ["deposit"]


def test_high_medium_names_ignore_informational_detectors():
    detectors = [
        {"check": "reentrancy-eth", "impact": "High"},
        {"check": "naming-convention", "impact": "Informational"},
        {"check": "tx-origin", "impact": "Medium"},
        {"check": "solc-version", "impact": "Informational"},
    ]
    assert high_medium_check_names(detectors) == ["reentrancy-eth", "tx-origin"]
