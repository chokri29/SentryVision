"""Known OpenZeppelin imports resolve. solc selection does not switch the global compiler."""

from pathlib import Path

import slither_runner
from slither_runner import (
    _resolve_solc_binary,
    _slither_command,
    _solc_artifact_path,
    rewrite_known_oz_imports,
    unsupported_imports,
)


OZ_CONTRACT = """
// import "@openzeppelin/contracts/finance/VestingWallet.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
contract Vault is Ownable, ReentrancyGuard {}
"""


def test_known_oz_imports_are_supported_and_rewritten():
    assert unsupported_imports(OZ_CONTRACT) == []
    rewritten = rewrite_known_oz_imports(OZ_CONTRACT)
    assert './oz/access/Ownable.sol' in rewritten
    assert './oz/security/ReentrancyGuard.sol' in rewritten
    assert './oz/utils/ReentrancyGuard.sol' in rewritten
    assert "@openzeppelin/contracts/access/Ownable.sol" not in rewritten


def test_commented_import_is_ignored():
    source = '// import "@openzeppelin/contracts/finance/VestingWallet.sol";\ncontract C {}'
    assert unsupported_imports(source) == []


def test_unknown_oz_and_relative_imports_are_rejected():
    unknown = 'import "@openzeppelin/contracts/finance/VestingWallet.sol";'
    relative = 'import "./Token.sol";'
    forge = 'import "forge-std/Test.sol";'
    assert any("VestingWallet" in item for item in unsupported_imports(unknown))
    assert unsupported_imports(relative) == ["./Token.sol"]
    assert unsupported_imports(forge) == ["forge-std/Test.sol"]


def test_plain_contract_has_no_unsupported_imports():
    assert unsupported_imports("pragma solidity ^0.8.0;\ncontract C { function f() external {} }") == []


def test_forge_style_oz_prefix_rewrites():
    source = 'import "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";'
    assert unsupported_imports(source) == []
    assert "./oz/token/ERC20/ERC20.sol" in rewrite_known_oz_imports(source)


def test_vendored_stubs_exist_for_rewritten_paths():
    rewritten = rewrite_known_oz_imports(OZ_CONTRACT)
    root = Path(slither_runner.__file__).resolve().parent / "vendor" / "openzeppelin" / "contracts"
    for rel in ("access/Ownable.sol", "security/ReentrancyGuard.sol", "utils/ReentrancyGuard.sol"):
        assert (root / rel).is_file()
        assert f"./oz/{rel}" in rewritten


def test_slither_command_pins_solc_binary():
    cmd = _slither_command(Path("C.sol"), Path("out.json"), "/opt/solc-0.8.20")
    assert cmd == ["slither", "C.sol", "--json", "out.json", "--solc", "/opt/solc-0.8.20"]
    assert "use" not in cmd


def test_resolve_solc_uses_artifact_without_solc_select_use(tmp_path, monkeypatch):
    version = "0.8.20"
    artifact = tmp_path / "artifacts" / f"solc-{version}"
    artifact.mkdir(parents=True)
    binary = artifact / f"solc-{version}"
    binary.write_text("")
    monkeypatch.setenv("SOLC_SELECT_INSTALL_DIR", str(tmp_path))

    def fail_run(*_args, **_kwargs):
        raise AssertionError("solc-select must not run when the artifact exists")

    monkeypatch.setattr(slither_runner.subprocess, "run", fail_run)
    got_version, got_path = _resolve_solc_binary(version)
    assert got_version == version
    assert got_path == str(binary)
    assert _solc_artifact_path(version) == binary


def test_resolve_solc_falls_back_without_global_switch(monkeypatch):
    def install(version):
        if version == "0.8.20":
            return Path("/opt/solc-0.8.20")
        return None

    monkeypatch.setattr(slither_runner, "_install_solc", install)
    got_version, got_path = _resolve_solc_binary("0.4.11")
    assert got_version == "0.8.20"
    assert got_path == "/opt/solc-0.8.20"
