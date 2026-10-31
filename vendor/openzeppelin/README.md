# Vendored OpenZeppelin subset

This directory contains a **vendored OZ subset**: hand-written minimal Solidity stubs used to resolve a bounded set of imports during Sentry Vision's static-analysis workflow. These files are not audited upstream OpenZeppelin code and are not claimed to be semantically equivalent to any complete OpenZeppelin release.

The stubs use **pre-5.0 style** patterns (for example, the Ownable constructor has no initialOwner argument). They are not a copy of a specific upstream version. Do not infer a version number or rely on these stubs for production behavior.

## Supported canonical import paths

The resolver's SUPPORTED_OZ_IMPORTS constant in slither_runner.py is the source of truth. The paths currently supported are:

- @openzeppelin/contracts/access/Ownable.sol
- @openzeppelin/contracts/interfaces/IERC20.sol
- @openzeppelin/contracts/security/Pausable.sol
- @openzeppelin/contracts/security/ReentrancyGuard.sol
- @openzeppelin/contracts/token/ERC20/ERC20.sol
- @openzeppelin/contracts/token/ERC20/IERC20.sol
- @openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol
- @openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol
- @openzeppelin/contracts/utils/Address.sol
- @openzeppelin/contracts/utils/Context.sol
- @openzeppelin/contracts/utils/Pausable.sol
- @openzeppelin/contracts/utils/ReentrancyGuard.sol

Equivalent supported package prefixes (openzeppelin-contracts/contracts/ and lib/openzeppelin-contracts/contracts/) map to these same relative paths. Imports outside the constant remain unresolved and fail closed to a model-only, not-verified result.
