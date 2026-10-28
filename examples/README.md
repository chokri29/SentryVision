# Example contracts for SentryVision

These fixtures are for demos and regression testing.

| File | Expected primary issues |
|---|---|
| `01_reentrancy.sol` | Reentrancy (external call before balance update) |
| `02_missing_access_control.sol` | Missing access control on `emergencyWithdraw` |
| `03_unchecked_call.sol` | Unchecked low-level call / CEI violation |
| `04_tx_origin_auth.sol` | `tx.origin` authentication |
| `05_safe_minimal.sol` | Ideally no critical/high findings |

Notes:
- Self-contained (no external imports) so Slither can run without OpenZeppelin.
- Models can still miss or over-report issues.
- These examples are for triage demos, not formal audit ground truth.
