"""SentryVision Slither runner — loads full implementation from split base64 parts."""
from __future__ import annotations

from pathlib import Path
import base64

here = Path(__file__).resolve().parent
_parts = []
for _i in range(3):
    _parts.append((here / f"slither_part_{_i}.b64").read_text())
_code = base64.b64decode("".join(_parts))
_target = here / "_slither_runner_impl.py"
_target.write_bytes(_code)
_ns = {"__name__": "slither_runner", "__file__": str(_target)}
exec(compile(_code, str(_target), "exec"), _ns)
globals().update({k: v for k, v in _ns.items() if not k.startswith("__")})
# Apply multi-layout solc path fix if available
try:
    import solc_patch  # noqa: F401
except Exception:
    pass
