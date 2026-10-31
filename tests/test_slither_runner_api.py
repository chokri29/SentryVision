"""Guard the Slither runner's public and key internal API against accidental truncation."""

import slither_runner


def test_required_runner_api_is_importable():
    for name in (
        "verify_patch",
        "public_entry_points",
        "_resolve_solc_binary",
        "rewrite_known_oz_imports",
        "unsupported_imports",
    ):
        assert callable(getattr(slither_runner, name, None)), f"missing runner API: {name}"
