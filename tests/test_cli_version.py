"""Offline installed-version discovery must not construct an operational runtime."""

from importlib.metadata import version
from unittest.mock import patch

import pytest

from cloudflare_publish.cli import main


def test_version_does_not_read_credentials_or_manager(capsys: pytest.CaptureFixture[str]) -> None:
    with (
        patch("cloudflare_publish.cli.build_cli_runtime", side_effect=AssertionError("runtime")),
        pytest.raises(SystemExit) as result,
    ):
        main(["--version"])
    assert result.value.code == 0
    captured = capsys.readouterr()
    assert captured.out == f"cloudflare-publish {version('cloudflare-publish')}\n"
    assert captured.err == ""
