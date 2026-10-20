"""Native curl configuration isolation without network or credentials."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from cloudflare_publish.http import CurlHttpClient
from cloudflare_publish.process import CommandRunner


def test_native_transport_ignores_operator_curlrc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real curlrc affects native curl, but cannot change the product request."""

    binary = shutil.which("curl")
    if binary is None:
        pytest.skip("native curl is not available")
    user_dir = tmp_path / "user"
    user_dir.mkdir()
    # curl checks CURL_HOME before HOME and may also inspect XDG_CONFIG_HOME.
    monkeypatch.setenv("HOME", str(user_dir))
    monkeypatch.setenv("CURL_HOME", str(user_dir))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(user_dir / "xdg"))
    (user_dir / ".curlrc").write_text("max-filesize = 1\n", encoding="utf-8")
    payload = "local fixture exceeds the operator's one-byte limit\n"
    origin = tmp_path / "response.txt"
    origin.write_text(payload, encoding="utf-8")

    baseline = subprocess.run(
        [binary, "--silent", "--show-error", origin.as_uri()],
        check=False,
        capture_output=True,
        text=True,
    )
    assert baseline.returncode == 63, baseline.stderr

    response = CurlHttpClient(CommandRunner()).get(origin.as_uri())
    # file:// deliberately supplies native curl with a fully offline fixture;
    # its synthetic status is not an HTTP-readiness assertion.
    assert response.status_code == 0
    assert response.body == payload
