"""Linux private-state custody starts before the manager writer lock is opened."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from cloudflare_publish.errors import AppError
from cloudflare_publish.manager_lock import ManagerWriterLock
from cloudflare_publish.models import AppPaths
from cloudflare_publish.paths import build_paths
from cloudflare_publish.private_files import ensure_private_directory


def _paths(tmp_path: Path) -> AppPaths:
    """Use real no-symlink ancestors, including macOS's temporary-directory alias."""

    root = tmp_path.resolve()
    return build_paths(root / "repo", root / "user", platform="linux")


def test_linux_lock_creates_private_state_before_any_workflow(tmp_path: Path) -> None:
    """A new manager never exposes its initial credential/token parent through the lock path."""

    paths = _paths(tmp_path)
    with ManagerWriterLock(paths):
        assert stat.S_IMODE(paths.state_dir.stat().st_mode) == 0o700
        lock = paths.state_dir / "manager.lock"
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600
        inode = lock.stat().st_ino
        with pytest.raises(AppError) as caught, ManagerWriterLock(paths):
            pytest.fail("The second writer must not acquire the same manager.")
        assert caught.value.code == "manager_busy"
    with ManagerWriterLock(paths):
        assert lock.stat().st_ino == inode


def test_linux_lock_rejects_nonprivate_state_without_repairing_it(tmp_path: Path) -> None:
    """An insecure existing state directory is not silently chmodded or used."""

    paths = _paths(tmp_path)
    paths.state_dir.mkdir(parents=True)
    paths.state_dir.chmod(0o755)
    with pytest.raises(AppError), ManagerWriterLock(paths):
        pytest.fail("Nonprivate state must not be used.")
    assert stat.S_IMODE(paths.state_dir.stat().st_mode) == 0o755
    assert not (paths.state_dir / "manager.lock").exists()


def test_linux_lock_rejects_symlinked_state_parent(tmp_path: Path) -> None:
    """The lock cannot create state through an attacker-selected directory component."""

    paths = _paths(tmp_path)
    destination = tmp_path.resolve() / "destination"
    destination.mkdir(mode=0o700)
    paths.state_dir.parent.mkdir(parents=True)
    paths.state_dir.symlink_to(destination, target_is_directory=True)
    with pytest.raises(AppError), ManagerWriterLock(paths):
        pytest.fail("Symlinked state must not be used.")
    assert not (destination / "manager.lock").exists()


@pytest.mark.parametrize("drift", ["mode", "hardlink", "symlink"])
def test_linux_lock_refuses_unsafe_lock_without_mutating_target(tmp_path: Path, drift: str) -> None:
    """An existing lock's custody must be valid before opening it can authorize workflow work."""

    paths = _paths(tmp_path)
    ensure_private_directory(paths.state_dir)
    target = paths.state_dir / "retained"
    target.write_text("retained", encoding="utf-8")
    target.chmod(0o600)
    lock = paths.state_dir / "manager.lock"
    if drift == "hardlink":
        os.link(target, lock)
    elif drift == "symlink":
        lock.symlink_to(target)
    else:
        lock.write_text("insecure", encoding="utf-8")
        lock.chmod(0o644)
    with pytest.raises(AppError) as caught, ManagerWriterLock(paths):
        pytest.fail("Unsafe lock must not be acquired.")
    assert caught.value.code == "manager_lock_failed"
    assert target.read_text(encoding="utf-8") == "retained"
    if drift == "mode":
        assert stat.S_IMODE(lock.stat().st_mode) == 0o644
