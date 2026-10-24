"""Headless private-file credential custody, atomic failures and negative paths."""

# Ownership metadata cannot portably be manufactured with chown in an unprivileged
# hermetic fixture. These tests deliberately exercise those validation boundaries.
# pyright: reportPrivateUsage=false

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from cloudflare_publish import private_files
from cloudflare_publish.errors import AppError
from cloudflare_publish.secret_store import MAX_SECRET_BYTES, FileSecretStore, SecretStore


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """Canonicalize the platform's temp anchor, not the store path under test.

    macOS exposes /var as a symlink; Linux generally uses root-owned sticky
    /tmp. Production paths reject symlink components, even trusted OS aliases.
    """

    return tmp_path.resolve() / "manager" / "credentials"


def _filename(account: str) -> str:
    """Specify the complete digest contract independently of the store adapter."""

    return hashlib.sha256(account.encode("utf-8")).hexdigest() + ".secret"


def _existing(root: Path, *, account: str = "account", value: bytes = b"original") -> Path:
    """Build an owned private file with independently specified bytes/modes."""

    root.mkdir(mode=0o700, parents=True)
    path = root / _filename(account)
    _ = path.write_bytes(value)
    path.chmod(0o600)
    return path


def test_protocol_and_availability_do_not_create_paths(root: Path) -> None:
    """Missing directories are valid bootstrap, not implicit setup effects."""

    store: SecretStore = FileSecretStore(root)
    assert store.binary_available()
    assert not root.parent.exists()
    store.delete_secret(account="missing")
    assert not root.parent.exists()
    with pytest.raises(AppError) as caught:
        _ = store.load_secret(account="missing")
    assert caught.value.code == "secret_missing"
    assert not root.parent.exists()


def test_ensure_directory_creates_private_parents_but_never_repairs_existing_root(
    root: Path,
) -> None:
    """Setup can establish local custody before remote effects without widening it."""

    private_files.ensure_private_directory(root)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(root.parent.stat().st_mode) == 0o700
    assert list(root.iterdir()) == []
    root.chmod(0o755)
    with pytest.raises(AppError):
        private_files.ensure_private_directory(root)
    assert stat.S_IMODE(root.stat().st_mode) == 0o755


def test_private_file_helper_supports_exact_runtime_token_newline_and_larger_bound(
    root: Path,
) -> None:
    """The generic helper supports token-file bytes independently of printable secret API rules."""

    value = b"jwt-" + b"x" * 8000 + b"\n"
    private_files.write_private_file(root, "tunnel-token.txt", value, max_bytes=65536)
    assert private_files.read_private_file(root, "tunnel-token.txt", max_bytes=65536) == value
    assert (root / "tunnel-token.txt").read_bytes() == value
    assert stat.S_IMODE((root / "tunnel-token.txt").stat().st_mode) == 0o600


def test_store_uses_opaque_full_digest_and_preserves_exact_whitespace(root: Path) -> None:
    """Filename secrecy and exact storage are externally inspectable invariants."""

    account = "service-token: ../untrusted/è ' \" \t"
    secret = "  sentinel 'quoted' \"double\" \\ $ ; `substitution`  "
    store = FileSecretStore(root)
    store.store_secret(account=account, secret=secret)

    assert store.load_secret(account=account) == secret
    assert {path.name for path in root.iterdir()} == {_filename(account)}
    path = root / _filename(account)
    assert path.read_bytes() == secret.encode("ascii")
    assert path.stat().st_uid == os.getuid()
    assert path.stat().st_nlink == 1
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(root.parent.stat().st_mode) == 0o700
    assert store.binary_available()


def test_update_and_delete_touch_only_the_exact_account(root: Path) -> None:
    """Account transitions do not erase a sibling credential or require a keyring."""

    store = FileSecretStore(root)
    store.store_secret(account="account", secret="original")
    store.store_secret(account="other", secret="sibling")
    store.store_secret(account="account", secret="replacement")
    assert store.load_secret(account="account") == "replacement"
    store.delete_secret(account="account")
    store.delete_secret(account="account")
    assert store.load_secret(account="other") == "sibling"
    assert {path.name for path in root.iterdir()} == {_filename("other")}


@pytest.mark.parametrize(
    "secret", ["", " ", "\t", "x\ny", "x\ry", "\0", "é", "\x7f", "x" * (MAX_SECRET_BYTES + 1)]
)
def test_invalid_secrets_fail_before_directory_creation(root: Path, secret: str) -> None:
    """Invalid token input cannot mutate even an empty store."""

    with pytest.raises(AppError) as caught:
        FileSecretStore(root).store_secret(account="account", secret=secret)
    assert caught.value.code == "invalid_secret"
    assert not root.parent.exists()


def test_exact_secret_size_boundary_is_accepted(root: Path) -> None:
    """The bounded API admits its advertised inclusive limit."""

    secret = "x" * MAX_SECRET_BYTES
    store = FileSecretStore(root)
    store.store_secret(account="account", secret=secret)
    assert store.load_secret(account="account") == secret


@pytest.mark.parametrize("account", ["", "a\0b", "a\rb", "a\nb", "a\ud800b"])
def test_invalid_metadata_fails_before_any_access(root: Path, account: str) -> None:
    """All operations share the same metadata boundary, without leaking the value."""

    store = FileSecretStore(root)
    for operation in (
        lambda: store.store_secret(account=account, secret="sentinel"),
        lambda: store.load_secret(account=account),
        lambda: store.delete_secret(account=account),
    ):
        with pytest.raises(AppError) as caught:
            _ = operation()
        assert caught.value.code == "invalid_secret_account"
    assert not root.parent.exists()


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770, 0o777, 0o1700])
def test_existing_insecure_root_is_not_chmodded_or_used(root: Path, mode: int) -> None:
    """Availability, reading and mutations all reject an unsafe store root."""

    path = _existing(root)
    root.chmod(mode)
    store = FileSecretStore(root)
    for operation in (
        store.binary_available,
        lambda: store.load_secret(account="account"),
        lambda: store.store_secret(account="account", secret="replacement"),
        lambda: store.delete_secret(account="account"),
    ):
        with pytest.raises(AppError):
            _ = operation()
    assert stat.S_IMODE(root.stat().st_mode) == mode
    assert path.read_bytes() == b"original"


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o400, 0o1600])
def test_existing_insecure_file_is_neither_repaired_nor_replaced(root: Path, mode: int) -> None:
    """A new value is not permission to silently overwrite unsafe existing custody."""

    path = _existing(root)
    path.chmod(mode)
    store = FileSecretStore(root)
    for operation in (
        lambda: store.load_secret(account="account"),
        lambda: store.store_secret(account="account", secret="replacement"),
        lambda: store.delete_secret(account="account"),
    ):
        with pytest.raises(AppError):
            _ = operation()
    assert path.read_bytes() == b"original"
    assert stat.S_IMODE(path.stat().st_mode) == mode


@pytest.mark.parametrize("at_root", [True, False])
def test_symlinked_root_or_ancestor_is_rejected(root: Path, at_root: bool) -> None:
    """Neither a private-looking root symlink nor a parent redirect is followed."""

    actual = root.parent.parent / "actual"
    actual.mkdir(mode=0o700)
    if at_root:
        root.parent.mkdir(mode=0o700)
        root.symlink_to(actual, target_is_directory=True)
    else:
        root.parent.symlink_to(actual, target_is_directory=True)
    store = FileSecretStore(root)
    for operation in (
        store.binary_available,
        lambda: store.store_secret(account="account", secret="sentinel"),
        lambda: store.load_secret(account="account"),
        lambda: store.delete_secret(account="account"),
    ):
        with pytest.raises(AppError):
            _ = operation()
    assert list(actual.iterdir()) == []


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "fifo"])
def test_nonprivate_file_types_are_never_followed_replaced_or_deleted(
    root: Path, kind: str
) -> None:
    """Nonblocking no-follow reads reject FIFOs, and links cannot widen authority."""

    path = _existing(root, account="other")
    candidate = root / _filename("account")
    if kind == "symlink":
        candidate.symlink_to(path)
    elif kind == "hardlink":
        os.link(path, candidate)
    elif kind == "directory":
        candidate.mkdir(mode=0o700)
    else:
        os.mkfifo(candidate, mode=0o600)
    store = FileSecretStore(root)
    for operation in (
        lambda: store.load_secret(account="account"),
        lambda: store.store_secret(account="account", secret="replacement"),
        lambda: store.delete_secret(account="account"),
    ):
        with pytest.raises(AppError):
            _ = operation()
    assert candidate.lstat()
    assert path.read_bytes() == b"original"


def test_writable_nonsticky_ancestor_is_rejected(root: Path) -> None:
    """A private leaf does not compensate for a replaceable ancestor."""

    _ = _existing(root)
    root.parent.chmod(0o777)
    with pytest.raises(AppError, match="unsafe ancestor"):
        _ = FileSecretStore(root).binary_available()


def test_root_owned_sticky_ancestor_is_accepted_not_general_writable_parents() -> None:
    """The POSIX sticky rule is narrow: root-owned shared dirs may hold private children."""

    root_sticky = os.stat_result((stat.S_IFDIR | 0o1777, 1, 1, 1, 0, 0, 0, 0, 0, 0))
    private_files._require_ancestor(root_sticky)
    root_writable = os.stat_result((stat.S_IFDIR | 0o777, 1, 1, 1, 0, 0, 0, 0, 0, 0))
    with pytest.raises(AppError):
        private_files._require_ancestor(root_writable)
    foreign_sticky = os.stat_result(
        (stat.S_IFDIR | 0o1777, 1, 1, 1, os.getuid() + 1, 0, 0, 0, 0, 0)
    )
    with pytest.raises(AppError):
        private_files._require_ancestor(foreign_sticky)


def test_foreign_uid_file_and_directory_are_rejected() -> None:
    """Ownership is checked even when the caller cannot chown a real fixture."""

    foreign = os.getuid() + 1
    file = os.stat_result((stat.S_IFREG | 0o600, 1, 1, 1, foreign, 0, 8, 0, 0, 0))
    directory = os.stat_result((stat.S_IFDIR | 0o700, 1, 1, 1, foreign, 0, 0, 0, 0, 0))
    with pytest.raises(AppError):
        private_files._require_private_file(file)
    with pytest.raises(AppError):
        private_files._require_private_directory(directory)
    with pytest.raises(AppError):
        private_files._require_ancestor(directory)


@pytest.mark.parametrize("value", [b"", b" ", b"line\n", b"\xff", b"x" * (MAX_SECRET_BYTES + 1)])
def test_load_rejects_invalid_or_oversized_stored_values(root: Path, value: bytes) -> None:
    """A secure mode does not make arbitrary persisted bytes an admissible token."""

    _ = _existing(root, value=value)
    with pytest.raises(AppError) as caught:
        _ = FileSecretStore(root).load_secret(account="account")
    assert caught.value.code == "invalid_secret"


def test_write_failure_keeps_original_and_removes_private_staging(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An interrupted staged write does not truncate the existing credential or echo output."""

    path = _existing(root)

    def fail_write(*args: object, **kwargs: object) -> int:
        del args, kwargs
        raise OSError("sentinel-secret-must-not-escape")

    monkeypatch.setattr(os, "write", fail_write)
    with pytest.raises(AppError) as caught:
        FileSecretStore(root).store_secret(
            account="account", secret="sentinel-secret-must-not-escape"
        )
    assert caught.value.code == "private_file_write_failed"
    assert "sentinel-secret-must-not-escape" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert path.read_bytes() == b"original"
    assert {entry.name for entry in root.iterdir()} == {path.name}


def test_replacement_failure_preserves_original_and_removes_stage(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rejected atomic replace leaves the previous account intact, not a truncated file."""

    path = _existing(root)

    def fail_replace(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("sentinel-secret-must-not-escape")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(AppError) as caught:
        FileSecretStore(root).store_secret(account="account", secret="replacement")
    assert caught.value.code == "private_file_write_failed"
    assert path.read_bytes() == b"original"
    assert {entry.name for entry in root.iterdir()} == {path.name}


def test_partial_writes_are_completed_before_confirming_storage(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POSIX write may legally consume less than the buffer even without an error."""

    real_write = os.write

    def partial_write(descriptor: int, value: memoryview) -> int:
        return real_write(descriptor, value[:3])

    monkeypatch.setattr(os, "write", partial_write)
    store = FileSecretStore(root)
    store.store_secret(account="account", secret="whole-token-must-survive")
    assert store.load_secret(account="account") == "whole-token-must-survive"


@pytest.mark.parametrize("failure_on", [1, 2])
def test_fsync_failure_never_reports_confirmed_storage(
    root: Path, monkeypatch: pytest.MonkeyPatch, failure_on: int
) -> None:
    """Both staged-file and replaced-directory durability failures retain uncertain custody."""

    path = _existing(root)
    real_fsync = os.fsync
    calls = 0

    def fail_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == failure_on:
            raise OSError("sentinel-secret-must-not-escape")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_fsync)
    with pytest.raises(AppError) as caught:
        FileSecretStore(root).store_secret(account="account", secret="replacement")
    assert caught.value.code == "private_file_write_failed"
    assert "sentinel-secret-must-not-escape" not in str(caught.value)
    assert path.read_bytes() == (b"original" if failure_on == 1 else b"replacement")
    assert {entry.name for entry in root.iterdir()} == {path.name}


def test_successful_replace_requires_exact_readback(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A completed filesystem mutation is not falsely reported as confirmed storage."""

    _ = _existing(root)

    def wrong_read(*args: object, **kwargs: object) -> bytes:
        del args, kwargs
        return b"wrong"

    monkeypatch.setattr(private_files, "_read_at", wrong_read)
    with pytest.raises(AppError) as caught:
        FileSecretStore(root).store_secret(account="account", secret="sentinel-secret")
    assert caught.value.code == "private_file_write_failed"
    assert "sentinel-secret" not in str(caught.value)
    assert (root / _filename("account")).read_bytes() == b"sentinel-secret"


def test_failed_delete_retains_exact_credential_and_typed_custody(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Failed removal cannot be confused with successful missing-item cleanup."""

    path = _existing(root)

    def fail_unlink(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("sentinel-secret-must-not-escape")

    monkeypatch.setattr(os, "unlink", fail_unlink)
    with pytest.raises(AppError) as caught:
        FileSecretStore(root).delete_secret(account="account")
    assert caught.value.code == "private_file_delete_failed"
    assert "sentinel-secret-must-not-escape" not in str(caught.value)
    assert path.read_bytes() == b"original"


def test_delete_requires_observed_absence(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A filesystem call returning normally is not itself positive deletion evidence."""

    path = _existing(root)

    def no_unlink(*args: object, **kwargs: object) -> None:
        del args, kwargs

    monkeypatch.setattr(os, "unlink", no_unlink)
    with pytest.raises(AppError) as caught:
        FileSecretStore(root).delete_secret(account="account")
    assert caught.value.code == "private_file_delete_failed"
    assert path.read_bytes() == b"original"


def test_directory_replacement_after_staging_is_detected_before_installing_secret(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Descriptor-relative writes never follow a replacement store to another location."""

    path = _existing(root)
    old_root = root.with_name("old-store")
    real_confirm = private_files._confirm_directory

    def replace_root(target: Path, descriptor: int) -> None:
        _ = root.rename(old_root)
        root.mkdir(mode=0o700)
        real_confirm(target, descriptor)

    monkeypatch.setattr(private_files, "_confirm_directory", replace_root)
    with pytest.raises(AppError, match="directory changed"):
        FileSecretStore(root).store_secret(account="account", secret="replacement")
    assert list(root.iterdir()) == []
    assert (old_root / path.name).read_bytes() == b"original"
    assert {entry.name for entry in old_root.iterdir()} == {path.name}


@pytest.mark.parametrize("unsafe", [Path("relative/credentials"), Path("/"), Path("/a/../b")])
def test_unsafe_store_locations_are_rejected_without_access(unsafe: Path) -> None:
    """Store selection is absolute, non-root and free of parent traversal."""

    with pytest.raises(AppError) as caught:
        _ = FileSecretStore(unsafe).binary_available()
    assert caught.value.code == "private_path_unsafe"
