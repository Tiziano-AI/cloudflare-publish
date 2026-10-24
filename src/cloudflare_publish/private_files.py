"""Private POSIX files with descriptor-relative, no-follow access.

General ancestors may belong to root or the current UID. Writable ancestors
are rejected except root-owned sticky directories (the usual /tmp contract).
The store itself is always current-UID 0700, never a shared temporary directory.
These checks protect local file custody, not against root or the same UID.
"""

from __future__ import annotations

import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path
from types import TracebackType

from cloudflare_publish.errors import AppError


def private_directory_available(root: Path) -> bool:
    """Validate an existing store/ancestor chain without creating any paths."""

    if not _posix_available():
        return False
    with _directory(root, create=False):
        return True


def ensure_private_directory(root: Path) -> None:
    """Create a missing current-UID 0700 directory; never chmod existing custody."""

    with _directory(root, create=True) as directory:
        assert directory is not None
        _confirm_directory(root, directory)


def read_private_file(root: Path, name: str, *, max_bytes: int) -> bytes | None:
    """Return a bounded private regular file, or None when its exact name is absent."""

    _require_name(name)
    try:
        with _directory(root, create=False) as directory:
            if directory is None:
                return None
            value = _read_at(directory, name, max_bytes=max_bytes)
            _confirm_directory(root, directory)
            return value
    except OSError:
        raise AppError("Private credential read failed.", code="private_file_read_failed") from None


def write_private_file(root: Path, name: str, value: bytes, *, max_bytes: int) -> None:
    """Atomically replace one private file and confirm exact durable readback.

    Only a newly created staging file may be chmodded. Existing insecure files
    and directories are never silently repaired or overwritten.
    """

    _require_name(name)
    if not value or len(value) > max_bytes:
        raise AppError("Private credential size is invalid.", code="invalid_secret")
    try:
        with _directory(root, create=True) as directory:
            assert directory is not None
            original = _file_stat_at(directory, name)
            staged_name = f".{name}.{secrets.token_hex(16)}"
            descriptor = os.open(
                staged_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
            try:
                try:
                    os.fchmod(descriptor, 0o600)
                    _require_private_file(os.fstat(descriptor))
                    remaining = memoryview(value)
                    while remaining:
                        written = os.write(descriptor, remaining)
                        if written <= 0:
                            raise OSError("Private file write made no progress.")
                        remaining = remaining[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                _confirm_directory(root, directory)
                _confirm_target(directory, name, original)
                os.replace(staged_name, name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
                if _read_at(directory, name, max_bytes=max_bytes) != value:
                    raise AppError(
                        "Private credential readback did not match; storage is unconfirmed.",
                        code="private_file_write_failed",
                    )
                _confirm_directory(root, directory)
            finally:
                with suppress(FileNotFoundError):
                    os.unlink(staged_name, dir_fd=directory)
    except OSError:
        raise AppError(
            "Private credential write failed; storage is unconfirmed.",
            code="private_file_write_failed",
        ) from None


def delete_private_file(root: Path, name: str) -> None:
    """Delete only an owned regular file and positively confirm its absence."""

    _require_name(name)
    try:
        with _directory(root, create=False) as directory:
            if directory is None:
                return
            original = _file_stat_at(directory, name)
            _confirm_directory(root, directory)
            if original is not None:
                _confirm_target(directory, name, original)
                os.unlink(name, dir_fd=directory)
                os.fsync(directory)
            if _file_stat_at(directory, name) is not None:
                raise AppError(
                    "Private credential deletion is unconfirmed.",
                    code="private_file_delete_failed",
                )
            _confirm_directory(root, directory)
    except OSError:
        raise AppError(
            "Private credential deletion failed; removal is unconfirmed.",
            code="private_file_delete_failed",
        ) from None


def _require_name(name: str) -> None:
    """Admit one literal directory entry, never a relative path."""

    if not name or name in {".", ".."} or "/" in name or "\0" in name:
        raise AppError("Private credential filename is invalid.", code="private_path_unsafe")


class _directory:
    """Keep one directory descriptor alive without rewriting frozen AppError objects.

    contextlib's generator context manager assigns exception.__traceback__;
    AppError is a frozen dataclass and deliberately cannot support that write.
    """

    def __init__(self, root: Path, *, create: bool) -> None:
        """Retain directory selection without opening anything."""

        self._root: Path = root
        self._create: bool = create
        self._descriptor: int | None = None

    def __enter__(self) -> int | None:
        """Open/validate the directory chain for the duration of the operation."""

        self._descriptor = _open_directory(self._root, create=self._create)
        return self._descriptor

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Release our descriptor, preserving the original error without mutation."""

        del exception_type, exception, traceback
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None


def _open_directory(root: Path, *, create: bool) -> int | None:
    """Walk every component without following symlinks or widening permissions."""

    if not _posix_available():
        raise AppError("Private credential files require POSIX.", code="secret_store_unavailable")
    if not root.is_absolute() or root == Path("/") or ".." in root.parts or "\0" in str(root):
        raise AppError(
            "Private credential directory must be an absolute safe path.",
            code="private_path_unsafe",
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor: int | None = None
    try:
        descriptor = os.open(root.anchor, flags)
        _require_ancestor(os.fstat(descriptor))
        for index, name in enumerate(root.parts[1:]):
            is_root = index == len(root.parts) - 2
            try:
                child = os.open(name, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    os.close(descriptor)
                    descriptor = None
                    return None
                os.mkdir(name, mode=0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(name, flags, dir_fd=descriptor)
            try:
                metadata = os.fstat(child)
                if is_root:
                    _require_private_directory(metadata)
                else:
                    _require_ancestor(metadata)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        result = descriptor
        descriptor = None
        return result
    except OSError:
        raise AppError(
            "Private credential directory could not be accessed safely.",
            code="private_path_unsafe",
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _posix_available() -> bool:
    """Keep platform capability inspection runtime-based on both supported hosts."""

    return os.name == "posix"


def _require_ancestor(metadata: os.stat_result) -> None:
    """Trust owned nonwritable ancestors and root-owned sticky shared directories."""

    owned = metadata.st_uid in {0, os.getuid()}
    writable = bool(metadata.st_mode & 0o022)
    root_sticky = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
    if not stat.S_ISDIR(metadata.st_mode) or not owned or (writable and not root_sticky):
        raise AppError(
            "Private credential directory has an unsafe ancestor.", code="private_path_unsafe"
        )


def _require_private_directory(metadata: os.stat_result) -> None:
    """Demand exact current-UID 0700, including rejection of special mode bits."""

    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise AppError(
            "Private credential directory must be owned by this user with mode 0700.",
            code="private_path_unsafe",
        )


def _require_private_file(metadata: os.stat_result) -> None:
    """Demand exact current-UID 0600 regular single-link file custody."""

    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise AppError(
            "Private credentials must be owned regular single-link files with mode 0600.",
            code="private_path_unsafe",
        )


def _file_stat_at(directory: int, name: str) -> os.stat_result | None:
    """Open first, then validate: nonblocking and no-follow also reject FIFOs/links."""

    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory
        )
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        _require_private_file(metadata)
        return metadata
    finally:
        os.close(descriptor)


def _read_at(directory: int, name: str, *, max_bytes: int) -> bytes | None:
    """Read through one no-follow descriptor, with bounded size and identity checks."""

    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory
        )
    except FileNotFoundError:
        return None
    try:
        original = os.fstat(descriptor)
        _require_private_file(original)
        if not 0 < original.st_size <= max_bytes:
            raise AppError("Private credential size is invalid.", code="invalid_secret")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        current = os.fstat(descriptor)
        _require_private_file(current)
        if (
            len(value) != original.st_size
            or len(value) > max_bytes
            or current.st_size != original.st_size
            or current.st_mtime_ns != original.st_mtime_ns
            or current.st_ctime_ns != original.st_ctime_ns
        ):
            raise AppError(
                "Private credential changed during read.", code="private_file_read_failed"
            )
        _confirm_target(directory, name, original)
        return value
    finally:
        os.close(descriptor)


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare kernel file identity, not a potentially redirected pathname."""

    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _confirm_target(directory: int, name: str, original: os.stat_result | None) -> None:
    """Fence replacement of an observed entry by another directory writer."""

    current = _file_stat_at(directory, name)
    if (original is None) != (current is None) or (
        original is not None and current is not None and not _same_identity(original, current)
    ):
        raise AppError("Private credential path changed during access.", code="private_path_unsafe")


def _confirm_directory(root: Path, descriptor: int) -> None:
    """Reject a renamed/replaced store rather than confirming a detached old path."""

    _require_private_directory(os.fstat(descriptor))
    with _directory(root, create=False) as current:
        if current is None or not _same_identity(os.fstat(descriptor), os.fstat(current)):
            raise AppError(
                "Private credential directory changed during access.", code="private_path_unsafe"
            )
