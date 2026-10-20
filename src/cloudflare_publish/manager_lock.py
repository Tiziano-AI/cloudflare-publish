"""One OS-owned writer lock for complete manager command workflows."""

from __future__ import annotations

import fcntl
import os
import stat
from types import TracebackType
from typing import Literal

from cloudflare_publish.errors import AppError
from cloudflare_publish.models import AppPaths


class ManagerWriterLock:
    """Exclude local writers through flock; close releases ownership even on failure."""

    def __init__(self, paths: AppPaths) -> None:
        """Select the one persistent manager lock inode."""

        self._paths: AppPaths = paths
        self._descriptor: int | None = None

    def __enter__(self) -> None:
        """Acquire before workflow reads or writes, failing promptly on contention."""

        try:
            self._paths.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                self._paths.state_dir / "manager.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
        except OSError as error:
            raise AppError(
                "Cannot open the manager writer lock.", code="manager_lock_failed"
            ) from error
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AppError(
                    "Manager writer lock must be a regular file.", code="manager_lock_failed"
                )
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(descriptor)
            raise AppError(
                "Another command is changing this manager.",
                code="manager_busy",
                hints=("Let the active writer finish, then inspect state before retrying.",),
            ) from error
        except BaseException:
            os.close(descriptor)
            raise
        self._descriptor = descriptor

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        """Release without changing the workflow's exception or deleting the inode."""

        del exc_type, exc_value, traceback
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None
        return False
