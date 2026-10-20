"""Typed user-facing error helpers for the CLI."""

from __future__ import annotations

from dataclasses import dataclass

type AppErrorJsonScalar = None | bool | int | float | str
type AppErrorJsonValue = AppErrorJsonScalar | list[AppErrorJsonValue] | dict[str, AppErrorJsonValue]
type AppErrorJsonObject = dict[str, AppErrorJsonValue]


@dataclass(frozen=True)
class AppError(Exception):
    """User-facing CLI error with optional remediation hints."""

    message: str
    hints: tuple[str, ...] = ()
    code: str = "app_error"
    data: AppErrorJsonObject | None = None
