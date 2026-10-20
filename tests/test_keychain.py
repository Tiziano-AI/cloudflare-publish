"""Keychain token storage and native CLI failure regression tests."""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Literal, override

import pytest

from cloudflare_publish import keychain as keychain_module
from cloudflare_publish.errors import AppError
from cloudflare_publish.keychain import Keychain
from cloudflare_publish.models import KEYCHAIN_SERVICE
from cloudflare_publish.process import CommandResult, CommandRunner


class _SecurityRunner(CommandRunner):
    """Model successful processes separately from actual stored values."""

    def __init__(self) -> None:
        """Initialize a private in-memory keychain and failure controls."""

        super().__init__()
        self.calls: list[tuple[tuple[str, ...], str | None, bool]] = []
        self.entries: dict[tuple[str, str], str] = {}
        self.write_mode: Literal["normal", "empty", "ignore", "wrong"] = "normal"
        self.write_returncode: int = 0
        self.read_returncode: int = 0
        self.read_stdout: str | None = None
        self.delete_returncode: int = 0

    @override
    def run(
        self,
        command: list[str],
        *,
        check: bool = True,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        """Parse the selected command form and model the native bare -w defect."""

        del cwd, env
        self.calls.append((tuple(command), input_text, check))
        args = command[1:]
        interactive = args == ["-q", "-i"]
        if interactive:
            assert input_text is not None
            assert input_text.endswith("\n") and input_text.count("\n") == 1
            args = shlex.split(input_text)
        operation = args[0]
        entry = (args[args.index("-s") + 1], args[args.index("-a") + 1])
        returncode = 0
        stdout = ""
        stderr = ""
        if operation == "add-generic-password":
            returncode = self.write_returncode
            if returncode:
                stdout = input_text or ""
                stderr = "native parser echoed: " + (input_text or "")
            else:
                # Native getpass with piped stdin can return success but store
                # an empty password; do not repeat the old fake's assumption.
                secret = (
                    bytes.fromhex(args[args.index("-X") + 1]).decode("utf-8") if interactive else ""
                )
                if self.write_mode == "empty":
                    secret = ""
                elif self.write_mode == "wrong":
                    secret = "different-token"
                if self.write_mode != "ignore":
                    self.entries[entry] = secret
        elif operation == "find-generic-password":
            returncode = self.read_returncode
            if returncode or entry not in self.entries:
                returncode = returncode or 44
                stdout = "untrusted credential-like output"
                stderr = "untrusted native error"
            else:
                stdout = (
                    self.read_stdout if self.read_stdout is not None else self.entries[entry] + "\n"
                )
        elif operation == "delete-generic-password":
            returncode = self.delete_returncode or (0 if entry in self.entries else 44)
            if returncode == 0:
                del self.entries[entry]
            else:
                stdout = "untrusted credential-like output"
                stderr = "untrusted native error"
        else:
            raise AssertionError(f"Unexpected security command: {operation}")
        return CommandResult(tuple(command), returncode, stdout, stderr)


def test_store_secret_uses_one_interactive_hex_command_and_verifies_storage() -> None:
    """A successful write means exact storage, not just process exit zero."""

    runner = _SecurityRunner()
    secret = "  sentinel 'quoted' \"double\" \\ $ ; `substitution`  "

    Keychain(runner).store_secret(account="account-1", secret=secret)

    assert runner.entries[(KEYCHAIN_SERVICE, "account-1")] == secret
    assert len(runner.calls) == 2
    command, stdin, check = runner.calls[0]
    assert command == ("security", "-q", "-i")
    assert not check
    assert secret not in command and secret.encode().hex() not in command
    assert stdin == (
        f'add-generic-password -a "account-1" -s "{KEYCHAIN_SERVICE}" '
        f"-U -X {secret.encode().hex()}\n"
    )
    assert runner.calls[1] == (
        (
            "security",
            "find-generic-password",
            "-a",
            "account-1",
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
        ),
        None,
        False,
    )


def test_store_secret_updates_an_existing_entry() -> None:
    """The same account/service key is replaced and its new value is verified."""

    runner = _SecurityRunner()
    runner.entries[(KEYCHAIN_SERVICE, "account-1")] = "old-token"

    Keychain(runner).store_secret(account="account-1", secret="new-token")

    assert runner.entries == {(KEYCHAIN_SERVICE, "account-1"): "new-token"}


def test_store_secret_escapes_metadata_for_security_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    """Quotes, backslashes and shell punctuation remain literal metadata."""

    account = "  è \\ \" -s 'other' ; $(touch nope) `nope` \t"
    service = "service \\ \" ' $ ;"
    monkeypatch.setattr(keychain_module, "KEYCHAIN_SERVICE", service)
    runner = _SecurityRunner()

    Keychain(runner).store_secret(account=account, secret="sentinel")

    assert runner.entries == {(service, account): "sentinel"}
    assert len(runner.calls) == 2


@pytest.mark.parametrize("secret", ["", " ", "\t", "with\nnewline", "\0", "é", "\x7f"])
def test_invalid_token_is_rejected_before_any_keychain_access(secret: str) -> None:
    """Token readback cannot distinguish arbitrary binary data from native hex output."""

    runner = _SecurityRunner()

    with pytest.raises(AppError, match="nonempty printable ASCII"):
        Keychain(runner).store_secret(account="account-1", secret=secret)

    assert runner.calls == []


@pytest.mark.parametrize("account", ["", "a\0b", "a\rb", "a\nb", "a\ud800b"])
def test_invalid_account_cannot_inject_or_truncate_interactive_input(account: str) -> None:
    """Invalid metadata is rejected before the native process can mutate anything."""

    runner = _SecurityRunner()

    with pytest.raises(AppError, match="Keychain metadata"):
        Keychain(runner).store_secret(account=account, secret="sentinel")

    assert runner.calls == []


@pytest.mark.parametrize("service", ["", "s\0b", "s\rb", "s\nb"])
def test_invalid_service_is_rejected_before_mutation(
    service: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same parser boundary applies to both interpolated metadata values."""

    monkeypatch.setattr(keychain_module, "KEYCHAIN_SERVICE", service)
    runner = _SecurityRunner()

    with pytest.raises(AppError, match="Keychain metadata"):
        Keychain(runner).store_secret(account="account-1", secret="sentinel")

    assert runner.calls == []


def test_native_input_limit_reserves_space_for_newline_and_nul() -> None:
    """The reader must consume the newline in the same read as the command."""

    runner = _SecurityRunner()
    keychain = Keychain(runner)
    keychain.store_secret(account="a", secret="x")
    baseline = runner.calls[0][1]
    assert baseline is not None
    longest_account = "a" * (1 + 4095 - len(baseline.encode("utf-8")))
    runner.calls.clear()

    keychain.store_secret(account=longest_account, secret="x")

    accepted_stdin = runner.calls[0][1]
    assert accepted_stdin is not None
    assert len(accepted_stdin.encode("utf-8")) == 4095
    runner.calls.clear()
    with pytest.raises(AppError, match="native input limit"):
        keychain.store_secret(account=longest_account + "a", secret="x")
    assert runner.calls == []


@pytest.mark.parametrize("account", ["é" * 2100, "\\" * 2100, '"' * 2100])
def test_input_limit_counts_encoded_and_escaped_bytes(account: str) -> None:
    """Character count before quoting is not the native buffer's byte count."""

    runner = _SecurityRunner()

    with pytest.raises(AppError, match="native input limit"):
        Keychain(runner).store_secret(account=account, secret="sentinel")

    assert runner.calls == []


def test_input_limit_includes_encoded_secret() -> None:
    """Hex doubles the token byte count and must be bounded before mutation."""

    runner = _SecurityRunner()

    with pytest.raises(AppError, match="native input limit"):
        Keychain(runner).store_secret(account="account-1", secret="s" * 2100)

    assert runner.calls == []


def test_failed_write_does_not_read_back_or_expose_native_output() -> None:
    """A native error may contain the reversible hex; none belongs in AppError."""

    runner = _SecurityRunner()
    runner.write_returncode = 1
    secret = "private-test-token"

    with pytest.raises(AppError, match="storage failed") as error:
        Keychain(runner).store_secret(account="account-1", secret=secret)

    assert len(runner.calls) == 1
    assert not runner.calls[0][2]
    public_error = repr(error.value)
    assert secret not in public_error
    assert secret.encode().hex() not in public_error
    assert "native parser echoed" not in public_error


@pytest.mark.parametrize("mode", ["empty", "ignore", "wrong"])
def test_exit_zero_cannot_mask_unstored_or_changed_value(
    mode: Literal["empty", "ignore", "wrong"],
) -> None:
    """Empty storage, dropped writes and changed data all fail after exit zero."""

    runner = _SecurityRunner()
    runner.write_mode = mode

    with pytest.raises(AppError, match="storage could not be verified|readback did not match"):
        Keychain(runner).store_secret(account="account-1", secret="sentinel")

    assert len(runner.calls) == 2


def test_ignored_update_cannot_pass_with_old_credential() -> None:
    """An existing readable credential does not confirm a replacement write."""

    runner = _SecurityRunner()
    runner.write_mode = "ignore"
    runner.entries[(KEYCHAIN_SERVICE, "account-1")] = "old-token"

    with pytest.raises(AppError, match="readback did not match"):
        Keychain(runner).store_secret(account="account-1", secret="new-token")

    assert runner.entries[(KEYCHAIN_SERVICE, "account-1")] == "old-token"


def test_failed_readback_reports_unconfirmed_storage_without_native_output() -> None:
    """The write may persist despite unreadable storage, so no rollback is invented."""

    runner = _SecurityRunner()
    runner.read_returncode = 51

    with pytest.raises(AppError, match="storage could not be verified") as error:
        Keychain(runner).store_secret(account="account-1", secret="sentinel")

    assert runner.entries[(KEYCHAIN_SERVICE, "account-1")] == "sentinel"
    assert len(runner.calls) == 2
    assert "untrusted" not in repr(error.value)


@pytest.mark.parametrize("stdout", ["", "token-without-native-newline"])
def test_malformed_readback_cannot_confirm_storage(stdout: str) -> None:
    """A missing native terminator is not a complete password response."""

    runner = _SecurityRunner()
    runner.read_stdout = stdout

    with pytest.raises(AppError, match="storage could not be verified"):
        Keychain(runner).store_secret(account="account-1", secret="sentinel")


def test_readback_does_not_normalize_changed_whitespace() -> None:
    """Trimming both values could hide a different credential in storage."""

    runner = _SecurityRunner()
    runner.read_stdout = "sentinel\n"

    with pytest.raises(AppError, match="readback did not match"):
        Keychain(runner).store_secret(account="account-1", secret=" sentinel ")


def test_load_preserves_printable_token_whitespace() -> None:
    """Only security's single terminator is removed from a returned token."""

    runner = _SecurityRunner()
    runner.entries[(KEYCHAIN_SERVICE, "account-1")] = "  token  "

    assert Keychain(runner).load_secret(account="account-1") == "  token  "


@pytest.mark.parametrize("secret", ["", " ", "\t"])
def test_load_rejects_empty_credentials(secret: str) -> None:
    """An existing but unusable value must not masquerade as an available token."""

    runner = _SecurityRunner()
    runner.entries[(KEYCHAIN_SERVICE, "account-1")] = secret

    with pytest.raises(AppError, match="is empty"):
        _ = Keychain(runner).load_secret(account="account-1")


@pytest.mark.parametrize("read_returncode", [44, 51])
def test_service_token_recovery_does_not_refresh_shared_manager(read_returncode: int) -> None:
    """Missing or unreadable service credentials belong to their publication."""

    runner = _SecurityRunner()
    runner.read_returncode = read_returncode

    with pytest.raises(AppError) as error:
        _ = Keychain(runner).load_secret(account="service-token:mac-ssh")

    assert "publish apply" in " ".join(error.value.hints)
    assert "token rotate" in " ".join(error.value.hints)
    assert "setup" not in " ".join(error.value.hints)
    assert "untrusted" not in repr(error.value)


def test_delete_secret_removes_only_the_selected_entry() -> None:
    """Native success confirms the exact account/service deletion, not a broader cleanup."""

    runner = _SecurityRunner()
    runner.entries[(KEYCHAIN_SERVICE, "account-1")] = "selected-token"
    runner.entries[(KEYCHAIN_SERVICE, "other-account")] = "retained-token"

    Keychain(runner).delete_secret(account="account-1")

    assert runner.entries == {(KEYCHAIN_SERVICE, "other-account"): "retained-token"}
    assert runner.calls == [
        (
            (
                "security",
                "delete-generic-password",
                "-a",
                "account-1",
                "-s",
                KEYCHAIN_SERVICE,
            ),
            None,
            False,
        )
    ]


def test_delete_secret_accepts_native_item_not_found_on_retry() -> None:
    """A completed deletion can be retried without inventing a missing-item failure."""

    runner = _SecurityRunner()
    runner.entries[(KEYCHAIN_SERVICE, "account-1")] = "selected-token"
    keychain = Keychain(runner)

    keychain.delete_secret(account="account-1")
    keychain.delete_secret(account="account-1")

    assert runner.entries == {}
    assert len(runner.calls) == 2


@pytest.mark.parametrize("returncode", [1, 51, 128, 255])
def test_delete_secret_rejects_other_failures_without_native_output(returncode: int) -> None:
    """An access or native error must keep workflow custody rather than report removal."""

    runner = _SecurityRunner()
    runner.delete_returncode = returncode
    runner.entries[(KEYCHAIN_SERVICE, "account-1")] = "retained-token"

    with pytest.raises(AppError, match="deletion failed") as error:
        Keychain(runner).delete_secret(account="account-1")

    assert runner.entries == {(KEYCHAIN_SERVICE, "account-1"): "retained-token"}
    assert error.value.code == "keychain_delete_failed"
    assert f"security exit {returncode}" in error.value.message
    assert "retry the original operation" in " ".join(error.value.hints)
    assert len(runner.calls) == 1
    assert not runner.calls[0][2]
    assert "untrusted" not in repr(error.value)
    assert "retained-token" not in repr(error.value)
