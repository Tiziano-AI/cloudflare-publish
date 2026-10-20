"""macOS Keychain adapter built on the `security` CLI."""

from __future__ import annotations

from cloudflare_publish.errors import AppError
from cloudflare_publish.models import KEYCHAIN_SERVICE
from cloudflare_publish.process import CommandRunner

# Apple's interactive reader has a 4096-byte buffer. Keep the complete line,
# including its newline, below that size so it cannot split into two commands.
_SECURITY_LINE_BUFFER_BYTES = 4096


def _quote_security_argument(value: str) -> str:
    """Quote metadata for security's own parser, not a shell."""

    if not value or any(character in value for character in "\0\r\n"):
        raise AppError("Keychain metadata must be nonempty text without NUL, CR, or LF.")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _recovery_hint(account: str) -> str:
    """Name the workflow that owns replacement of this credential."""

    if account.startswith("service-token:"):
        return "Use `publish apply` or `token rotate` for this publication's credential."
    return "Run `cloudflare-publish setup` to store the API token again."


class Keychain:
    """Stores and retrieves secrets in the macOS Keychain."""

    def __init__(self, runner: CommandRunner) -> None:
        """Store the shared command runner."""

        self._runner: CommandRunner = runner

    def binary_available(self) -> bool:
        """Return whether the `security` CLI is present on PATH."""

        return self._runner.which("security") is not None

    def store_secret(self, *, account: str, secret: str) -> None:
        """Store a printable ASCII token and verify its exact native readback."""

        # `find-generic-password -w` hex-encodes nonprintable data, ambiguously
        # with an actual hex token. This adapter stores tokens, not binary data.
        if not secret.strip() or any(not 0x20 <= ord(character) <= 0x7E for character in secret):
            raise AppError("Keychain credentials must be nonempty printable ASCII tokens.")
        line = (
            f"add-generic-password -a {_quote_security_argument(account)} "
            f"-s {_quote_security_argument(KEYCHAIN_SERVICE)} "
            f"-U -X {secret.encode('utf-8').hex()}\n"
        )
        try:
            line_length = len(line.encode("utf-8"))
        except UnicodeEncodeError:
            raise AppError("Keychain metadata must be valid UTF-8 text.") from None
        if line_length >= _SECURITY_LINE_BUFFER_BYTES:
            raise AppError("Keychain credential command exceeds the native input limit.")

        # Bare `-w` prompts with getpass; piping the secret to it can silently
        # store an empty value. Interactive command input with -X is documented
        # and keeps both the original secret and its reversible hex out of argv.
        result = self._runner.run(
            ["security", "-q", "-i"],
            input_text=line,
            check=False,
        )
        if result.returncode != 0:
            # Never include output: a parser error could echo the encoded secret.
            raise AppError(
                "Keychain credential storage failed; the stored value is unconfirmed.",
                hints=(_recovery_hint(account),),
            )
        try:
            stored_secret = self.load_secret(account=account)
        except AppError:
            raise AppError(
                "Keychain credential storage could not be verified.",
                hints=(_recovery_hint(account),),
            ) from None
        if stored_secret != secret:
            raise AppError(
                "Keychain credential readback did not match the submitted value.",
                hints=(_recovery_hint(account),),
            )

    def load_secret(self, *, account: str) -> str:
        """Load a generic password secret."""

        result = self._runner.run(
            [
                "security",
                "find-generic-password",
                "-a",
                account,
                "-s",
                KEYCHAIN_SERVICE,
                "-w",
            ],
            check=False,
        )
        if result.returncode != 0:
            raise AppError(
                f"Keychain secret for {account!r} is missing.",
                hints=(_recovery_hint(account),),
            )
        if not result.stdout.endswith("\n"):
            raise AppError(
                "Keychain returned an invalid credential response.",
                hints=(_recovery_hint(account),),
            )
        # security appends one newline; stripping arbitrary whitespace would
        # hide a changed token and make the storage comparison inexact.
        secret = result.stdout.removesuffix("\n")
        if not secret.strip():
            raise AppError(
                f"Keychain secret for {account!r} is empty.",
                hints=(_recovery_hint(account),),
            )
        return secret

    def delete_secret(self, *, account: str) -> None:
        """Delete an entry, accepting only success or the native item-not-found status."""

        result = self._runner.run(
            [
                "security",
                "delete-generic-password",
                "-a",
                account,
                "-s",
                KEYCHAIN_SERVICE,
            ],
            check=False,
        )
        if result.returncode not in {0, 44}:
            # Other failures do not confirm removal. Native output can contain
            # credential material and must not enter a public error envelope.
            raise AppError(
                f"Keychain credential deletion failed (security exit {result.returncode}); "
                + "removal is unconfirmed.",
                hints=("Resolve the Keychain failure, then retry the original operation.",),
                code="keychain_delete_failed",
            )
