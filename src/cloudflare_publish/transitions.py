"""One unfinished mutation in the canonical manifest, with fixed-flow recovery."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import JsonObject
from cloudflare_publish.models import (
    ManagedPublication,
    PendingEffect,
    PendingTransition,
    StateManifest,
)
from cloudflare_publish.state import now_rfc3339, write_manifest


def require_no_pending(manifest: StateManifest) -> None:
    """Keep unrelated writers from overwriting recovery custody."""

    if manifest.pending is not None:
        raise AppError(
            f"Operation {manifest.pending.operation_id} ({manifest.pending.kind} "
            + f"{manifest.pending.target}) is incomplete.",
            code="transition_pending",
            hints=("Run cloudflare-publish --json repair plan and resume that operation.",),
        )


class Mutation:
    """Persistence boundary used by ordinary synchronous domain workflows."""

    def __init__(
        self,
        *,
        path: Path,
        manifest: StateManifest,
        kind: str,
        target: str,
        request: JsonObject,
        candidate: ManagedPublication | None = None,
    ) -> None:
        pending = manifest.pending
        if pending is not None:
            if (pending.kind, pending.target, pending.request) != (kind, target, request):
                require_no_pending(manifest)
        else:
            pending = PendingTransition(
                operation_id=str(uuid4()),
                kind=kind,
                target=target,
                request=request,
                candidate=candidate,
            )
        self.path: Path = path
        self.manifest: StateManifest = replace(manifest, pending=pending)
        self.save()

    @property
    def pending(self) -> PendingTransition:
        """Return the active transition or reject accidental use after completion."""

        if self.manifest.pending is None:
            raise AppError("The mutation has already completed.")
        return self.manifest.pending

    def save(self, *, pending: PendingTransition | None = None) -> None:
        """Persist current ownership, and only then permit the next effect."""

        if pending is not None:
            self.manifest = replace(self.manifest, pending=pending)
        self.manifest = replace(self.manifest, updated_at=now_rfc3339())
        write_manifest(self.path, self.manifest)

    def before_effect(
        self,
        *,
        kind: str,
        resource_name: str,
        resource_id: str | None = None,
    ) -> None:
        """Fence a non-repeatable call; an interrupted call needs exact resolution."""

        if self.pending.effect is not None:
            effect = self.pending.effect
            raise AppError(
                f"Operation {self.pending.operation_id} has an unknown {effect.kind} result.",
                code="outcome_unknown",
                hints=("Use cloudflare-publish --json repair plan; do not repeat the POST.",),
            )
        self.save(
            pending=replace(
                self.pending,
                effect=PendingEffect(
                    kind=kind, resource_name=resource_name, resource_id=resource_id
                ),
            )
        )

    def observed(self, *, candidate: ManagedPublication | None = None) -> None:
        """Record returned ownership and clear uncertainty in the same atomic write."""

        self.save(
            pending=replace(
                self.pending,
                effect=None,
                candidate=self.pending.candidate if candidate is None else candidate,
            )
        )

    def finish(self) -> StateManifest:
        """Forget only a completed transition, keeping its committed owned state."""

        self.manifest = replace(self.manifest, pending=None, updated_at=now_rfc3339())
        write_manifest(self.path, self.manifest)
        return self.manifest


def effective_publications(manifest: StateManifest) -> dict[str, ManagedPublication]:
    """One route projection for writes, verification and recovery."""

    publications = dict(manifest.publications)
    pending = manifest.pending
    if pending is None or pending.kind not in {"publish", "remove"}:
        return publications
    if pending.route == "withdrawn":
        _ = publications.pop(pending.target, None)
    elif pending.route == "candidate":
        if pending.candidate is None:
            raise AppError("Pending candidate routing has no owned publication.")
        publications[pending.target] = pending.candidate
    return publications
