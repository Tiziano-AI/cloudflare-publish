"""Typed persistence for the manager state manifest."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import (
    JsonArray,
    JsonObject,
    JsonValue,
    load_json_value,
    require_object,
)
from cloudflare_publish.models import (
    SCHEMA_VERSION,
    BackupRecord,
    ManagedPublication,
    ManagerConfig,
    PendingEffect,
    PendingTransition,
    PublicationRemoteState,
    PublicationSpec,
    PublishRequest,
    StateManifest,
)
from cloudflare_publish.publication_contract import build_publication_spec


def now_rfc3339() -> str:
    """Return the current UTC timestamp in RFC3339 form."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_manifest(path: Path) -> StateManifest | None:
    """Load the canonical manager state manifest when it exists."""

    if not path.exists():
        return None
    payload = require_object(
        load_json_value(path.read_text(encoding="utf-8"), label="state.json"),
        message="state.json must contain a JSON object.",
    )
    return _manifest_from_object(payload)


def write_manifest(path: Path, manifest: StateManifest) -> None:
    """Replace the manifest atomically from a private same-directory staging file."""

    staged_path: Path | None = None
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, staged_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        staged_path = Path(staged_name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            _ = handle.write(
                json.dumps(_manifest_to_object(manifest), indent=2, sort_keys=True) + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged_path, path)
    except OSError as error:
        raise AppError(
            "Could not persist state.json; inspect current state before retrying the workflow.",
            code="state_write_failed",
        ) from error
    finally:
        if staged_path is not None:
            staged_path.unlink(missing_ok=True)


def build_initial_manifest(
    *,
    manager: ManagerConfig,
    backups: tuple[BackupRecord, ...] = (),
) -> StateManifest:
    """Build the initial manager manifest before any publications exist."""

    return StateManifest(
        schema_version=SCHEMA_VERSION,
        manager=manager,
        publications={},
        backups=backups,
        updated_at=now_rfc3339(),
    )


def replace_publications(
    manifest: StateManifest,
    *,
    publications: dict[str, ManagedPublication],
) -> StateManifest:
    """Return a new manifest with updated publication ownership."""

    return StateManifest(
        schema_version=manifest.schema_version,
        manager=manifest.manager,
        publications=publications,
        backups=manifest.backups,
        updated_at=now_rfc3339(),
        pending=manifest.pending,
    )


def replace_manager(manifest: StateManifest, *, manager: ManagerConfig) -> StateManifest:
    """Return a new manifest with refreshed manager identity."""

    return StateManifest(
        schema_version=manifest.schema_version,
        manager=manager,
        publications=manifest.publications,
        backups=manifest.backups,
        updated_at=now_rfc3339(),
        pending=manifest.pending,
    )


def replace_backups(
    manifest: StateManifest | None,
    *,
    manager: ManagerConfig,
    backups: tuple[BackupRecord, ...],
) -> StateManifest:
    """Return a manifest with refreshed backup history."""

    if manifest is None:
        return build_initial_manifest(manager=manager, backups=backups)
    return StateManifest(
        schema_version=manifest.schema_version,
        manager=manifest.manager,
        publications=manifest.publications,
        backups=backups,
        updated_at=now_rfc3339(),
        pending=manifest.pending,
    )


def _manifest_to_object(manifest: StateManifest) -> JsonObject:
    """Encode the state manifest into canonical JSON."""

    return {
        "schema_version": manifest.schema_version,
        "manager": _manager_to_object(manifest.manager),
        "publications": {
            key: _managed_publication_to_object(value)
            for key, value in manifest.publications.items()
        },
        "backups": [_backup_to_object(item) for item in manifest.backups],
        "updated_at": manifest.updated_at,
        "pending": transition_to_object(manifest.pending),
    }


def _manager_to_object(manager: ManagerConfig) -> JsonObject:
    """Encode the manager identity object."""

    return {
        "account_id": manager.account_id,
        "account_name": manager.account_name,
        "zone_id": manager.zone_id,
        "zone_name": manager.zone_name,
        "auth_domain": manager.auth_domain,
        "tunnel_name": manager.tunnel_name,
        "tunnel_id": manager.tunnel_id,
        "api_token_keychain_account": manager.api_token_keychain_account,
    }


def _managed_publication_to_object(publication: ManagedPublication) -> JsonObject:
    """Encode a publication plus its remote ownership."""

    return {
        "spec": _spec_to_object(publication.spec),
        "state": _remote_state_to_object(publication.state),
    }


def _spec_to_object(spec: PublicationSpec) -> JsonObject:
    """Encode a publication spec."""

    return {
        "kind": spec.kind,
        "name": spec.name,
        "hostname": spec.hostname,
        "origin_url": spec.origin_url,
        "audience": spec.audience,
        "allowed_emails": list(spec.allowed_emails),
        "allowed_email_domains": list(spec.allowed_email_domains),
        "verify_path": spec.verify_path,
        "expect_status": spec.expect_status,
        "ssh_host_key": spec.ssh_host_key,
        "origin_options": {
            "http_host_header": spec.origin_options.http_host_header,
            "origin_server_name": spec.origin_options.origin_server_name,
            "no_tls_verify": spec.origin_options.no_tls_verify,
        },
    }


def _remote_state_to_object(state: PublicationRemoteState) -> JsonObject:
    """Encode remote ownership data."""

    return {
        "dns_record_id": state.dns_record_id,
        "access_application_id": state.access_application_id,
        "access_aud": state.access_aud,
        "policy_ids": list(state.policy_ids),
        "service_token_id": state.service_token_id,
        "service_token_client_id": state.service_token_client_id,
        "service_token_keychain_account": state.service_token_keychain_account,
        "updated_at": state.updated_at,
    }


def _backup_to_object(record: BackupRecord) -> JsonObject:
    """Encode one takeover backup record."""

    return {
        "created_at": record.created_at,
        "directory": str(record.directory),
        "copied_paths": [str(path) for path in record.copied_paths],
    }


def _manifest_from_object(payload: JsonObject) -> StateManifest:
    """Decode and validate a JSON manifest payload."""

    version = _require_int(payload, "schema_version")
    if version != SCHEMA_VERSION:
        raise AppError("state.json schema_version is unsupported.")
    manager_payload = require_object(
        _require_value(payload, "manager"),
        message="state.json field 'manager' must be an object.",
    )
    publications_payload = require_object(
        _require_value(payload, "publications"),
        message="state.json field 'publications' must be an object.",
    )
    backups_payload = _require_array(payload, "backups")
    publications: dict[str, ManagedPublication] = {}
    for key, value in publications_payload.items():
        publications[key] = _managed_publication_from_value(value)
    return StateManifest(
        schema_version=version,
        manager=_manager_from_object(manager_payload),
        publications=publications,
        backups=tuple(_backup_from_value(item) for item in backups_payload),
        updated_at=_require_str(payload, "updated_at"),
        pending=_transition_from_value(payload.get("pending")),
    )


def transition_to_object(transition: PendingTransition | None) -> JsonObject | None:
    """Encode only normalized requests, ownership and recovery state; never secrets."""

    if transition is None:
        return None
    return {
        "operation_id": transition.operation_id,
        "kind": transition.kind,
        "target": transition.target,
        "request": transition.request,
        "phase": transition.phase,
        "route": transition.route,
        "candidate": (
            None
            if transition.candidate is None
            else _managed_publication_to_object(transition.candidate)
        ),
        "effect": (
            None
            if transition.effect is None
            else {
                "kind": transition.effect.kind,
                "resource_name": transition.effect.resource_name,
                "resource_id": transition.effect.resource_id,
            }
        ),
        "configuration_version": transition.configuration_version,
    }


def _transition_from_value(value: JsonValue) -> PendingTransition | None:
    """Decode pending custody without guessing malformed or unsupported state."""

    if value is None:
        return None
    item = require_object(value, message="pending transition must be an object.")
    route = _require_str(item, "route")
    if route != "current" and route != "withdrawn" and route != "candidate":
        raise AppError("state.json pending route is unsupported.")
    kind = _require_str(item, "kind")
    if kind not in {"setup", "setup_refresh", "publish", "remove", "teardown", "token_rotate"}:
        raise AppError("state.json pending operation kind is unsupported.")
    raw_effect = item.get("effect")
    effect = None
    if raw_effect is not None:
        effect_item = require_object(raw_effect, message="pending effect must be an object.")
        effect = PendingEffect(
            kind=_require_str(effect_item, "kind"),
            resource_name=_require_str(effect_item, "resource_name"),
            resource_id=_require_optional_str(effect_item, "resource_id"),
        )
    version = item.get("configuration_version")
    if version is not None and (type(version) is not int or version < 0):
        raise AppError("pending configuration_version must be a nonnegative integer or null.")
    candidate = item.get("candidate")
    return PendingTransition(
        operation_id=_require_str(item, "operation_id"),
        kind=kind,
        target=_require_str(item, "target"),
        request=require_object(item.get("request"), message="pending request must be an object."),
        phase=_require_str(item, "phase"),
        route=route,
        candidate=None if candidate is None else _managed_publication_from_value(candidate),
        effect=effect,
        configuration_version=version,
    )


def _manager_from_object(payload: JsonObject) -> ManagerConfig:
    """Decode the manager identity object."""

    return ManagerConfig(
        account_id=_require_str(payload, "account_id"),
        account_name=_require_str(payload, "account_name"),
        zone_id=_require_str(payload, "zone_id"),
        zone_name=_require_str(payload, "zone_name"),
        auth_domain=_require_str(payload, "auth_domain"),
        tunnel_name=_require_str(payload, "tunnel_name"),
        tunnel_id=_require_str(payload, "tunnel_id"),
        api_token_keychain_account=_require_str(payload, "api_token_keychain_account"),
    )


def _managed_publication_from_value(payload: JsonValue) -> ManagedPublication:
    """Decode a managed publication object."""

    item = require_object(payload, message="publication entries must be JSON objects.")
    spec_payload = require_object(
        _require_value(item, "spec"),
        message="publication spec must be a JSON object.",
    )
    state_payload = require_object(
        _require_value(item, "state"),
        message="publication state must be a JSON object.",
    )
    return ManagedPublication(
        spec=_spec_from_object(spec_payload),
        state=_remote_state_from_object(state_payload),
    )


def _spec_from_object(payload: JsonObject) -> PublicationSpec:
    """Decode a publication spec object."""

    origin_options_payload = require_object(
        _require_value(payload, "origin_options"),
        message="publication origin_options must be a JSON object.",
    )
    kind = _require_str(payload, "kind")
    if kind not in {"http_public", "ssh_public"}:
        raise AppError("state.json contains an unsupported publication kind.")
    spec = build_publication_spec(
        PublishRequest(
            name=_require_str(payload, "name"),
            hostname=_require_str(payload, "hostname"),
            origin_url=_require_str(payload, "origin_url"),
            audience=_require_str(payload, "audience"),
            allowed_emails=tuple(_require_str_array(payload, "allowed_emails")),
            allowed_email_domains=tuple(_require_str_array(payload, "allowed_email_domains")),
            verify_path=(
                _require_str(payload, "verify_path")
                if kind == "http_public"
                else _require_optional_str(payload, "verify_path")
            ),
            expect_status=(
                _require_str(payload, "expect_status")
                if kind == "http_public"
                else _require_optional_str(payload, "expect_status")
            ),
            http_host_header=_require_optional_str(origin_options_payload, "http_host_header"),
            origin_server_name=_require_optional_str(origin_options_payload, "origin_server_name"),
            no_tls_verify=_require_bool(origin_options_payload, "no_tls_verify"),
            ssh_host_key=_require_optional_str(payload, "ssh_host_key"),
        )
    )
    if spec.kind != kind:
        raise AppError("state.json publication kind does not match its origin scheme.")
    return spec


def _remote_state_from_object(payload: JsonObject) -> PublicationRemoteState:
    """Decode publication remote ownership state."""

    return PublicationRemoteState(
        dns_record_id=_require_str(payload, "dns_record_id"),
        access_application_id=_require_optional_str(payload, "access_application_id"),
        access_aud=_require_optional_str(payload, "access_aud"),
        policy_ids=tuple(_require_str_array(payload, "policy_ids")),
        service_token_id=_require_optional_str(payload, "service_token_id"),
        service_token_client_id=_require_optional_str(payload, "service_token_client_id"),
        service_token_keychain_account=_require_optional_str(
            payload,
            "service_token_keychain_account",
        ),
        updated_at=_require_str(payload, "updated_at"),
    )


def _backup_from_value(payload: JsonValue) -> BackupRecord:
    """Decode a takeover backup record."""

    item = require_object(payload, message="backup entries must be JSON objects.")
    return BackupRecord(
        created_at=_require_str(item, "created_at"),
        directory=Path(_require_str(item, "directory")),
        copied_paths=tuple(Path(path) for path in _require_str_array(item, "copied_paths")),
    )


def _require_value(payload: JsonObject, key: str) -> JsonValue:
    """Require a present field from a JSON object."""

    if key not in payload:
        raise AppError(f"state.json field {key!r} is required.")
    return payload[key]


def _require_array(payload: JsonObject, key: str) -> JsonArray:
    """Require a JSON array field."""

    value = _require_value(payload, key)
    if not isinstance(value, list):
        raise AppError(f"state.json field {key!r} must be an array.")
    return value


def _require_str_array(payload: JsonObject, key: str) -> list[str]:
    """Require an array of strings."""

    items = _require_array(payload, key)
    result: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise AppError(f"state.json field {key!r} must contain only strings.")
        result.append(item)
    return result


def _require_str(payload: JsonObject, key: str) -> str:
    """Require a string field."""

    value = _require_value(payload, key)
    if not isinstance(value, str):
        raise AppError(f"state.json field {key!r} must be a string.")
    return value


def _require_optional_str(payload: JsonObject, key: str) -> str | None:
    """Require an optional string field."""

    if key not in payload or payload[key] is None:
        return None
    value = payload[key]
    if not isinstance(value, str):
        raise AppError(f"state.json field {key!r} must be a string or null.")
    return value


def _require_int(payload: JsonObject, key: str) -> int:
    """Require an integer field."""

    value = _require_value(payload, key)
    if type(value) is not int:
        raise AppError(f"state.json field {key!r} must be an integer.")
    return value


def _require_bool(payload: JsonObject, key: str) -> bool:
    """Require a boolean field."""

    value = _require_value(payload, key)
    if not isinstance(value, bool):
        raise AppError(f"state.json field {key!r} must be a boolean.")
    return value
