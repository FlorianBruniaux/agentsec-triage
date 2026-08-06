from __future__ import annotations

import json
import re
from collections.abc import Mapping
from importlib import resources
from typing import cast

from agentsec.models import ThreatDatabase


class ThreatDatabaseError(RuntimeError):
    """Raised when the bundled runtime threat database is missing or invalid."""


_REQUIRED_KEYS = (
    "version",
    "updated",
    "package_versions",
    "wildcard_package_versions",
    "hashes",
    "domains",
    "commit_indicators",
    "complete",
)


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ThreatDatabaseError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ThreatDatabaseError(f"{label} must be a non-empty string")
    return value


def _sorted_unique_strings(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ThreatDatabaseError(f"{label} must be an array of non-empty strings")
    values = cast(list[str], value)
    if not values:
        raise ThreatDatabaseError(f"{label} must not be empty")
    if values != sorted(set(values)):
        raise ThreatDatabaseError(f"{label} must be sorted and unique")
    return values


def _version_mapping(
    value: object, label: str, *, allow_empty: bool = False
) -> dict[str, frozenset[str]]:
    mapping = _object(value, label)
    if not mapping and not allow_empty:
        raise ThreatDatabaseError(f"{label} must not be empty")
    result: dict[str, frozenset[str]] = {}
    for package, versions in mapping.items():
        if not package:
            raise ThreatDatabaseError(f"{label} contains an empty package name")
        result[package] = frozenset(
            _sorted_unique_strings(versions, f"{label}.{package}")
        )
    return result


def _hash_mapping(value: object) -> dict[str, str]:
    mapping = _object(value, "hashes")
    if not mapping:
        raise ThreatDatabaseError("hashes must not be empty")
    result: dict[str, str] = {}
    for digest, description in mapping.items():
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ThreatDatabaseError(f"hashes contains invalid SHA-256 key {digest!r}")
        result[digest] = _string(description, f"hashes.{digest}")
    return result


def _commit_indicators(value: object) -> tuple[dict[str, str], ...]:
    if not isinstance(value, list):
        raise ThreatDatabaseError("commit_indicators must be an array")
    if not value:
        raise ThreatDatabaseError("commit_indicators must not be empty")
    indicators: list[dict[str, str]] = []
    for index, item in enumerate(value):
        indicator = _object(item, f"commit_indicators[{index}]")
        for key in ("author", "email", "subject"):
            if key not in indicator:
                raise ThreatDatabaseError(
                    f"commit_indicators[{index}] is missing required key {key!r}"
                )
        indicators.append(
            {
                "author": _string(indicator["author"], f"commit_indicators[{index}].author"),
                "email": _string(indicator["email"], f"commit_indicators[{index}].email"),
                "subject": _string(
                    indicator["subject"], f"commit_indicators[{index}].subject"
                ),
            }
        )
    indicator_keys = [
        (item["author"], item["email"], item["subject"]) for item in indicators
    ]
    if indicator_keys != sorted(set(indicator_keys)):
        raise ThreatDatabaseError("commit_indicators must be sorted and unique")
    return tuple(indicators)


def _load_payload() -> dict[str, object]:
    try:
        raw = resources.files("agentsec.resources").joinpath("threat-db.json").read_text(
            encoding="utf-8"
        )
        loaded = cast(object, json.loads(raw))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ThreatDatabaseError(f"cannot load bundled threat database: {exc}") from exc
    payload = _object(loaded, "bundled threat database")
    for key in _REQUIRED_KEYS:
        if key not in payload:
            raise ThreatDatabaseError(f"missing required runtime key {key!r}")
    return payload


def load_bundled_database() -> ThreatDatabase:
    """Load and validate the generated threat database without fallback data."""

    payload = _load_payload()
    complete = payload["complete"]
    if complete is not True:
        raise ThreatDatabaseError("complete must be true for a bundled runtime database")
    return ThreatDatabase(
        version=_string(payload["version"], "version"),
        updated=_string(payload["updated"], "updated"),
        package_versions=_version_mapping(payload["package_versions"], "package_versions"),
        wildcard_package_versions=_version_mapping(
            payload["wildcard_package_versions"],
            "wildcard_package_versions",
            allow_empty=True,
        ),
        hashes=_hash_mapping(payload["hashes"]),
        domains=frozenset(_sorted_unique_strings(payload["domains"], "domains")),
        commit_indicators=_commit_indicators(payload["commit_indicators"]),
        complete=True,
    )
