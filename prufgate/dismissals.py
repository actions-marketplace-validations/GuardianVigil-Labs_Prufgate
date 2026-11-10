"""Version-controlled, append-only requests and reviewed finding dismissals."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import uuid
from pathlib import Path, PurePosixPath
from typing import Optional

from prufgate.baseline import PROTECTED_RULES, canonical_rule
from prufgate.config import _diff_base, git_blob, repo_prefix
from prufgate.privacy import redact_data
from prufgate.result_validation import read_json
from prufgate.safe_fs import exclusive_lock, safe_read_text, safe_write_text

LEDGER = ".prufgate/dismissals.json"
ZERO = "0" * 64
REQUEST_KEYS = {"rule", "file", "fingerprint", "owner", "expires"}
COMMON_KEYS = {"id", "dismissal_id", "action", "actor", "reason", "at", "previous", "hash"}


class DismissalError(ValueError):
    pass


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def digest(event: dict) -> str:
    return hashlib.sha256(json.dumps({k: v for k, v in event.items() if k != "hash"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _text(value, name: str) -> str:
    if not isinstance(value, str) or len(value.strip()) < 3 or len(value) > 1000 or any(ord(c) < 32 for c in value):
        raise DismissalError(f"dismissal {name} must be a non-empty label/reason (3–1000 characters)")
    return value.strip()


def parse(text: Optional[str], today: Optional[dt.date] = None) -> tuple[list[dict], dict[str, dict]]:
    if text is None:
        return [], {}
    data = read_json(text)
    if not isinstance(data, dict) or set(data) != {"version", "events"} or type(data["version"]) is not int or data["version"] != 1 or not isinstance(data["events"], list):
        raise DismissalError("dismissals must be a version 1 event ledger")
    if len(data["events"]) > 10000:
        raise DismissalError("dismissal ledger exceeds 10000 events; archive it through maintainer review")
    previous, seen, states = ZERO, set(), {}
    last_at = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    for event in data["events"]:
        if not isinstance(event, dict):
            raise DismissalError("invalid dismissal event")
        action = event.get("action")
        expected = COMMON_KEYS | REQUEST_KEYS if action == "requested" else COMMON_KEYS
        if set(event) != expected or action not in ("requested", "approved", "rejected", "revoked"):
            raise DismissalError("invalid dismissal event fields or action")
        for key in ("id", "dismissal_id", "actor", "reason"):
            _text(event[key], key)
        if event["previous"] != previous or event["hash"] != digest(event) or event["id"] in seen:
            raise DismissalError("dismissal audit chain is invalid")
        seen.add(event["id"])
        previous = event["hash"]
        try:
            stamp = dt.datetime.fromisoformat(event["at"])
            if stamp.tzinfo is None or stamp < last_at:
                raise ValueError("invalid ordering")
        except (ValueError, TypeError):
            raise DismissalError("dismissal timestamps must be ordered timezone-aware ISO timestamps") from None
        last_at = stamp
        key = event["dismissal_id"]
        if action == "requested":
            if key in states or key != event["id"]:
                raise DismissalError("duplicate dismissal request")
            for name in ("rule", "file", "fingerprint", "owner"):
                _text(event[name], name)
            path = PurePosixPath(event["file"])
            if path.is_absolute() or ".." in path.parts or "\\" in event["file"] or not re.fullmatch(r"[0-9a-f]{16}:\d+", event["fingerprint"]):
                raise DismissalError("dismissals require an exact relative file and finding fingerprint")
            if canonical_rule(event["rule"]) in PROTECTED_RULES:
                raise DismissalError("gate integrity findings cannot be dismissed")
            expires = event["expires"]
            if expires is not None:
                try:
                    dt.date.fromisoformat(expires)
                except (ValueError, TypeError):
                    raise DismissalError("dismissal expiration must be YYYY-MM-DD") from None
            states[key] = {**event, "state": "pending", "requested_by": event["actor"], "history": [event]}
        else:
            state = states.get(key)
            if state is None or (action in ("approved", "rejected") and state["state"] != "pending") or (action == "revoked" and state["state"] != "approved"):
                raise DismissalError("invalid dismissal review transition")
            if action == "approved" and event["actor"].strip().casefold() == state["requested_by"].strip().casefold():
                raise DismissalError("requesters cannot approve their own dismissal")
            state.update(state=action, reviewed_by=event["actor"], review_reason=event["reason"])
            state["history"].append(event)
    day = today or now().date()
    for state in states.values():
        if state["expires"] and dt.date.fromisoformat(state["expires"]) < day and state["state"] == "approved":
            state["state"] = "expired"
    return data["events"], states


def load(root: Path, ref: Optional[str] = None) -> tuple[list[dict], dict[str, dict]]:
    if ref:
        commit = _diff_base(ref, root)
        text = git_blob(commit, repo_prefix(root) + LEDGER, root)
    else:
        path = root / LEDGER
        text = safe_read_text(path) if path.exists() else None
    return parse(text)


def append(root: Path, action: str, actor: str, reason: str, *, dismissal_id: Optional[str] = None,
           finding: Optional[dict] = None, owner: Optional[str] = None, expires: Optional[str] = None) -> dict:
    """Write only a local event. Identity labels require version-control review."""
    root = root.resolve()
    try:
        with exclusive_lock(root / (LEDGER + ".lock")):
            events, _ = load(root)
            uid = str(uuid.uuid4())
            event = {"id": uid, "dismissal_id": uid if action == "requested" else dismissal_id,
                     "action": action, "actor": _text(actor, "actor"), "reason": _text(reason, "reason"),
                     "at": now().isoformat(), "previous": events[-1]["hash"] if events else ZERO}
            if action == "requested":
                if not finding:
                    raise DismissalError("a request must select a finding from a result file")
                event.update(rule=finding["rule"], file=finding["file"], fingerprint=finding["fingerprint"], owner=_text(owner, "owner"), expires=expires)
                if expires and dt.date.fromisoformat(expires) < now().date():
                    raise DismissalError("a new request cannot already be expired")
            previous = event.pop("previous")
            event = redact_data(event)
            event["previous"] = previous  # Structural digests are not provider credentials.
            event["hash"] = digest(event)
            text = json.dumps({"version": 1, "events": [*events, event]}, indent=2) + "\n"
            parse(text)
            safe_write_text(root / LEDGER, text)
            return event
    except OSError as exc:
        raise DismissalError(f"could not safely update dismissal ledger ({exc.__class__.__name__}); a lock may already exist") from exc


def apply(findings: list[dict], root: Path, ref: Optional[str]) -> tuple[list[dict], dict]:
    events, states = load(root, ref)
    head_events, _ = load(root)
    if ref and head_events[:len(events)] != events:
        raise DismissalError("the branch rewrites dismissal history from the trusted base")
    kept, dismissed = [], []
    for item in findings:
        match = next((state for state in states.values() if state["state"] == "approved"
                      and state["file"] == item["file"] and canonical_rule(state["rule"]) == canonical_rule(item["rule"])
                      and state["fingerprint"] == item["fingerprint"]), None)
        if match:
            dismissed.append({**item, "kind": "reviewed-dismissal", "dismissal_id": match["dismissal_id"],
                              "reason": match["reason"], "owner": match["owner"], "expires": match["expires"], "reviewed_by": match["reviewed_by"]})
        else:
            kept.append(item)
    pending = head_events[len(events):] if ref else []
    return kept, {"dismissed": dismissed, "audit": events,
                  "states": [{k: v for k, v in state.items() if k != "history"} for state in states.values()],
                  "pending_changes": len(pending), "applied_ref": ref, "ledger": LEDGER}
