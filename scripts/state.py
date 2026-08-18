# -*- coding: utf-8 -*-
"""Cross-round memory for the pipeline.

Why it exists: a source that answers HTTP 200 with plenty of configs can still
be worthless if every config is a duplicate of another feed. Measured example,
Eternity.txt is a 100% strict subset of sub_merge.txt, and nine
V2RAYCONFIGSPOOL feeds contribute 56 unique configs out of 8,043. So the retire
signal has to be *unique* yield per round, remembered across rounds.

Design guarantees
    fail-open      nothing in this file may break a healthy round; corrupt
                   memory degrades to empty memory plus a warning.
    bounded growth every history array is capped at MAX_HISTORY.
    stable keys    a source is keyed by sha256(url)[:12], so reordering
                   sources.py never loses history.
    atomic writes  tmp file + os.replace, so a concurrent round never reads a
                   half-written file.

Note: ``state.json`` must be listed in the workflow's OUTPUT_PATHS, otherwise
the rolling squash drops it from the snapshot and memory resets every round.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

#: Schema version. Anything else is treated as unknown and rebuilt from zero.
SCHEMA = 1

#: Cap on every history array. This is where bounded growth comes from.
MAX_HISTORY = 20

#: Minimum rounds of evidence before any auto-disable decision.
MIN_ROUNDS = 10

#: Never take the active source count below this.
MIN_ACTIVE = 8

#: Published filename.
STATE_PATH = "state.json"


def source_key(url: str) -> str:
    """Stable, content-addressed key for a source URL."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _str_or(value: Any, default: Optional[str] = None) -> Optional[str]:
    return value if isinstance(value, str) else default


def _int_or(value: Any, default: int = 0) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def empty_state() -> Dict[str, Any]:
    """A valid empty memory. Returned on every failure path."""
    return {"schema": SCHEMA, "updated_at": _now_iso(), "round": 0, "sources": {}}


def _clip(seq: Any, n: int = MAX_HISTORY) -> List[int]:
    """Last ``n`` integers of a sequence; anything non-numeric is dropped.

    Enforces bounded growth and neutralises a hand-edited state.json that
    carries a 10,000 element history.
    """
    if not isinstance(seq, list):
        return []
    out: List[int] = []
    for value in seq:
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            out.append(value)
        elif isinstance(value, float) and value == int(value):
            out.append(int(value))
    return out[-n:] if n > 0 else []


def _new_entry(url: str, tier: str = "unknown") -> Dict[str, Any]:
    """Canonical shape of one source entry. Single source of truth."""
    return {
        "url": url,
        "tier": tier,
        "rounds": 0,
        "last_seen": None,
        "yield": [],
        "unique": [],
        "fail": 0,
        "disabled_since": None,
        "reason": None,
    }


def _normalize_entry(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Coerce an untrusted entry into :func:`_new_entry` shape, or reject it."""
    url = entry.get("url")
    if not isinstance(url, str) or "://" not in url:
        return None
    clean = _new_entry(url, _str_or(entry.get("tier"), "unknown") or "unknown")
    clean.update(
        rounds=_int_or(entry.get("rounds")),
        last_seen=_str_or(entry.get("last_seen")),
        fail=_int_or(entry.get("fail")),
        disabled_since=_str_or(entry.get("disabled_since")),
        reason=_str_or(entry.get("reason")),
    )
    clean["yield"] = _clip(entry.get("yield"))
    clean["unique"] = _clip(entry.get("unique"))
    return clean


def load_state(path: str = STATE_PATH) -> Dict[str, Any]:
    """Read memory. Never raises.

    Missing file, unparsable JSON, unknown schema, or a wrong top-level type
    all yield an empty memory plus a warning on stdout.
    """
    if not os.path.exists(path):
        print(f"\N{BRAIN} no {path} yet - starting with an empty memory (first round)")
        return empty_state()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception as exc:  # noqa: BLE001 - intentionally broad, fail-open
        print(f"\N{WARNING SIGN} {path} is unreadable ({type(exc).__name__}) - "
              f"falling back to an empty memory instead of failing the round")
        return empty_state()
    if not isinstance(raw, dict):
        print(f"\N{WARNING SIGN} {path} is a {type(raw).__name__}, not an object - empty memory")
        return empty_state()
    if raw.get("schema") != SCHEMA:
        print(f"\N{WARNING SIGN} {path} has schema={raw.get('schema')!r}, expected {SCHEMA} - "
              f"rebuilding memory from scratch")
        return empty_state()
    sources = raw.get("sources")
    if not isinstance(sources, dict):
        print(f"\N{WARNING SIGN} {path} has no usable 'sources' object - empty memory")
        return empty_state()

    clean: Dict[str, Dict[str, Any]] = {}
    for key, entry in sources.items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            continue
        normalized = _normalize_entry(entry)
        if normalized is not None:
            clean[key] = normalized

    round_no = _int_or(raw.get("round"), -1)
    return {
        "schema": SCHEMA,
        "updated_at": _str_or(raw.get("updated_at")) or _now_iso(),
        "round": round_no if round_no >= 0 else 0,
        "sources": clean,
    }


def save_state(state: Dict[str, Any], path: str = STATE_PATH) -> bool:
    """Write memory atomically. Returns False on failure and never raises."""
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"\N{WARNING SIGN} could not write {path} ({type(exc).__name__}) - "
              f"this round still succeeds, memory just does not advance")
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


def record_round(state: Dict[str, Any],
                 per_source: Dict[str, Dict[str, Any]],
                 live_urls: List[str]) -> Dict[str, Any]:
    """Record one round and garbage-collect keys that left ``sources.py``.

    ``per_source[url] = {"tier": str, "total": int, "unique": int}``.
    Keys whose URL is absent from ``live_urls`` are dropped, otherwise memory
    accumulates garbage on every list edit and the growth bound is meaningless.
    """
    live_keys = {source_key(url) for url in live_urls}
    sources = {key: entry for key, entry in state.get("sources", {}).items()
               if key in live_keys}

    now = _now_iso()
    for url, observed in per_source.items():
        key = source_key(url)
        if key not in live_keys:
            continue
        entry = sources.get(key) or _new_entry(url, observed.get("tier", "unknown"))
        total = _int_or(observed.get("total"))
        unique = _int_or(observed.get("unique"))
        entry["url"] = url
        entry["tier"] = observed.get("tier", entry.get("tier", "unknown"))
        entry["yield"] = _clip(list(entry.get("yield", [])) + [total])
        entry["unique"] = _clip(list(entry.get("unique", [])) + [unique])
        entry["rounds"] = _int_or(entry.get("rounds")) + 1
        entry["last_seen"] = now
        entry["fail"] = _int_or(entry.get("fail")) + (1 if total == 0 else 0)
        sources[key] = entry

    state["schema"] = SCHEMA
    state["sources"] = sources
    state["round"] = _int_or(state.get("round")) + 1
    state["updated_at"] = now
    return state


def disable_candidates(state: Dict[str, Any],
                       current_unique: Dict[str, int],
                       union_size: int) -> Dict[str, str]:
    """Sources that are *allowed* to be disabled, as ``{url: reason}``.

    All conditions must hold:
      1. ``rounds >= MIN_ROUNDS``, so no decision on thin evidence.
      2. the last ``MIN_ROUNDS`` unique-yield values are all zero.
      3. this round's unique yield is zero, zero tolerance. Today's data gets
         veto power over history, so a dormant source that suddenly brings
         unique content is not punished for its past.
      4. global floor: the active count never drops below ``MIN_ACTIVE``.

    Condition 1 looks implied by condition 2, because normally
    ``len(unique) == min(rounds, MAX_HISTORY)``. It is not: state.json arrives
    via force-push and is editable, so ``rounds: 3`` with ten zeros loads fine
    and condition 1 is the only guard there.

    Disabling is sticky. A rejected source is no longer fetched, so it cannot
    produce fresh evidence to clear itself; recovery is manual, by deleting its
    entry from the published state.json (which also carries ``reason``).

    ``union_size`` is accepted for call-site compatibility and telemetry; the
    decision is share-free on purpose. An earlier fractional threshold
    (``today / union > 0.005``) was provably unreachable behind the harder
    ``today > 0`` guard, so it was removed rather than tested around.
    """
    sources = state.get("sources", {})
    active = [key for key, entry in sources.items() if not entry.get("disabled_since")]
    eligible: List[Tuple[str, int]] = []

    for key in active:
        entry = sources[key]
        rounds = _int_or(entry.get("rounds"))
        history = _clip(entry.get("unique"), MIN_ROUNDS)
        if rounds < MIN_ROUNDS:
            continue
        if len(history) < MIN_ROUNDS or any(value != 0 for value in history):
            continue
        if _int_or(current_unique.get(entry["url"])) > 0:
            continue  # condition 3, today vetoes history
        eligible.append((key, rounds))

    # Global floor. Retire the longest-running dead weight first, but never go
    # below MIN_ACTIVE.
    budget = max(0, len(active) - MIN_ACTIVE)
    eligible.sort(key=lambda item: -item[1])
    return {
        sources[key]["url"]: (
            f"zero unique yield in the last {MIN_ROUNDS} of {rounds} rounds, "
            f"and zero again this round"
        )
        for key, rounds in eligible[:budget]
    }


def mark_disabled(state: Dict[str, Any], reasons: Dict[str, str]) -> Dict[str, Any]:
    """Stamp the decided sources as disabled."""
    now = _now_iso()
    for url, why in reasons.items():
        entry = state.get("sources", {}).get(source_key(url))
        if entry is not None and not entry.get("disabled_since"):
            entry["disabled_since"] = now
            entry["reason"] = why
    return state


def disabled_urls(state: Dict[str, Any]) -> List[str]:
    """URLs memory says to skip."""
    return [entry["url"] for entry in state.get("sources", {}).values()
            if entry.get("disabled_since") and isinstance(entry.get("url"), str)]


def summary(state: Dict[str, Any]) -> str:
    """One readable line for the round log."""
    sources = state.get("sources", {})
    off = sum(1 for entry in sources.values() if entry.get("disabled_since"))
    return (f"\N{BRAIN} memory: round={state.get('round', 0)} "
            f"sources={len(sources)} disabled={off}")
