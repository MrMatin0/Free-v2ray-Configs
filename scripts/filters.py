# -*- coding: utf-8 -*-
"""L0/L1 of the verification cascade: de-duplication plus cheap offline checks.

Pipeline position::

    all/configs.txt -> [L0 dedup] -> [L1 cheap filter] -> L2 (TCP) -> L3 (proxy)

L3 spins up a real proxy and issues an HTTP request per config, so anything
decidable *without* the network has to die here.

Why L0 exists: on a real 8,028 config snapshot there are only 6,940 unique
(host, port) endpoints and 5,068 unique hosts, so ~13.6% of the network work
is duplicated. L2/L3 therefore operate on endpoints, not on config lines.

House rule: the parser is the judge, never a regex. Ad-hoc ``grep``/``rsplit``
parsing produced wrong numbers every time (bare IPv6 gets truncated by
``rsplit(':', 1)``, base64 vmess has no remark, ``vmess://`` has two shapes).
This module always asks ``converters.parse_proxy()`` and reuses the server
checks that live in ``converters`` instead of re-implementing them.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

import converters

#: Protocols where ``uuid`` identifies a user. shadowsocks/trojan/hysteria2 use
#: a free-form password, so judging their id is meaningless.
UUID_PROTOCOLS = frozenset({"vless", "vmess", "tuic"})

#: Canonical dashed UUID, 8-4-4-4-12 hex digits.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

#: Compact 32-hex UUID. It is 32 bytes so it exceeds the custom-string budget
#: below and must be allowed explicitly; sing-box and mihomo both accept it.
_UUID_RE_COMPACT = re.compile(r"^[0-9a-fA-F]{32}$")

#: Xray accepts "any string less than 30 bytes, or a valid UUID" for VLESS and
#: VMess user ids and maps custom strings to a UUIDv5. Requiring a canonical
#: UUID dropped 113 working configs (e.g. '@free_conf_iran', 'AlfredConfig').
_CUSTOM_ID_MAX_BYTES = 30

#: All-zero UUID: well formed, but an upstream placeholder, never a real user.
_NIL_UUID_HEX = "0" * 32

# Drop reasons. These strings ship inside health.json, so renaming one is a
# breaking change.
REASON_UNPARSABLE = "unparsable"
REASON_INVALID_PORT = "invalid_port"
REASON_INVALID_UUID = "invalid_uuid"
REASON_UNROUTABLE = "unroutable_server"
REASON_INVALID_SERVER = "invalid_server"

ALL_REASONS = (
    REASON_UNPARSABLE,
    REASON_INVALID_PORT,
    REASON_INVALID_UUID,
    REASON_UNROUTABLE,
    REASON_INVALID_SERVER,
)


def _as_port(value: Any) -> Optional[int]:
    """Parse a TCP port, or ``None`` when it is not a usable one.

    Port 0 is rejected on purpose: it is reserved and nothing listens on it.
    """
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def is_invalid_port(port: Any) -> bool:
    """True when ``port`` is outside the usable TCP range 1..65535."""
    return _as_port(port) is None


def is_invalid_uuid(uuid: Any, proto: str) -> bool:
    """True when a user id is invalid *per the Xray spec* for ``proto``.

    An id is valid when it is a canonical UUID, a compact 32-hex UUID, or a
    custom string shorter than 30 bytes. So only three things fail: an empty
    id, a non-UUID string of 30 bytes or more, and the nil UUID.

    Always False outside :data:`UUID_PROTOCOLS`, where the field is a password.
    """
    if proto not in UUID_PROTOCOLS:
        return False
    ident = str(uuid or "").strip()
    if not ident:
        return True
    if _UUID_RE.match(ident) or _UUID_RE_COMPACT.match(ident):
        return ident.replace("-", "").lower() == _NIL_UUID_HEX
    return len(ident.encode("utf-8")) >= _CUSTOM_ID_MAX_BYTES


def endpoint_of_proxy(p: Dict[str, Any]) -> Optional[Tuple[str, int]]:
    """``(host, port)`` for a parsed proxy, or ``None`` if it is unusable.

    IPv6 brackets are stripped: L2 passes the host to ``getaddrinfo`` /
    ``open_connection``, which want the bare address rather than URI syntax.
    """
    host = str(p.get("server") or "").strip().strip("[]").lower()
    port = _as_port(p.get("port"))
    if not host or port is None:
        return None
    return host, port


def classify(line: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Judge one line: ``(proxy, None)`` on pass, ``(None, reason)`` on drop.

    Gates run cheapest first and the first hit is reported, so the counters
    stay attributable: unparsable, bad port, malformed server, unroutable
    server, malformed uuid.
    """
    proxy = converters.parse_proxy(line)
    if not proxy:
        return None, REASON_UNPARSABLE
    if is_invalid_port(proxy.get("port")):
        return None, REASON_INVALID_PORT
    server = proxy.get("server")
    # Deliberate reuse: both rules are owned by `converters`. One rule in two
    # places becomes two diverging rules.
    if converters._is_structurally_invalid_server(server):
        return None, REASON_INVALID_SERVER
    if converters._is_unroutable_server(server):
        return None, REASON_UNROUTABLE
    if is_invalid_uuid(proxy.get("uuid"), str(proxy.get("type") or "")):
        return None, REASON_INVALID_UUID
    return proxy, None


class _EndpointIndex:
    """Accumulates kept lines and the endpoint <-> line mapping around them."""

    def __init__(self) -> None:
        self.kept: List[str] = []
        self.endpoints: List[Tuple[str, int]] = []
        self.ep_to_lines: Dict[Tuple[str, int], List[int]] = {}
        self.line_endpoint: List[Tuple[str, int]] = []

    def add(self, line: str, endpoint: Tuple[str, int]) -> None:
        index = len(self.kept)
        self.kept.append(line)
        self.line_endpoint.append(endpoint)
        if endpoint not in self.ep_to_lines:
            self.endpoints.append(endpoint)
            self.ep_to_lines[endpoint] = []
        self.ep_to_lines[endpoint].append(index)

    @property
    def unique_hosts(self) -> int:
        return len({host for host, _ in self.endpoints})


def _stats(index: _EndpointIndex, total: int, dropped_total: int) -> Dict[str, Any]:
    kept = len(index.kept)
    unique = len(index.endpoints)
    return {
        "input": total,
        "kept": kept,
        "dropped": dropped_total,
        "endpoints_unique": unique,
        "hosts_unique": index.unique_hosts,
        "removal_pct": round(100.0 * dropped_total / total, 2) if total else 0.0,
        "dedup_saving_pct": round(100.0 * (1 - unique / kept), 2) if kept else 0.0,
    }


def filter_lines(lines: Iterable[str]) -> Dict[str, Any]:
    """Run L0 + L1 over a sequence of lines.

    Returned keys are part of the ``health.json`` contract::

        kept          lines that passed L1, input order preserved
        endpoints     unique (host, port) in first-seen order
        ep_to_lines   endpoint -> indices into `kept`
        line_endpoint index into `kept` -> endpoint
        dropped       {reason: count}, every reason present even at zero
        stats         summary counters for telemetry
    """
    index = _EndpointIndex()
    dropped: Dict[str, int] = {reason: 0 for reason in ALL_REASONS}
    total = 0

    for raw in lines:
        line = (raw or "").strip()
        # Blank lines and comment headers are not configs; counting them
        # inflates every downstream percentage.
        if not line or line.startswith("#"):
            continue
        total += 1
        proxy, reason = classify(line)
        if reason is not None:
            dropped[reason] += 1
            continue
        endpoint = endpoint_of_proxy(proxy or {})
        if endpoint is None:
            # Unreachable while `classify` and `endpoint_of_proxy` agree. Kept
            # as a visible counter rather than a silent `continue` so any future
            # divergence shows up in the stats instead of hiding.
            dropped[REASON_INVALID_PORT] += 1
            continue
        index.add(line, endpoint)

    dropped_total = sum(dropped.values())
    return {
        "kept": index.kept,
        "endpoints": index.endpoints,
        "ep_to_lines": index.ep_to_lines,
        "line_endpoint": index.line_endpoint,
        "dropped": dropped,
        "stats": _stats(index, total, dropped_total),
    }


def filter_file(path: str) -> Dict[str, Any]:
    """:func:`filter_lines` over a file. Lenient decoding: this is upstream data."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        return filter_lines(fh)


if __name__ == "__main__":  # pragma: no cover - CLI helper
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "all/configs.txt"
    result = filter_file(target)
    print(json.dumps({"stats": result["stats"], "dropped": result["dropped"]},
                     ensure_ascii=False, indent=2))
