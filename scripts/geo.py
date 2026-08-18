# -*- coding: utf-8 -*-
"""Resolve a server's real country from its network address, not its remark text.

Why: the old label came from the remark string, and its last step assumed any
two-letter Latin word was a country code. "join-us-on-Telegram" became US and
"55.26 GB" became GB. Accuracy on a 675 config sample, ground truth from
ip-api.com:

    old remark parsing   53.6% correct, 14.7% wrong, 31.7% gave up as "Global"
    this module          97.9% correct,  2.1% wrong,  0.0% gave up

A wrong flag is worse than no flag: someone who sees "US" and lands in Canada
is right to distrust every other number in the repo.

Database: DB-IP Country Lite, CC-BY-4.0, monthly, no account key. Chosen over
MaxMind GeoLite2, whose download has required an account key since 2019 (live
check: DB-IP 200, MaxMind 401). The download itself happens in the workflow's
"Download GeoIP database" step, which owns that URL; this module only reads the
file at MMDB_PATH and degrades gracefully when it is absent.

Label stability: 73.2% of hosts are IP literals, so their lookup is pure. The
rest need DNS, which is not stable. Over two back-to-back runs on 1,127 named
hosts, gethostbyname flipped the country for 25 hosts (2.22%) because it returns
one rotating round-robin address; taking the full sorted A-record set and voting
by majority flips 4 (0.35%). So the country is derived from the address *set*,
which is independent of response order.

Cost: 1,365 named hosts at 64 threads is ~4.9s, against a 15 minute refresh
interval. 75.8% of configs need no DNS at all.
"""

from __future__ import annotations

import collections
import contextlib
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

#: Database path. CI downloads and caches the file here.
MMDB_PATH = os.environ.get("GEOIP_MMDB", os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".cache", "dbip-country-lite.mmdb",
))

#: DNS concurrency. Measured: 64 threads -> 4.9s for 1,365 hosts; 128 threads
#: was slower (8.4s) because the upstream resolver is the bottleneck.
DNS_WORKERS = int(os.environ.get("GEO_DNS_WORKERS", "64"))

#: Per-lookup DNS budget, seconds.
DNS_TIMEOUT = float(os.environ.get("GEO_DNS_TIMEOUT", "4"))

#: Fallback flag for an unknown or malformed country code.
UNKNOWN_FLAG = "\N{GLOBE WITH MERIDIANS}"

_reader = None
_reader_tried = False
_reader_lock = threading.Lock()

#: Final verdict per host. normalised host -> (code, flag).
_HOST_CC: Dict[str, Tuple[str, str]] = {}

#: Resolved addresses per host, so one run never resolves the same host twice.
_HOST_ADDRS: Dict[str, Tuple[str, ...]] = {}

#: Hosts that were tried once and failed, i.e. the negative cache.
#:
#: Needed because warm_up() runs three times (all / heavy / light) and only
#: successes were cached, so every failing host was re-resolved and re-counted
#: each round. That reported dns_failed=924 out of 1,375 named hosts, i.e. the
#: stats over-counted. A host must be tried once and counted once.
#:
#: Only *host* failures belong here. A missing database is not the host's fault
#: and must stay retryable, see _label_batch().
_HOST_FAILED: Set[str] = set()

_stats: collections.Counter = collections.Counter()


# --------------------------------------------------------------------------- #
# Flag from ISO code
# --------------------------------------------------------------------------- #

def flag_of(code: str) -> str:
    """Unicode flag for an ISO-3166-1 alpha-2 code, computed not tabulated.

    The previous hand-written map covered 56 countries while live data contains
    84 distinct ones, so 32 (CY, IL, KZ, AM, MO, IS, MT, PH, ...) were
    unrepresentable. The regional-indicator formula removes the limit.
    """
    code = (code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return UNKNOWN_FLAG
    return chr(0x1F1E6 + ord(code[0]) - 65) + chr(0x1F1E6 + ord(code[1]) - 65)


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #

def _get_reader():
    """The mmdb reader, or None. Tries once and never raises.

    A missing auxiliary database must not stop config publication, so failure
    degrades the module instead of breaking the run.

    Uses `maxminddb` rather than `geoip2`: geoip2 is a model layer that drags in
    aiohttp and requests for what is one "IP -> country code" lookup. Checked on
    all 3,720 real IP literals in this repo: 3,720/3,720 identical verdicts, and
    maxminddb was 1.82x faster (31.4ms vs 57.1ms).
    """
    global _reader, _reader_tried
    if _reader is not None or _reader_tried:
        return _reader
    with _reader_lock:
        if _reader is not None or _reader_tried:
            return _reader
        _reader_tried = True
        try:
            import maxminddb  # type: ignore
            if os.path.exists(MMDB_PATH) and os.path.getsize(MMDB_PATH) > 1024:
                _reader = maxminddb.open_database(MMDB_PATH)
                _stats["db_loaded"] = 1
        except Exception:  # noqa: BLE001 - optional dependency, degrade quietly
            _reader = None
    return _reader


def database_available() -> bool:
    """Whether the database loaded. Reported in health.json."""
    return _get_reader() is not None


def country_of_ip(ip: str) -> Optional[str]:
    """Country code for an IP, or None.

    Reads the record directly. DB-IP Country Lite shape, of which only one key
    matters::

        {"continent": {...}, "country": {"iso_code": "DE", "names": {...}}}

    Both "not in the database" and "private address" reach None naturally, so
    callers fall back to Global without an exception escaping.
    """
    reader = _get_reader()
    if reader is None or not ip:
        return None
    try:
        record = reader.get(ip)
        if not record:
            return None
        return ((record.get("country") or {}).get("iso_code")) or None
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #

@contextlib.contextmanager
def _dns_timeout():
    """Apply DNS_TIMEOUT for this block only, then restore the previous value.

    `socket.getaddrinfo` takes no timeout argument, so the only lever is the
    global `setdefaulttimeout`. That setting is per *process*, not per thread.
    resolve_all() used to set it and never restore it, so every socket created
    after the first DNS lookup inherited it (measured: None -> 4.0).

    The restore must wrap the thread pool, not live inside the worker: workers
    all set the same value, so one worker's `prev` can be another worker's
    value. Measured: the in-worker pattern leaked 6 out of 6 trials, this one 0
    out of 6. `reachability.resolve_hosts` already did it this way; the two
    modules now behave the same.
    """
    prev = socket.getdefaulttimeout()
    socket.setdefaulttimeout(DNS_TIMEOUT)
    try:
        yield
    finally:
        socket.setdefaulttimeout(prev)


def is_ip_literal(host: str) -> bool:
    """Whether the host is already an IP address, v4 or v6."""
    host = (host or "").strip()
    if not host:
        return False
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


def resolve_all(host: str) -> Tuple[str, ...]:
    """Every IPv4 address of a host, sorted.

    Sorting is deliberate: round-robin DNS returns a different order per call,
    so sorting makes the result a function of the record *set*.

    Does not touch `setdefaulttimeout`; this runs inside a thread pool and
    mutating global state from a worker races. Timeouts are the caller's job via
    ``with _dns_timeout():``.
    """
    host = (host or "").strip().lower()
    if not host:
        return ()
    if host in _HOST_ADDRS:
        return _HOST_ADDRS[host]
    if is_ip_literal(host):
        _HOST_ADDRS[host] = (host,)
        return (host,)
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        addrs = tuple(sorted({info[4][0] for info in infos}))
    except Exception:  # noqa: BLE001
        addrs = ()
    _HOST_ADDRS[host] = addrs
    return addrs


def country_of_addrs(addrs: Iterable[str]) -> Optional[str]:
    """Country for an address set, by majority vote.

    Some CDNs answer with addresses in several countries. "First address" is
    unstable, a majority is stable. Ties break on the lowest IP so the result
    never depends on input order.
    """
    votes: collections.Counter = collections.Counter()
    first: Dict[str, str] = {}
    for ip in sorted(set(addrs)):
        code = country_of_ip(ip)
        if code:
            votes[code] += 1
            first.setdefault(code, ip)
    if not votes:
        return None
    top = max(votes.values())
    winners = [code for code, count in votes.items() if count == top]
    return sorted(winners, key=lambda code: first[code])[0]


# --------------------------------------------------------------------------- #
# Warm-up
# --------------------------------------------------------------------------- #

def _remember(host: str, code: Optional[str], success_stat: str,
              failure_stat: str) -> None:
    """Cache one verdict, positive or negative, and count it exactly once."""
    if code:
        _HOST_CC[host] = (code, flag_of(code))
        _stats[success_stat] += 1
    else:
        _HOST_FAILED.add(host)
        _stats[failure_stat] += 1


def _resolve_batch(hosts: Sequence[str]) -> List[Tuple[str, ...]]:
    """Resolve hosts concurrently, falling back to serial on pool failure."""
    try:
        with _dns_timeout():
            with ThreadPoolExecutor(max_workers=max(1, DNS_WORKERS)) as pool:
                return list(pool.map(resolve_all, hosts))
    except Exception:  # noqa: BLE001
        with _dns_timeout():
            return [resolve_all(host) for host in hosts]


def _label_literals(hosts: Sequence[str]) -> None:
    """Label IP literals. No network needed, only the database."""
    for host in hosts:
        _HOST_ADDRS[host] = (host,)
        _remember(host, country_of_ip(host), "by_ip_literal", "unknown_ip_literal")


def _label_named(hosts: Sequence[str]) -> None:
    """Label named hosts via concurrent DNS plus a majority vote."""
    for host, addrs in zip(hosts, _resolve_batch(hosts)):
        if not addrs:
            _HOST_FAILED.add(host)
            _stats["dns_failed"] += 1
            continue
        _remember(host, country_of_addrs(addrs), "by_dns", "unknown_after_dns")


def warm_up(hosts: Iterable[str]) -> Dict[str, int]:
    """Label every host up front, concurrently.

    The pipeline calls this once before branding. Labelling lazily instead would
    serialise 1,365 DNS lookups (measured at over 10 minutes) against 4.9s here.
    """
    pending: Set[str] = set()
    for host in hosts:
        host = (host or "").strip().lower()
        # Skip both successes and known failures: the second pass needs neither
        # a fresh lookup nor a fresh count.
        if host and host not in _HOST_CC and host not in _HOST_FAILED:
            pending.add(host)
    if not pending:
        return dict(_stats)

    ordered = sorted(pending)  # deterministic order
    literals = [host for host in ordered if is_ip_literal(host)]
    named = [host for host in ordered if not is_ip_literal(host)]

    # Without the database nothing can be labelled, and that is not the hosts'
    # fault: record it as skipped and leave the negative cache alone so a
    # database that arrives later can still label them.
    if _get_reader() is None:
        _stats["skipped_no_db"] += len(ordered)
        return dict(_stats)

    _label_literals(literals)
    if named:
        _label_named(named)
    return dict(_stats)


def country_for_host(host: str) -> Optional[Tuple[str, str]]:
    """``(code, flag)`` for a host, or None if it could not be determined.

    Works standalone when warm_up() was never called, so scattered callers and
    tests still get an answer. It records stats on this path too: otherwise a
    host labelled here would be invisible in health.json and the totals would
    silently disagree with the real host count.
    """
    host = (host or "").strip().lower()
    if not host:
        return None
    cached = _HOST_CC.get(host)
    if cached is not None:
        return cached
    # Negative cache: a host that failed once is neither re-asked nor re-counted.
    if host in _HOST_FAILED:
        return None
    if _get_reader() is None:
        _stats["skipped_no_db"] += 1
        return None

    literal = is_ip_literal(host)
    with _dns_timeout():
        addrs = resolve_all(host)
    if not addrs:
        _HOST_FAILED.add(host)
        _stats["dns_failed"] += 1
        return None
    code = country_of_addrs(addrs)
    if not code:
        _HOST_FAILED.add(host)
        _stats["unknown_ip_literal" if literal else "unknown_after_dns"] += 1
        return None
    result = (code, flag_of(code))
    _HOST_CC[host] = result
    _stats["by_ip_literal" if literal else "by_dns"] += 1
    return result


#: Keys always present in stats(), even at zero.
#
# Fixed schema because health.json is parsed by outside tools. If a key appeared
# only when non-zero, "dns_failed missing" and "dns_failed == 0" would look the
# same, while the first means nothing was measured and the second means all good.
_STAT_KEYS = (
    "db_loaded",
    "by_ip_literal",
    "unknown_ip_literal",
    "by_dns",
    "dns_failed",
    "unknown_after_dns",
    "skipped_no_db",
)


def stats() -> Dict[str, int]:
    """Work counters for health.json.

    Fixed shape, plus two derived totals so consumers do not re-add them::

        hosts_resolved  hosts that got a country label
        hosts_unknown   hosts that did not, for any reason
    """
    out = {key: int(_stats.get(key, 0)) for key in _STAT_KEYS}
    out["db_loaded"] = 1 if _get_reader() is not None else 0
    out["hosts_resolved"] = out["by_ip_literal"] + out["by_dns"]
    out["hosts_unknown"] = (
        out["unknown_ip_literal"] + out["unknown_after_dns"]
        + out["dns_failed"] + out["skipped_no_db"]
    )
    return out


def reset() -> None:
    """Clear all caches. For tests that must not leak state into each other."""
    _HOST_CC.clear()
    _HOST_ADDRS.clear()
    _HOST_FAILED.clear()
    _stats.clear()
    if _get_reader() is not None:
        _stats["db_loaded"] = 1
