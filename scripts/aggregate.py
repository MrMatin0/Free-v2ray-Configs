#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Main aggregation pipeline for the @Raydikalx config repo.

Flow (no TCP connect happens here, that is the cascade's job)::

    1. fetch all sources concurrently (light + heavy)
    2. extract valid configs from each source (direct or base64)
    3. for ALL / HEAVY / LIGHT: drop dummies, dedup (CDN aware), brand remarks
    4. write outputs:
         all|heavy|light/  configs.txt, configs_base64.txt, clash.yaml, singbox.json
         protocols/        vless.txt, vmess.txt, ... (from the ALL category)
         archive/          <cat>_broken.txt (+ base64)
         index.json        machine-readable metadata
         health.json       per-source health and gate telemetry

Usage::

    python scripts/aggregate.py --out <output_dir>
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

import requests

# Allow imports whether run from the repo root or from scripts/.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import converters  # noqa: E402
import core  # noqa: E402
import state as memory  # noqa: E402
from sources import HEAVY_SOURCES, LIGHT_SOURCES  # noqa: E402

# geo is optional: without the GeoIP database or its library the pipeline must
# still work exactly as before, only with weaker labels. So this import must
# never abort the run.
try:
    import geo  # noqa: E402
except Exception:  # pragma: no cover - environment without geo
    geo = None  # type: ignore

# --------------------------------------------------------------------------- #
# Link bases, published in index.json
#
# raw is primary and jsDelivr is the mirror, from measurement not taste:
#   raw.githubusercontent -> cache-control: max-age=300      (5 minutes)
#   cdn.jsdelivr.net      -> cache-control: s-maxage=43200   (12 hours)
# In a live check jsDelivr served a 12h45m old snapshot (4,353 configs) while raw
# served the fresh one (8,168), i.e. 51x the 15 minute target interval. So aiming
# for 15 minute updates was pointless for anyone subscribed via jsDelivr. The
# mirror stays for users who cannot reach raw, and is purged every round.
#
# Outputs are published on the default branch. An earlier revision moved them to
# a separate `data` branch to keep main's history small. That was right about git
# size and wrong about the product: the repo front page went empty, every link
# users had already copied (.../main/all/configs.txt) 404'd, and search engines
# only index the default branch. Size is instead handled by (1) stable output, so
# each publish diff is small, and (2) a rolling squash in the workflow, so only
# one output commit exists at a time.
#
# The branch is not hard-coded so tests and the workflow can override it.
# --------------------------------------------------------------------------- #
GH_USER = os.environ.get("AGG_GH_USER", "0xRadikal")
GH_REPO = os.environ.get("AGG_GH_REPO", "Free-v2ray-Configs")

#: Publish branch. AGG_PUBLISH_BRANCH is the current name; the two older names
#: are still accepted so a stale config fails loudly rather than silently.
GH_BRANCH = (os.environ.get("AGG_PUBLISH_BRANCH")
             or os.environ.get("PUBLISH_BRANCH")
             or os.environ.get("AGG_DATA_BRANCH")
             or os.environ.get("DATA_BRANCH")
             or "main")
RAW_BASE = f"https://raw.githubusercontent.com/{GH_USER}/{GH_REPO}/{GH_BRANCH}"
CDN_BASE = f"https://cdn.jsdelivr.net/gh/{GH_USER}/{GH_REPO}@{GH_BRANCH}"
PRIMARY_BASE = RAW_BASE
MIRROR_BASE = CDN_BASE

#: Rotated between retries; some sources answer better to a specific UA.
USER_AGENTS = (
    "v2rayNG/1.8.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "ClashforWindows/0.20.39",
)
FETCH_TIMEOUT = int(os.getenv("AGG_FETCH_TIMEOUT", "15"))
MAX_WORKERS = int(os.getenv("AGG_MAX_WORKERS", "16"))
FETCH_RETRIES = int(os.getenv("AGG_FETCH_RETRIES", "3"))
RETRY_BACKOFF = 1.5  # seconds, multiplied by the attempt number

#: HTTP codes that retrying can never fix. Three attempts with backoff would
#: waste ~4.5s of the workflow budget for nothing.
_PERMANENT_HTTP = frozenset({400, 401, 403, 404, 410, 451})

#: Update interval in minutes. Must match repo_trigger.py and
#: UPDATE_INTERVAL_MINUTES in aggregate.yml.
UPDATE_INTERVAL_MIN = int(os.getenv("AGG_UPDATE_INTERVAL_MIN", "15"))

#: Per-source health, filled by fetch_all, published in index.json and health.json.
SOURCE_HEALTH: Dict[str, dict] = {}

#: Converter write failures, keyed "{cat}/{target}", published in health.json as
#: `converter_gate`.
#:
#: Named converter_gate and not output_gate because in this project "output gate"
#: already means the control-byte guard (core.ControlByteInOutput). Sharing the
#: name would make the telemetry ambiguous.
CONVERT_FAILURES: Dict[str, str] = {}

CATEGORY_NAMES = ("all", "heavy", "light")


def log(msg: str) -> None:
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%H:%M:%S")
    print(f"[{stamp}] {msg}", flush=True)


# --------------------------------------------------------------------------- #
# Fetching
# --------------------------------------------------------------------------- #

def _health_record(name: str, status: str, count: int, http_code: int,
                   attempts: int, started: float,
                   error: str = "") -> Dict[str, object]:
    record: Dict[str, object] = {
        "name": name, "status": status, "count": count,
        "http_code": http_code, "attempts": attempts,
        "latency_ms": int((time.time() - started) * 1000),
    }
    if error:
        record["error"] = error
    return record


def _attempt_fetch(url: str, user_agent: str) -> Tuple[Optional[List[str]], int, str]:
    """One fetch attempt.

    Returns ``(configs, http_code, error)``. ``configs`` is None when the attempt
    did not yield anything usable; ``error`` then says why.
    """
    try:
        resp = requests.get(url, timeout=FETCH_TIMEOUT,
                            headers={"User-Agent": user_agent})
    except Exception as exc:  # noqa: BLE001 - network faults are expected here
        return None, 0, f"{type(exc).__name__}: {str(exc)[:80]}"

    body = resp.text.strip() if resp.text else ""
    if resp.status_code != 200:
        return None, resp.status_code, f"HTTP {resp.status_code}"
    if not body:
        return None, resp.status_code, "empty body"
    configs = core.extract_valid_lines(body)
    if not configs:
        # 200 with nothing usable, possibly an unrecognised format.
        return None, resp.status_code, "200 but 0 valid configs"
    return configs, resp.status_code, ""


def fetch_source(url: str) -> Tuple[str, List[str]]:
    """Fetch one source into ``(url, configs)`` and record its health.

    Retries up to FETCH_RETRIES times, rotating the User-Agent and backing off
    between attempts. All attempts failing yields an empty list, with the reason
    recorded in SOURCE_HEALTH.

    `tries` is a clamped local rather than a clamped module constant for three
    reasons: both consumers (the range and the sleep condition) read one value so
    they cannot disagree; FETCH_RETRIES stays patchable by tests at call time; and
    max(1, ...) is the same idiom geo.py and reachability.py already use for
    DNS_WORKERS. Without the clamp, AGG_FETCH_RETRIES=0 skipped the loop body and
    the code below raised UnboundLocalError on `attempt`, which fetch_all
    re-raises, killing the entire round over one env var.
    """
    name = url.rsplit("/", 1)[-1] or url
    started = time.time()
    tries = max(1, FETCH_RETRIES)
    last_error = ""
    last_code = 0
    attempt = 0

    for attempt in range(1, tries + 1):
        user_agent = USER_AGENTS[(attempt - 1) % len(USER_AGENTS)]
        configs, last_code, last_error = _attempt_fetch(url, user_agent)
        if configs:
            SOURCE_HEALTH[url] = _health_record(
                name, "ok", len(configs), last_code, attempt, started)
            return url, configs
        if last_code in _PERMANENT_HTTP:
            break
        # Measured: tries=1 -> no sleeps, tries=2 -> [1.5], tries=3 -> [1.5, 3.0].
        if attempt < tries:
            time.sleep(RETRY_BACKOFF * attempt)

    status = "empty" if "0 valid" in last_error else "fail"
    SOURCE_HEALTH[url] = _health_record(
        name, status, 0, last_code, attempt, started, last_error)
    log(f"  WARN fetch fail {name}: {last_error} (after {attempt} tries)")
    return url, []


def fetch_all(urls: Sequence[str]) -> Dict[str, List[str]]:
    """Fetch every URL concurrently into a url -> configs mapping.

    Two deliberate details.

    `max(1, MAX_WORKERS)`: MAX_WORKERS comes from the environment and was never
    validated. AGG_MAX_WORKERS=0 or -1 raised "max_workers must be greater than
    0" before a single fetch, so no source was fetched at all.

    `fut.result()` is deliberately unguarded. fetch_source already catches every
    *network* fault, so anything reaching here is a programming error. The
    aggregator workflow step has no `continue-on-error`, so an exception fails the
    job loudly, the publish step never runs, and the previous healthy snapshot
    survives. Wrapping this in try/except would turn a bug into a silent partial
    aggregation, and since the minimum-output check is only 100 lines, that thin
    output would probably get published. Loud failure is better.
    """
    results: Dict[str, List[str]] = {}
    with ThreadPoolExecutor(max_workers=max(1, MAX_WORKERS)) as pool:
        futures = {pool.submit(fetch_source, url): url for url in urls}
        for future in as_completed(futures):
            url, configs = future.result()
            results[url] = configs
            log(f"  ok {len(configs):>5} configs <- {url.rsplit('/', 1)[-1]}")
    return results


# --------------------------------------------------------------------------- #
# Per-category processing
# --------------------------------------------------------------------------- #

#: line -> (is_dummy, dedup_key). Shared across the three categories.
AnalysisCache = Dict[str, Tuple[bool, str]]


@dataclass
class CategoryResult:
    """Everything one category produced.

    The `unbranded_*` counters exist for the branding gate. They should always be
    zero (measured: 0 across 8,136 published lines); without the counters a
    violation of the "every config carries the channel id" rule would be silent.
    """

    unique: List[str] = field(default_factory=list)
    broken: List[str] = field(default_factory=list)
    duplicates: List[str] = field(default_factory=list)
    total_seen: int = 0
    active_sources: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    unbranded_dropped: int = 0
    unbranded_rebranded: int = 0
    unbranded_samples: List[str] = field(default_factory=list)


def _analyse(line: str, cache: AnalysisCache) -> Tuple[bool, str]:
    """``(is_dummy, dedup_key)`` for a line, memoised.

    process_category runs three times and HEAVY/LIGHT sources are also inside
    ALL, so without the cache every line is analysed twice. Both underlying
    functions are pure, so caching is safe.
    """
    cached = cache.get(line)
    if cached is None:
        if core.is_dummy_config(line):
            cached = (True, "")
        else:
            cached = (False, core.dedup_key(line))
        cache[line] = cached
    return cached


def _collect_unique(per_source: Dict[str, List[str]], source_urls: Sequence[str],
                    result: CategoryResult, cache: AnalysisCache) -> List[str]:
    """Drop dummies, dedup across sources, return the surviving raw lines."""
    seen_keys: Set[str] = set()
    unique: List[str] = []
    for url in source_urls:
        configs = per_source.get(url, [])
        if not configs:
            continue
        result.active_sources += 1
        for line in configs:
            result.total_seen += 1
            is_dummy, key = _analyse(line, cache)
            if is_dummy:
                result.broken.append(line)
            elif key not in seen_keys:
                seen_keys.add(key)
                unique.append(line)
            else:
                result.duplicates.append(line)
    return unique


def _warm_up_countries(lines: Sequence[str]) -> None:
    """Resolve every host's country up front, concurrently.

    core.brand_remark asks for a country per line, which can trigger DNS. Done
    one at a time inside the branding loop, every named host becomes a serial
    round trip. Measured on live data: 5,085 unique hosts, of which 3,720 (73.2%)
    are IP literals needing no DNS; the remaining 1,365 resolve in 4.9s with 64
    workers (128 workers was worse at 8.4s, the upstream resolver is the
    bottleneck). The geo cache is global, so the second and third category cost
    nothing.

    Best effort: a geo failure must never stop aggregation.
    """
    if geo is None:
        return
    try:
        hosts = [ep for ep in (core.endpoint_of(line) for line in lines) if ep]
        geo.warm_up(hosts)
    except Exception as exc:  # noqa: BLE001
        log(f"  WARN geo warm-up skipped: {exc}")


def _brand_all(lines: Sequence[str], result: CategoryResult) -> None:
    """Brand each line, enforcing the branding gate.

    Repo policy is that every published config carries the channel id.
    brand_remark succeeds on 100% of lines today, but "works today" is not a
    guarantee: a new upstream format could produce a line branding skips, and an
    unbranded config, or worse one advertising a rival channel, would ship.

    Three deliberate choices:
      - retry once. brand_remark is idempotent (measured over 56 adversarial
        samples x 5 applications), so re-applying is a no-op on healthy lines and
        only rescues a transient miss.
      - drop that one line, do not abort. One malformed line must not empty every
        user's subscription; total collapse is covered separately by the
        `if not res_all.unique` gate in main().
      - drop rather than publish unbranded, and count it, because silence is what
        made this invisible before.
    """
    for index, line in enumerate(lines, start=1):
        branded = core.brand_remark(line, index)
        if not core.is_branded(branded):
            retry = core.brand_remark(branded, index)
            if core.is_branded(retry):
                branded = retry
                result.unbranded_rebranded += 1
            else:
                result.unbranded_dropped += 1
                # Capped: health.json is downloaded by consumers and must not
                # balloon. Three samples are enough to spot the pattern.
                if len(result.unbranded_samples) < 3:
                    result.unbranded_samples.append(branded[:160])
                continue
        result.unique.append(branded)
        protocol = core.protocol_of(branded)
        if protocol:
            result.protocol_counts[protocol] = \
                result.protocol_counts.get(protocol, 0) + 1


def process_category(per_source: Dict[str, List[str]],
                     source_urls: Sequence[str],
                     _cache: Optional[AnalysisCache] = None) -> CategoryResult:
    """Global dedup plus branding for one category.

    Output order is by dedup key, not by fetch order. Fetch order depends on
    network response times, so it changed every run and made the file look
    completely rewritten. Sorting by content keeps the order stable as long as the
    config set is stable.
    """
    cache: AnalysisCache = {} if _cache is None else _cache
    result = CategoryResult()
    raw_unique = _collect_unique(per_source, source_urls, result, cache)

    # Reuse the cached key instead of recomputing dedup_key per line.
    ordered = sorted(raw_unique, key=lambda line: _analyse(line, cache)[1] or line)
    _warm_up_countries(ordered)
    _brand_all(ordered, result)
    return result


# --------------------------------------------------------------------------- #
# Writing files
# --------------------------------------------------------------------------- #

def _write_text(path: str, content: str) -> None:
    """Write text, vetting it before the file is opened.

    Vetting first means a rejected write leaves no truncated file on disk. See
    core.py, "output guard".
    """
    core.assert_no_control_bytes(path, content)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _remove_if_exists(path: str) -> bool:
    """Delete a previously published file. Returns whether it was removed.

    Delete rather than write an empty file: an empty 200 makes a subscribed
    client replace its working list with nothing, while a 404 makes clients keep
    the previous list. A written file also adds a new blob to git history every
    round.
    """
    if os.path.exists(path):
        try:
            os.remove(path)
            return True
        except OSError as exc:
            log(f"  WARN could not remove {path}: {exc}")
    return False


def _write_converted(base: str, cat: str, target: str, filename: str,
                     build: Callable[[], str]) -> None:
    """Write one converted output, or prune the stale file and record the failure.

    Why a failure is not just logged: these files are tracked on the publish
    branch and the workflow starts with actions/checkout, so the previous round's
    copy is on disk. Not writing means republishing *stale* data, with no signal
    to the subscriber, which is worse than a 404. It also made index.json
    advertise files that were never regenerated and left heavy/ and light/ outside
    the workflow's MUST_EXIST guard.

    So: record the failure (published as health.json.converter_gate) and delete
    the stale file so the link 404s, an honest signal. The run continues, because
    configs.txt is independent and must not be sacrificed.
    """
    path = os.path.join(base, filename)
    try:
        _write_text(path, build())
        CONVERT_FAILURES.pop(f"{cat}/{target}", None)
    except Exception as exc:  # noqa: BLE001
        log(f"  WARN {target} {cat}: {exc}")
        CONVERT_FAILURES[f"{cat}/{target}"] = f"{type(exc).__name__}: {exc}"[:200]
        if _remove_if_exists(path):
            log(f"  pruned stale {cat}/{filename} (404 beats stale data)")


def write_category(out_dir: str, cat: str, result: CategoryResult) -> None:
    """Write one category's four files.

    The Hiddify profile header is always the first thing in the file: Hiddify only
    scans the first 29 lines. singbox.json gets no header, because comments break
    standard JSON.
    """
    base = os.path.join(out_dir, cat)
    profile = core.hiddify_profile_header(cat.upper())
    header = profile + f"# @Raydikalx - {cat.upper()} - {len(result.unique)} unique configs\n"

    # The `#` shield is documented in core.py. The header count comes from
    # result.unique, not from the shielded list, because a shield is not a config.
    _write_text(os.path.join(base, "configs.txt"),
                header + "\n".join(core.shield_unsupported_runs(result.unique)) + "\n")
    _write_text(os.path.join(base, "configs_base64.txt"),
                core.encode_base64_subscription(result.unique, header=profile))
    # YAML: the header is a YAML comment. Measured that yaml.safe_load output is
    # identical with and without it (10,586 proxies).
    _write_converted(base, cat, "clash", "clash.yaml",
                     lambda: profile + converters.build_clash_yaml(result.unique))
    _write_converted(base, cat, "singbox", "singbox.json",
                     lambda: converters.build_singbox_json(result.unique))


def write_archive(out_dir: str, cat: str, result: CategoryResult) -> None:
    """Archive one category's broken configs.

    archive/*_duplicates* is no longer produced. Measured, those six files were
    14,492,513 B (~13.8 MiB) rewritten every round, 98 rounds a day, with new git
    blobs each time; a controlled experiment showed removing them cut per-commit
    cost from 1,680 to 1,328 KiB (-21%). Their value is zero by definition: a
    duplicate's unique twin is already published in all/.

    broken files are kept: they are tiny and useful for debugging sources.
    """
    base = os.path.join(out_dir, "archive")
    txt = os.path.join(base, f"{cat}_broken.txt")
    b64 = os.path.join(base, f"{cat}_broken_base64.txt")

    if result.broken:
        header = (f"# @Raydikalx - {cat.upper()} BROKEN/dummy - "
                  f"{len(result.broken)} configs\n")
        _write_text(txt, header +
                    "\n".join(core.shield_unsupported_runs(result.broken)) + "\n")
        _write_text(b64, core.encode_base64_subscription(result.broken))
    else:
        # Same "no empty files" policy: a header-only txt and a 0-byte base64 file
        # were both being published.
        gone_txt = _remove_if_exists(txt)
        gone_b64 = _remove_if_exists(b64)
        if gone_txt or gone_b64:
            log(f"  pruned empty archive/{cat}_broken*")

    for stale in (f"{cat}_duplicates.txt", f"{cat}_duplicates_base64.txt"):
        if _remove_if_exists(os.path.join(base, stale)):
            log(f"  removed obsolete archive/{stale}")


def write_protocols(out_dir: str, all_unique: Sequence[str]) -> Dict[str, int]:
    """Write per-protocol files from the ALL category.

    An empty protocol file is not published. Before this policy, 14 of the 28
    files in protocols/ held no configs: seven 0-byte base64 files and seven
    header-only txt files. Those cost three ways at once: a user opening the link
    gets an empty 200 and assumes the repo is broken, a subscribed client replaces
    its list with nothing, and each file is a git tree entry in all 98 daily
    rounds. A previously published empty file is deleted so the link 404s, an
    honest signal.

    Counts for every protocol, including zeros, stay in index.json, so no
    information is lost.
    """
    base = os.path.join(out_dir, "protocols")
    buckets: Dict[str, List[str]] = {}
    for line in all_unique:
        protocol = core.protocol_of(line)
        if protocol:
            buckets.setdefault(protocol, []).append(line)

    counts: Dict[str, int] = {}
    written = 0
    pruned = 0

    def emit(protocol: str, lines: List[str]) -> None:
        """Write, or prune, one protocol's file pair."""
        nonlocal written, pruned
        txt = os.path.join(base, f"{protocol}.txt")
        b64 = os.path.join(base, f"{protocol}_base64.txt")
        if lines:
            profile = core.hiddify_profile_header(protocol.upper())
            header = profile + f"# @Raydikalx - {protocol} - {len(lines)} configs\n"
            _write_text(txt, header +
                        "\n".join(core.shield_unsupported_runs(lines)) + "\n")
            _write_text(b64, core.encode_base64_subscription(lines, header=profile))
            written += 1
        else:
            # Both removals must be evaluated independently. Writing
            # `if _remove_if_exists(txt) or _remove_if_exists(b64)` short-circuits
            # and leaves the base64 file in the repo forever, which is exactly how
            # seven 0-byte files survived.
            gone_txt = _remove_if_exists(txt)
            gone_b64 = _remove_if_exists(b64)
            if gone_txt or gone_b64:
                pruned += 1

    for protocol in core.PROTOCOL_ORDER:
        lines = buckets.get(protocol, [])
        counts[protocol] = len(lines)
        emit(protocol, lines)

    # Unknown or newly seen protocols get files automatically.
    for protocol, lines in sorted(buckets.items(), key=lambda item: -len(item[1])):
        if protocol not in counts:
            counts[protocol] = len(lines)
            emit(protocol, lines)

    log(f"  protocols: {written} file-pairs written, {pruned} empty pruned")
    return counts


# --------------------------------------------------------------------------- #
# index.json
# --------------------------------------------------------------------------- #

#: (filename, index key) for the four per-category outputs.
_CATEGORY_FILES = (
    ("configs.txt", "configs_txt"),
    ("configs_base64.txt", "configs_base64"),
    ("clash.yaml", "clash_yaml"),
    ("singbox.json", "singbox_json"),
)


def _category_files(cat: str, exists: Callable[..., bool]) -> Dict[str, str]:
    """Primary and mirror URLs for the files a category actually has.

    A key and its mirror are dropped together: the mirror is fed by the same
    file, so keeping one without the other advertises a 404 via the mirror.

    Key order is deliberately all primaries then all mirrors, matching the
    previous layout, because index.json is published and a gratuitous reordering
    is a noisy diff for no gain.
    """
    live = [(fname, key) for fname, key in _CATEGORY_FILES if exists(cat, fname)]
    files: Dict[str, str] = {}
    for fname, key in live:
        files[key] = f"{PRIMARY_BASE}/{cat}/{fname}"
    for fname, key in live:
        files[f"{key}_mirror"] = f"{MIRROR_BASE}/{cat}/{fname}"
    return files


def _protocol_urls(base: str, suffix: str, proto_counts: Dict[str, int],
                   exists: Callable[..., bool]) -> Dict[str, str]:
    """Protocol URLs, only for protocols whose file is really on disk.

    A non-zero count is a good proxy but not sufficient: _write_text can fail on
    the control-byte guard, leaving a non-zero count with no file. So the count is
    ANDed with disk reality, not replaced by it.
    """
    return {
        protocol: f"{base}/protocols/{protocol}{suffix}"
        for protocol in core.PROTOCOL_ORDER
        if proto_counts.get(protocol, 0) > 0
        and exists("protocols", f"{protocol}{suffix}")
    }


def _archive_urls(results: Dict[str, CategoryResult],
                  exists: Callable[..., bool]) -> Dict[str, str]:
    """Archive URLs for categories that actually have a broken file this round.

    The *_duplicates keys are gone because their files are no longer produced,
    and a key without a file is an advertised 404. The base64 file used to be
    produced but never listed, i.e. published yet undiscoverable; it is listed now.
    """
    urls: Dict[str, str] = {}
    for cat in CATEGORY_NAMES:
        if not results[cat].broken:
            continue
        for key_suffix, fname in (("", f"{cat}_broken.txt"),
                                  ("_base64", f"{cat}_broken_base64.txt")):
            if exists("archive", fname):
                urls[f"{cat}_broken{key_suffix}"] = f"{PRIMARY_BASE}/archive/{fname}"
    return urls


def build_index(results: Dict[str, CategoryResult], proto_counts: Dict[str, int],
                elapsed: float, out_dir: Optional[str] = None) -> dict:
    """Build index.json, the machine-readable list of everything published.

    Standing contract: no URL is advertised whose file does not exist. That used
    to be enforced by proxies (a non-zero protocol count, a non-empty broken
    list), while clash_yaml and singbox_json were advertised unconditionally. The
    proxy was fine while those two were always written, but the converter gate now
    *deletes* a stale file, so a failing clash converter produced three advertised
    404s. Existence is therefore checked on disk.

    ``out_dir=None`` keeps the old behaviour for callers with no disk, such as
    unit tests.
    """
    now = _dt.datetime.now(_dt.timezone.utc)
    next_run = now + _dt.timedelta(minutes=UPDATE_INTERVAL_MIN)

    def exists(*parts: str) -> bool:
        """Whether a file is really on disk.

        ``out_dir=None`` means "unknown" and deliberately reads as True: with no
        disk information, dropping links would produce a *less* complete document
        than today's. Only remove something we are sure is absent.
        """
        if out_dir is None:
            return True
        return os.path.exists(os.path.join(out_dir, *parts))

    def cat_block(cat: str) -> dict:
        result = results[cat]
        return {
            "unique": len(result.unique),
            "broken": len(result.broken),
            "duplicates": len(result.duplicates),
            "total_fetched": result.total_seen,
            "active_sources": result.active_sources,
            "protocols": dict(sorted(result.protocol_counts.items(),
                                     key=lambda item: -item[1])),
            "files": _category_files(cat, exists),
        }

    return {
        "brand": core.BRAND_CHANNEL,
        "generator": "RaydikalxBot aggregator",
        "updated_at": now.isoformat(),
        "updated_at_unix": int(now.timestamp()),
        "next_update_eta": next_run.isoformat(),
        "update_interval_minutes": UPDATE_INTERVAL_MIN,
        "elapsed_seconds": round(elapsed, 1),
        # Link priority is published machine-readably so any consumer knows which
        # base is fresher. The legacy raw_base/cdn_base keys are kept.
        "raw_base": RAW_BASE,
        "cdn_base": CDN_BASE,
        "primary_base": PRIMARY_BASE,
        "mirror_base": MIRROR_BASE,
        # data_branch keeps the same value so consumers reading it do not break.
        "publish_branch": GH_BRANCH,
        "data_branch": GH_BRANCH,
        # index.json publishes its own address. A full "is every published file
        # advertised?" audit found index.json was the only one without a URL, so a
        # consumer holding just this document had to hard-code where to refetch it.
        "self_url": f"{PRIMARY_BASE}/index.json",
        "self_url_mirror": f"{MIRROR_BASE}/index.json",
        "link_policy": {
            "primary": "raw.githubusercontent.com",
            "primary_cache_seconds": 300,
            "mirror": "cdn.jsdelivr.net",
            "mirror_cache_seconds": 43200,
            "note": ("raw is ~144x fresher (300s vs 43200s cache). The jsDelivr "
                     "mirror is purged on every run, but use raw when possible."),
        },
        "categories": {cat: cat_block(cat) for cat in CATEGORY_NAMES},
        "protocols": dict(sorted(proto_counts.items(), key=lambda item: -item[1])),
        "protocol_files": _protocol_urls(PRIMARY_BASE, ".txt", proto_counts, exists),
        "protocol_files_base64": _protocol_urls(PRIMARY_BASE, "_base64.txt",
                                                proto_counts, exists),
        "protocol_files_mirror": _protocol_urls(MIRROR_BASE, ".txt",
                                                proto_counts, exists),
        "archive": _archive_urls(results, exists),
        "sources": {
            "light_count": len(LIGHT_SOURCES),
            "heavy_count": len(HEAVY_SOURCES),
            "total_count": len(LIGHT_SOURCES) + len(HEAVY_SOURCES),
            "healthy": sum(1 for h in SOURCE_HEALTH.values()
                           if h.get("status") == "ok"),
            "unhealthy": sum(1 for h in SOURCE_HEALTH.values()
                             if h.get("status") != "ok"),
            "health_url": f"{PRIMARY_BASE}/health.json",
            "health_url_mirror": f"{MIRROR_BASE}/health.json",
        },
    }


# --------------------------------------------------------------------------- #
# health.json
# --------------------------------------------------------------------------- #

def build_health_report(
    elapsed: float,
    conv_by_category: Optional[Dict[str, dict]] = None,
    results: Optional[Dict[str, CategoryResult]] = None,
) -> dict:
    """Per-source health plus gate telemetry, for monitoring dead sources.

    Extra blocks beyond the source list:

    ``converters`` how many configs were dropped converting to Clash/sing-box and
    why. Previously silent, so a change that suddenly dropped thousands was
    invisible.

    ``converters_by_category`` the per-category split. ``converters._drops`` is a
    *global* counter and each build call clears it, while files are written
    all -> heavy -> light and this report is built afterwards, so the published
    number used to describe only **light** while reading as a total (measured:
    light 21 drops, all 93). The pipeline now snapshots after each category.

    ``geo`` how many labels came from GeoIP versus DNS, how many lookups failed,
    and whether the database loaded at all. Without it, a broken mmdb download
    silently degraded labelling.

    ``brand_gate`` should be all zeros. Any non-zero value means an upstream
    format brand_remark does not understand.

    ``converter_gate`` which converter did not get written. Always a dict, never
    None when measured, so monitoring can tell three states apart: ``{}`` means
    the gate ran clean, a populated dict means real failures, and an absent key
    means an older health.json. ``or None`` would merge the first and last.
    """
    now = _dt.datetime.now(_dt.timezone.utc)
    light = set(LIGHT_SOURCES)
    items = []
    for url in (LIGHT_SOURCES + HEAVY_SOURCES):
        health = SOURCE_HEALTH.get(url, {"name": url.rsplit("/", 1)[-1],
                                         "status": "unknown", "count": 0})
        items.append({"url": url,
                      "tier": "light" if url in light else "heavy",
                      **health})

    conv_by_cat = dict(conv_by_category or {})
    try:
        conv_stats = conv_by_cat.get("all") or converters.drop_stats()
    except Exception:  # noqa: BLE001
        conv_stats = None

    brand_gate = None
    if results:
        brand_gate = {
            cat: {"dropped": result.unbranded_dropped,
                  "rebranded": result.unbranded_rebranded,
                  "samples": list(result.unbranded_samples)}
            for cat, result in results.items()
        }

    geo_stats = None
    if geo is not None:
        try:
            geo_stats = geo.stats()
        except Exception:  # noqa: BLE001
            geo_stats = None

    return {
        "brand": core.BRAND_CHANNEL,
        "checked_at": now.isoformat(),
        "checked_at_unix": int(now.timestamp()),
        "elapsed_seconds": round(elapsed, 1),
        "summary": {
            "total": len(items),
            "ok": sum(1 for item in items if item.get("status") == "ok"),
            "empty": sum(1 for item in items if item.get("status") == "empty"),
            "fail": sum(1 for item in items if item.get("status") == "fail"),
        },
        "sources": items,
        "converters": conv_stats,
        "converters_by_category": conv_by_cat or None,
        "brand_gate": brand_gate,
        # Shallow copy: the report must not alias the live global, or a later
        # write would mutate an already-built report. Values are str, so shallow
        # is enough.
        "converter_gate": dict(CONVERT_FAILURES),
        "geo": geo_stats,
    }


# --------------------------------------------------------------------------- #
# Cross-round memory
# --------------------------------------------------------------------------- #

def unique_yield(per_source: Dict[str, List[str]]) -> Tuple[Dict[str, int],
                                                            Dict[str, int], int]:
    """Per-source *unique* yield as ``(totals, unique, union_size)``.

    "Unique" means a key no other source produced this round. Neither config
    count nor HTTP 200 can see redundancy: Eternity.txt reports 198 configs and
    status ok while being a 100% strict subset of sub_merge.txt from the same
    upstream. By this measure its unique yield is zero.

    Uses core.dedup_key, the same identity function the pipeline dedups with, so
    the metric agrees with the real output.
    """
    keys: Dict[str, Set[str]] = {}
    for url, configs in per_source.items():
        source_keys: Set[str] = set()
        for line in configs:
            try:
                if not core.is_dummy_config(line):
                    source_keys.add(core.dedup_key(line))
            except Exception:  # noqa: BLE001
                continue
        keys[url] = source_keys

    owners: Dict[str, int] = {}
    for source_keys in keys.values():
        for key in source_keys:
            owners[key] = owners.get(key, 0) + 1

    totals = {url: len(source_keys) for url, source_keys in keys.items()}
    unique = {url: sum(1 for key in source_keys if owners.get(key) == 1)
              for url, source_keys in keys.items()}
    return totals, unique, len(owners)


def advance_memory(state: dict, per_source: Dict[str, List[str]],
                   live_urls: Sequence[str], state_path: str) -> dict:
    """Record the round, decide auto-disables, and save.

    Entirely best effort: nothing here may break a healthy round, because the
    published output does not depend on memory. Memory only improves the *next*
    round.
    """
    try:
        totals, unique, union = unique_yield(per_source)
        light = set(LIGHT_SOURCES)
        observed = {url: {"tier": "light" if url in light else "heavy",
                          "total": totals.get(url, 0),
                          "unique": unique.get(url, 0)}
                    for url in per_source}
        state = memory.record_round(state, observed, list(live_urls))

        candidates = memory.disable_candidates(state, unique, union)
        if candidates:
            state = memory.mark_disabled(state, candidates)
            for url, why in candidates.items():
                log(f"  auto-disabling {url.rsplit('/', 1)[-1]} - {why}")
        memory.save_state(state, state_path)

        top = sorted(unique.items(), key=lambda item: -item[1])[:3]
        zero = [url.rsplit("/", 1)[-1] for url, n in unique.items() if n == 0]
        log(memory.summary(state))
        log(f"  union={union} - top unique: "
            + ", ".join(f"{url.rsplit('/', 1)[-1]}={n}" for url, n in top))
        if zero:
            log(f"  WARN zero unique yield this round ({len(zero)}): "
                f"{', '.join(zero)}")
    except Exception as exc:  # noqa: BLE001 - memory never breaks a round
        log(f"  WARN memory step failed ({type(exc).__name__}) - round continues")
    return state


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def _log_category_summary(results: Dict[str, CategoryResult],
                          all_urls: Sequence[str]) -> None:
    pool_size = {"heavy": len(HEAVY_SOURCES),
                 "light": len(LIGHT_SOURCES),
                 "all": len(all_urls)}
    for cat, result in results.items():
        log(f"  - {cat:<5}: {len(result.unique):>6} unique | "
            f"{len(result.duplicates):>6} dup | {len(result.broken):>5} broken | "
            f"{result.active_sources}/{pool_size[cat]} src")


def _log_gates(results: Dict[str, CategoryResult], health: dict) -> None:
    for cat, result in results.items():
        if result.unbranded_dropped or result.unbranded_rebranded:
            log(f"  WARN brand gate [{cat}]: dropped={result.unbranded_dropped} "
                f"rebranded={result.unbranded_rebranded}")
            for sample in result.unbranded_samples:
                log(f"       -> {sample}")

    converters_stats = health.get("converters") or {}
    for target in ("clash", "singbox"):
        stats = converters_stats.get(target)
        if not stats:
            continue
        reasons = ", ".join(f"{k}={v}"
                            for k, v in (stats.get("by_reason") or {}).items())
        log(f"  - {target} drops: {stats.get('total', 0)}"
            + (f" ({reasons})" if reasons else ""))

    geo_stats = health.get("geo")
    if geo_stats:
        unknown = (geo_stats.get("unknown_ip_literal", 0)
                   + geo_stats.get("unknown_after_dns", 0))
        log("  - geo: db=" + ("yes" if geo_stats.get("db_loaded") else "no")
            + f" ip={geo_stats.get('by_ip_literal', 0)}"
            + f" dns={geo_stats.get('by_dns', 0)}"
            + f" dns_failed={geo_stats.get('dns_failed', 0)}"
            + f" unknown={unknown}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Raydikalx config aggregator")
    parser.add_argument("--out", default=os.getcwd(),
                        help="output directory (repo root)")
    args = parser.parse_args()
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    started = time.time()
    log(f"Aggregator start -> out={out_dir}")
    log(f"Fetching {len(LIGHT_SOURCES)} light + {len(HEAVY_SOURCES)} heavy sources")

    # Memory is read before fetching so disabled sources are skipped. load_state
    # never raises; a missing file means empty memory, i.e. the old behaviour.
    all_sources = LIGHT_SOURCES + HEAVY_SOURCES
    state_path = os.path.join(out_dir, memory.STATE_PATH)
    mem = memory.load_state(state_path)
    known = set(all_sources)
    skipped = [url for url in memory.disabled_urls(mem) if url in known]
    skipped_set = set(skipped)
    active_urls = [url for url in all_sources if url not in skipped_set]

    if skipped:
        log(f"memory disabled {len(skipped)} source(s) -> fetching "
            f"{len(active_urls)} of {len(all_sources)}")
        for url in skipped:
            log(f"     skip {url.rsplit('/', 1)[-1]}")
    per_source = fetch_all(active_urls)

    log("Processing categories (dedup + brand)")
    # One analysis cache shared by all three categories.
    cache: AnalysisCache = {}
    results = {
        "all": process_category(per_source, active_urls, cache),
        "heavy": process_category(per_source, HEAVY_SOURCES, cache),
        "light": process_category(per_source, LIGHT_SOURCES, cache),
    }
    _log_category_summary(results, active_urls)

    # Safety gate, before *any* write. This used to run after everything was
    # written, so a round where all sources failed overwrote good files with empty
    # ones and only then returned 2, destroying the previous healthy data.
    if not results["all"].unique:
        log("FAIL no configs produced - aborting BEFORE writing "
            "(existing files preserved)")
        return 2

    # Recorded after the safety gate on purpose: a round that produced nothing is
    # not valid evidence about source yield and must not pollute history or
    # disable anyone. live_urls is the *full* source list, not the filtered one,
    # or a source we skipped ourselves would be garbage-collected in the same
    # round, losing its disable reason and getting refetched next round.
    mem = advance_memory(mem, per_source, all_sources, state_path)

    log("Writing output files")
    # Drop stats are snapshotted right after each category, otherwise the next
    # category's clear_target() wipes them.
    conv_by_cat: Dict[str, dict] = {}
    for cat, result in results.items():
        write_category(out_dir, cat, result)
        try:
            conv_by_cat[cat] = converters.drop_stats()
        except Exception:  # noqa: BLE001
            pass
        write_archive(out_dir, cat, result)

    proto_counts = write_protocols(out_dir, results["all"].unique)
    log("  - protocols: " + ", ".join(f"{k}={v}"
                                      for k, v in proto_counts.items() if v))

    elapsed = time.time() - started
    # out_dir is passed so advertising is tied to disk reality, not to proxies.
    # Called after write_category and write_protocols, so any pruning done by the
    # converter gate is visible here.
    index = build_index(results, proto_counts, elapsed, out_dir)
    _write_text(os.path.join(out_dir, "index.json"),
                json.dumps(index, ensure_ascii=False, indent=2))

    health = build_health_report(elapsed, conv_by_cat, results)
    _write_text(os.path.join(out_dir, "health.json"),
                json.dumps(health, ensure_ascii=False, indent=2))
    summary = health["summary"]
    log(f"  - source health: {summary['ok']} ok / {summary['empty']} empty / "
        f"{summary['fail']} fail")
    _log_gates(results, health)

    log(f"Done in {elapsed:.1f}s - "
        f"ALL={len(results['all'].unique)} "
        f"HEAVY={len(results['heavy'].unique)} "
        f"LIGHT={len(results['light'].unique)} unique")
    return 0


if __name__ == "__main__":
    sys.exit(main())
