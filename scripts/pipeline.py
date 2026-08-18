#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Four-layer verification cascade: the orchestrator.

This module *arranges* the existing layers, it does not restate their logic::

    L0/L1  filters.py       offline structural drop + endpoint dedup
    L2     reachability.py  TCP handshake
    L3     realtest.py      real proxy test via xray-knife
    ->     verified/ . fast/ . secure/ . top100.txt

Four measured decisions shape this file.

1. "Stable" means passing in *every* run of a round, and a round is 3 runs.
   Over 5 full sandbox runs the pass counts were 501/473/363/442/473 (mean
   450.4, stdev 53.1, range 30.6%). Of 626 configs that worked at least once,
   only 224 always worked, i.e. 64.22% flaky. Leave-one-out validation:
   1-of-4 -> 611 configs, 71.3% precision; 2-of-4 -> 520, 77.8%;
   3-of-4 -> 416, 83.7%; 4-of-4 -> 255, 88.5%; single run baseline 450, 78.6%.

   That 64.22% is an environment number, not a property of the rule. The same
   code on a dedicated server (same 8,158 configs, 3 runs) gave 542/531/532,
   stdev ~6 instead of 53, and 24.92% flaky. The rule survived both
   measurements; only the percentage is local, so every output writes its own
   run's figure into its header via stats['flaky_pct'].

   Cost on the server: three L3 runs 106.92s, whole cascade 149.34s against a
   900s CI budget.

2. Accepting a row takes four conditions, not one. `success == total` alone is a
   hole: it is also true for all 87 broken rows (0 == 0). The rule lives in
   realtest.is_row_genuinely_ok and is not restated here.

3. `fast` is judged on the median across runs, not one run. Per-run medians were
   761/720/768/756/765ms (stdev 20), so the *distribution* is stable, but 77
   configs (34.4%) cross the 800ms line between runs (median intra-link range
   373ms). A single-run label is therefore not trustworthy.

4. `secure` means forward secrecy, not "any encryption". See
   has_forward_secrecy() for the summary and PHASE_B_PLAN.md B7 for the proofs.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import converters  # noqa: E402
import core  # noqa: E402
import filters  # noqa: E402
import reachability  # noqa: E402
import realtest  # noqa: E402

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

#: L3 runs per round. "Stable" means passing in all of them.
L3_ROUNDS = int(os.environ.get("L3_ROUNDS", "3"))

#: `fast` threshold on the median delay across runs, in ms. Measured on the
#: stable set: 300 -> 14 configs (useless), 500 -> 86, 600 -> 111,
#: 800 -> 149 (66.5%), 1000 -> 168, 1200 -> 182.
FAST_THRESHOLD_MS = int(os.environ.get("L3_FAST_MS", "800"))

#: Cap for top100.txt. If fewer configs qualify, the real count is published;
#: padding with untested configs is forbidden.
TOP_N = int(os.environ.get("L3_TOP_N", "100"))

#: `tls` values that imply an (EC)DHE handshake, hence forward secrecy.
FS_TLS_VALUES = frozenset({"tls", "reality", "xtls"})

#: QUIC-based protocols, where TLS 1.3 is mandatory (RFC 9001 section 4.2:
#: "Clients MUST NOT offer TLS versions older than 1.3").
FS_SCHEMES = frozenset({"hysteria2", "hy2", "tuic"})

#: Parameters with which a link waives certificate validation. Such a link has
#: TLS but no MITM protection.
INSECURE_KEYS = frozenset({
    "insecure", "allowinsecure", "allow_insecure",
    "skip-cert-verify", "skipcertverify", "allowinsecureciphers",
})
_TRUEISH = frozenset({"1", "true", "yes", "on"})

CATEGORIES = ("verified", "fast", "secure")

#: Sentinel rank for a stable config with no recorded delay. Should not happen,
#: but it must sort last rather than vanish silently.
_NO_DELAY = 10 ** 9


class StabilityError(RuntimeError):
    """The round produced no valid run. An environment fault, not a data one."""


# --------------------------------------------------------------------------- #
# Security judgement
# --------------------------------------------------------------------------- #

def scheme_of(link: str) -> str:
    return link.split("://", 1)[0].strip().lower() if "://" in link else ""


def _query(link: str) -> Dict[str, str]:
    try:
        raw = parse_qs(urlsplit(link).query)
    except ValueError:
        return {}
    return {key.strip().lower(): (val[0] if val else "")
            for key, val in raw.items()}


def declares_insecure(link: str) -> bool:
    """Whether the link itself disables certificate validation."""
    query = _query(link)
    return any(unquote(query.get(key, "")).strip().lower() in _TRUEISH
               for key in INSECURE_KEYS)


def has_forward_secrecy(link: str, tls_value: str) -> bool:
    """Whether the session key comes from an (EC)DHE handshake.

    Why this bar and not "any encryption": this repo is public, so a pre-shared
    key that is printed in the link protects nothing. Three executed proofs:

    - shadowsocks with an AEAD cipher: the salt is plaintext on the wire and the
      main key derives from the password inside the published link, so an
      observer holding only the link recovered the plaintext (3/3 ciphers).
      SIP022 is explicit: "Shadowsocks 2022 does not provide forward secrecy".
    - vmess without TLS: the command-section key is MD5(UUID + public constant)
      and that section carries the session data key, so the session key was
      recovered from the published UUID with 61 MD5 attempts (a 30 second window).
    - vless with tls=none: the VLESS spec only accepts `encryption=none`, so it
      really is unencrypted.

    These configs are not broken and stay in verified/. Only the "secure" label
    would be false for them in a public repo.
    """
    if (tls_value or "").strip().lower() in FS_TLS_VALUES:
        return True
    return scheme_of(link) in FS_SCHEMES


def is_secure(link: str, tls_value: str) -> bool:
    return has_forward_secrecy(link, tls_value) and not declares_insecure(link)


# --------------------------------------------------------------------------- #
# Multi-run L3 round
# --------------------------------------------------------------------------- #

def _median_int(values: Sequence[int]) -> int:
    return int(round(statistics.median(values)))


def _rows_of(result: Dict[str, Any]) -> List[Dict[str, str]]:
    """Rows of one L3 run, normalising the container shape in one place.

    `realtest.run_test` returns `rows` as a link -> row *mapping*. Iterating it
    directly yields string keys and fails at runtime with "'str' object has no
    attribute 'get'", which once passed the test suite because a test shim
    returned the wrong shape. An unknown shape breaks loudly here.
    """
    rows = result.get("rows")
    if isinstance(rows, dict):
        return list(rows.values())
    if isinstance(rows, list):
        return rows
    raise StabilityError(
        f"unexpected shape for the L3 'rows' field: {type(rows).__name__}")


def run_l3_round(lines: Sequence[str], rounds: Optional[int] = None,
                 **kwargs: Any) -> Dict[str, Any]:
    """Run L3 ``rounds`` times over the same input and measure stability.

    Returns::

        rounds      runs performed
        per_run_ok  pass count per run, for telemetry and regression spotting
        stable      links accepted in *every* run
        ever_ok     links accepted at least once
        delays      stable link -> median delay across runs
        tls         link -> tls value (static: changed in 0 of 3,845 rows)
        flaky_pct   share of everything that worked which was not stable
    """
    if rounds is None:
        rounds = L3_ROUNDS
    if rounds < 1:
        raise ValueError(f"rounds must be >= 1, got {rounds!r}")

    lines = [line.strip() for line in lines if (line or "").strip()]
    if not lines:
        # Same lesson as L3 itself: empty input breaks loudly, never silently.
        raise realtest.EmptyInput("no configs to test at L3")

    ok_sets: List[Set[str]] = []
    per_run_ok: List[int] = []
    delays: Dict[str, List[int]] = {}
    tls_of: Dict[str, str] = {}

    for _ in range(rounds):
        result = realtest.test_lines(lines, **kwargs)
        passing: Set[str] = set()
        for row in _rows_of(result):
            link = (row.get("link") or "").strip()
            if not link:
                continue
            tls_of.setdefault(link, realtest.row_tls(row))
            if realtest.is_row_genuinely_ok(row):
                passing.add(link)
                delay = realtest.row_delay_ms(row)
                if delay is not None:
                    delays.setdefault(link, []).append(delay)
        ok_sets.append(passing)
        per_run_ok.append(len(passing))

    stable = set.intersection(*ok_sets)
    ever_ok = set.union(*ok_sets)
    flaky_pct = (round(100.0 * (len(ever_ok) - len(stable)) / len(ever_ok), 2)
                 if ever_ok else 0.0)

    return {
        "rounds": rounds,
        "per_run_ok": per_run_ok,
        "stable": stable,
        "ever_ok": ever_ok,
        # Only stable links have a full sample, so only they get a median.
        "delays": {link: _median_int(delays[link])
                   for link in stable if link in delays},
        "tls": tls_of,
        "flaky_pct": flaky_pct,
    }


def build_buckets(round_result: Dict[str, Any],
                  fast_ms: Optional[int] = None,
                  top_n: Optional[int] = None) -> Dict[str, Any]:
    """Turn a round result into the three buckets plus top100.

    Ordering is by median delay, then by the link itself, so equal delays keep a
    deterministic order and git sees no phantom diffs.
    """
    if fast_ms is None:
        fast_ms = FAST_THRESHOLD_MS
    if top_n is None:
        top_n = TOP_N

    delays = round_result["delays"]
    tls_of = round_result["tls"]
    stable = round_result["stable"]

    ranked = sorted(stable, key=lambda link: (delays.get(link, _NO_DELAY), link))
    verified = ranked
    fast = [link for link in ranked if delays.get(link, _NO_DELAY) < fast_ms]
    secure = [link for link in ranked if is_secure(link, tls_of.get(link, ""))]
    top = ranked[:top_n]

    return {
        "verified": verified,
        "fast": fast,
        "secure": secure,
        "top": top,
        "delays": delays,
        "stats": {
            "rounds": round_result["rounds"],
            "per_run_ok": round_result["per_run_ok"],
            "ever_ok": len(round_result["ever_ok"]),
            "stable": len(stable),
            "flaky_pct": round_result["flaky_pct"],
            "fast_threshold_ms": fast_ms,
            "verified": len(verified),
            "fast": len(fast),
            "secure": len(secure),
            "top": len(top),
            "top_short_by": max(0, top_n - len(top)),
            "median_delay_ms": (_median_int(sorted(delays.values()))
                                if delays else None),
        },
    }


# --------------------------------------------------------------------------- #
# Writing output
# --------------------------------------------------------------------------- #

def _write_lines(path: str, header: str, lines: Sequence[str]) -> None:
    """Write a header plus one line per entry, vetting content first.

    The header and each line are vetted separately rather than by joining them
    into one giant string: these files run to tens of thousands of lines.
    Vetting happens before the file is opened so a rejected write leaves no
    half-written file behind.
    """
    core.assert_no_control_bytes(path, header)
    for line in lines:
        core.assert_no_control_bytes(path, line)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(header)
        for line in lines:
            fh.write(line + "\n")


def _category_headers(stats: Dict[str, Any]) -> Dict[str, str]:
    """Per-category file headers.

    Each header states the *measured* criterion, so a user can see what "secure"
    or "fast" is actually claiming.

    The Hiddify profile header goes first so it stays inside Hiddify's 29-line
    scan window; the longest descriptive header below is 8 lines.
    """
    rounds = stats["rounds"]
    profile = {cat: core.hiddify_profile_header(cat.upper()) for cat in CATEGORIES}
    return {
        "verified": (
            profile["verified"] +
            f"# @Raydikalx - VERIFIED - {stats['verified']} configs\n"
            f"# criterion: a real proxied request to {realtest.TEST_URL} succeeded\n"
            f"# in ALL {rounds} independent runs of this round.\n"
            f"# measured: {stats['flaky_pct']}% of everything that ever worked is "
            f"flaky, so a single run is not enough.\n"),
        "fast": (
            profile["fast"] +
            f"# @Raydikalx - FAST - {stats['fast']} configs\n"
            f"# criterion: verified AND median delay across {rounds} runs "
            f"< {stats['fast_threshold_ms']}ms.\n"
            f"# the median (not one sample) is used because configs cross this "
            f"line between runs: measured 34.4% of them in a 5-run experiment.\n"
            f"# that share depends on the network the test ran on, so treat it "
            f"as the reason for using a median, not as a constant.\n"),
        "secure": (
            profile["secure"] +
            f"# @Raydikalx - SECURE - {stats['secure']} configs\n"
            f"# criterion: verified AND forward secrecy - the session key comes\n"
            f"# from an (EC)DHE handshake (TLS/REALITY, or QUIC which mandates\n"
            f"# TLS 1.3 per RFC 9001 section 4.2) AND the link does not disable\n"
            f"# certificate validation.\n"
            f"# note: this repo is PUBLIC. A pre-shared-key protocol such as\n"
            f"# shadowsocks is decryptable by anyone who reads the link, so it\n"
            f"# is NOT listed here even though it is encrypted on the wire.\n"),
    }


def _write_category(out_dir: str, cat: str, links: Sequence[str], header: str,
                    profile_header: str) -> Dict[str, str]:
    """Write all four files for one category and return the paths written.

    All four are required, not optional: validate.py judges any category
    directory that *exists* as strictly as a core one and counts a missing
    singbox.json/clash.yaml as `missing`. Writing only configs.txt measured
    ok=False, missing=2, so `--strict` closed the publish gate. Either write all
    four or do not create the category.

    singbox.json deliberately gets no profile header: comments break standard
    JSON and validate.py calls json.load on it.
    """
    written: Dict[str, str] = {}
    path = os.path.join(out_dir, cat, "configs.txt")
    # The `#` shield applies to config lines only, which is why it is here and
    # not inside _write_lines: that helper also writes yaml/json bodies.
    _write_lines(path, header, core.shield_unsupported_runs(links))
    written[cat] = path

    builders = (
        ("configs_base64.txt",
         lambda items: core.encode_base64_subscription(items, header=profile_header)),
        ("clash.yaml",
         lambda items: profile_header + converters.build_clash_yaml(items)),
        ("singbox.json", converters.build_singbox_json),
    )
    for name, build in builders:
        try:
            body = build(links)
        except Exception as exc:  # noqa: BLE001
            # A converter may break on one specific link. That must not destroy
            # the cascade, but it must be visible.
            print(f"WARN {cat}/{name}: {exc}", file=sys.stderr)
            continue
        sub = os.path.join(out_dir, cat, name)
        _write_lines(sub, "", [body.rstrip("\n")])
        written[f"{cat}/{name}"] = sub
    return written


def write_buckets(out_dir: str, buckets: Dict[str, Any]) -> Dict[str, str]:
    """Write the three buckets plus top100.txt and return the paths."""
    stats = buckets["stats"]
    headers = _category_headers(stats)
    written: Dict[str, str] = {}

    for cat in CATEGORIES:
        written.update(_write_category(
            out_dir, cat, buckets[cat], headers[cat],
            core.hiddify_profile_header(cat.upper()),
        ))

    top = buckets["top"]
    short = stats["top_short_by"]
    top_head = (
        core.hiddify_profile_header(f"TOP {len(top)}") +
        f"# @Raydikalx - TOP {len(top)} - sorted by median delay\n"
        f"# every entry passed a real proxied request in all "
        f"{stats['rounds']} runs.\n")
    if short:
        # Say so explicitly instead of padding. The user should know the pool
        # was small.
        top_head += (f"# NOTE: only {len(top)} configs met the bar this round "
                     f"({short} short of {TOP_N}). The file is NOT padded with "
                     f"untested configs.\n")
    top_path = os.path.join(out_dir, "top100.txt")
    _write_lines(top_path, top_head, core.shield_unsupported_runs(top))
    written["top"] = top_path
    return written


# --------------------------------------------------------------------------- #
# Exit country
# --------------------------------------------------------------------------- #

#: Where the exit country is asked. Deliberately the same host the test itself
#: connects to, so it adds no new domain and no new dependency.
TRACE_URL = "https://cp.cloudflare.com/cdn-cgi/trace"


def exit_country(timeout: float = 10.0) -> Optional[Dict[str, str]]:
    """Exit country of the machine running the test.

    A `verified` label means "it worked from this machine", so a user in Iran
    reading a list produced by a US runner needs to know where it was measured.
    Without this field the numbers are unqualified and therefore misleading.

    Best effort: any error returns None. An incomplete health report must never
    break config publication.
    """
    import urllib.request

    try:
        with urllib.request.urlopen(TRACE_URL, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None

    out: Dict[str, str] = {}
    for row in body.splitlines():
        key, _, value = row.partition("=")
        if key in ("loc", "colo") and value:
            out[key] = value
    if not out:
        return None
    out["source"] = TRACE_URL
    return out


# --------------------------------------------------------------------------- #
# Merging into published reports
# --------------------------------------------------------------------------- #

def _load_json_doc(path: str, purpose: str) -> Optional[Dict[str, Any]]:
    """Load an existing JSON object, warning and returning None on any problem.

    Shared by the health and index merges. Both are monitoring/advertising, not
    the product, so they warn and give up instead of raising.
    """
    if not os.path.exists(path):
        print(f"WARN {path} does not exist; {purpose} skipped", file=sys.stderr)
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        print(f"WARN {path} is unreadable ({exc}); {purpose} skipped",
              file=sys.stderr)
        return None
    if not isinstance(doc, dict):
        print(f"WARN {path} is not a JSON object; {purpose} skipped",
              file=sys.stderr)
        return None
    return doc


def _atomic_write_json(path: str, doc: Dict[str, Any],
                       purpose: str) -> Optional[str]:
    """Write JSON atomically, returning the path or None on failure.

    tmp + os.replace, because a half-written health.json is worse than none.
    Failures are reported rather than raised: these files are published after
    the configs already are, so a write error here must not fail the cascade.
    """
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
        return path
    except Exception as exc:  # noqa: BLE001
        print(f"WARN could not write {path} ({exc}); {purpose} skipped",
              file=sys.stderr)
        try:
            os.remove(tmp)
        except OSError:
            pass
        return None


def merge_health(out_dir: str, cascade: Dict[str, Any]) -> Optional[str]:
    """Add the ``cascade`` block to an existing ``health.json``.

    Added rather than created because aggregate.py builds that file and runs
    *before* the cascade in the workflow (the cascade needs the same run's
    all/configs.txt), so layer stats cannot come from build_health_report.
    """
    path = os.path.join(out_dir, "health.json")
    doc = _load_json_doc(path, "layer stats not merged")
    if doc is None:
        return None
    doc["cascade"] = cascade
    return _atomic_write_json(path, doc, "layer stats not merged")


#: One-line, machine-readable criterion per cascade category. An index.json
#: consumer should not have to download a text file and parse its header to
#: learn what "fast" means.
CASCADE_CRITERIA = {
    "verified": "a real proxied request succeeded in ALL rounds of this run",
    "fast": "verified AND median delay across all rounds is under the threshold",
    "secure": ("verified AND forward secrecy ((EC)DHE via TLS/REALITY/QUIC) "
               "AND certificate validation not disabled"),
}

#: Filename -> index key. Deliberately the same keys aggregate.build_index uses,
#: so consumers never see two shapes for the same thing.
_INDEX_FILE_KEYS = (
    ("configs.txt", "configs_txt"),
    ("configs_base64.txt", "configs_base64"),
    ("clash.yaml", "clash_yaml"),
    ("singbox.json", "singbox_json"),
)


def _bases_of(doc: Dict[str, Any], path: str) -> Optional[Tuple[str, str]]:
    """``(primary, mirror)`` URL roots read from the document itself.

    Read from the document rather than redefined here, so the roots cannot
    diverge from what aggregate.build_index wrote. The mirror is optional.
    """
    primary = doc.get("primary_base")
    if not isinstance(primary, str) or not primary:
        print(f"WARN {path} has no primary_base; not merged", file=sys.stderr)
        return None
    mirror = doc.get("mirror_base")
    return primary, mirror if isinstance(mirror, str) else ""


def _cascade_index_block(out_dir: str, buckets: Dict[str, Any],
                         primary: str, mirror: str) -> Dict[str, Any]:
    """Index entries for the cascade categories that exist on disk."""
    cascade: Dict[str, Any] = {}
    for cat in CATEGORIES:
        cat_dir = os.path.join(out_dir, cat)
        files: Dict[str, str] = {}
        for fname, key in _INDEX_FILE_KEYS:
            if not os.path.exists(os.path.join(cat_dir, fname)):
                continue
            files[key] = f"{primary}/{cat}/{fname}"
            if mirror:
                files[f"{key}_mirror"] = f"{mirror}/{cat}/{fname}"
        if not files:
            # The category was never written, e.g. the pool was empty. Do not
            # advertise it.
            continue
        cascade[cat] = {
            "unique": len(buckets.get(cat, [])),
            "criterion": CASCADE_CRITERIA.get(cat, ""),
            "files": files,
        }
    return cascade


def merge_index(out_dir: str, buckets: Dict[str, Any]) -> Optional[str]:
    """Add the cascade categories and ``top100`` to an existing ``index.json``.

    Added rather than created for the same reason as :func:`merge_health`: when
    aggregate.build_index runs, verified/, fast/, secure/ and top100.txt do not
    exist yet, so index.json never advertised them at all.

    The ``categories`` key is left untouched and cascade categories go under a
    separate ``cascade_categories`` key. That is required, not cosmetic:
    docs/index.html loops over Object.entries(categories) to build its links,
    and the cascade workflow step is `continue-on-error: true`, so a round may
    not run. Folding them into ``categories`` would advertise links that can 404.

    Only files that really exist on disk are advertised, matching the contract
    aggregate.build_index already honours.
    """
    path = os.path.join(out_dir, "index.json")
    purpose = "cascade categories not advertised"
    doc = _load_json_doc(path, purpose)
    if doc is None:
        return None
    bases = _bases_of(doc, path)
    if bases is None:
        return None
    primary, mirror = bases

    cascade = _cascade_index_block(out_dir, buckets, primary, mirror)
    if cascade:
        doc["cascade_categories"] = cascade

    top_name = "top100.txt"
    if os.path.exists(os.path.join(out_dir, top_name)):
        top_block: Dict[str, Any] = {
            "count": len(buckets.get("top", [])),
            "criterion": ("verified configs sorted by median delay "
                          "(fastest first); never padded with untested ones"),
            "url": f"{primary}/{top_name}",
        }
        if mirror:
            top_block["url_mirror"] = f"{mirror}/{top_name}"
        doc["top100"] = top_block

    return _atomic_write_json(path, doc, purpose)


# --------------------------------------------------------------------------- #
# Full run
# --------------------------------------------------------------------------- #

def _pct(part: int, whole: int) -> float:
    """``part`` as a percentage of ``whole``; division by zero gives 0.0."""
    if not whole:
        return 0.0
    return round(100.0 * part / whole, 2)


def _cascade_report(pre: Dict[str, Any], l2: Dict[str, Any],
                    stats: Dict[str, Any], open_count: int,
                    timings: Dict[str, float]) -> Dict[str, Any]:
    """The ``cascade`` block published into health.json.

    l2's `in` comes from `pre`, not from l2's own `configs_in`:
    reachability.check_lines takes *raw* lines and re-runs L0/L1 itself, so
    configs_in is the raw input (measured 300 where L0/L1 kept 295). Reporting
    300 after a layer that emitted 295 reads as if 5 configs appeared from
    nowhere. reachability's own number is kept under the explicit name
    `open_pct_of_raw_input`; they answer two different questions.
    """
    l2_stats = l2["stats"]
    kept = pre["stats"]["kept"]
    return {
        "exit_country": exit_country(),
        "layers": {
            "l0_l1": {
                "in": pre["stats"]["input"],
                "out": kept,
                "dropped": pre["dropped"],
                "endpoints_unique": pre["stats"]["endpoints_unique"],
                "dedup_saving_pct": pre["stats"]["dedup_saving_pct"],
                "seconds": timings["l0_l1"],
            },
            "l2": {
                "in": kept,
                "out": l2_stats["configs_open"],
                "open_pct": _pct(l2_stats["configs_open"], kept),
                "open_pct_of_raw_input": l2_stats["configs_open_pct"],
                "dns_failed": l2_stats["dns_failed"],
                "dns_seconds": l2_stats["dns_s"],
                "tcp_seconds": l2_stats["tcp_s"],
                "fd_before": l2_stats["fd_before"],
                "fd_after": l2_stats["fd_after"],
                "seconds": timings["l2"],
            },
            "l3": {
                "in": open_count,
                "rounds": stats["rounds"],
                "per_run_ok": stats["per_run_ok"],
                "ever_ok": stats["ever_ok"],
                "stable": stats["stable"],
                "flaky_pct": stats["flaky_pct"],
                "seconds": timings["l3"],
            },
        },
        "buckets": {
            "verified": stats["verified"],
            "fast": stats["fast"],
            "secure": stats["secure"],
            "top": stats["top"],
            "top_short_by": stats["top_short_by"],
            "fast_threshold_ms": stats["fast_threshold_ms"],
        },
        "total_seconds": timings["total"],
    }


def run_pipeline(lines: Iterable[str], out_dir: str,
                 rounds: Optional[int] = None, fast_ms: Optional[int] = None,
                 top_n: Optional[int] = None, **kwargs: Any) -> Dict[str, Any]:
    """Full cascade: L0/L1 -> L2 -> L3 x n -> buckets -> files -> health.json."""
    lines = list(lines)
    started = time.time()

    # L0/L1 is run here as well as inside check_lines because check_lines only
    # surfaces the *summary*; the per-reason `dropped` breakdown stays inside.
    # The alternatives were worse: editing two mutation-tested modules, or
    # restating layer logic here and breaking "arrange, do not repeat". Cost
    # measured at 0.35s over 8,158 configs, i.e. 0.2% of a 149s cascade.
    mark = time.time()
    pre = filters.filter_lines(lines)
    l01_s = round(time.time() - mark, 2)

    mark = time.time()
    l2 = reachability.check_lines(lines)
    l2_s = round(time.time() - mark, 2)
    open_lines = l2["kept_open"]

    mark = time.time()
    round_result = run_l3_round(open_lines, rounds=rounds, **kwargs)
    l3_s = round(time.time() - mark, 2)

    buckets = build_buckets(round_result, fast_ms=fast_ms, top_n=top_n)
    paths = write_buckets(out_dir, buckets)
    stats = buckets["stats"]
    stats["l2"] = l2["stats"]
    buckets["paths"] = paths

    cascade = _cascade_report(pre, l2, stats, len(open_lines), {
        "l0_l1": l01_s,
        "l2": l2_s,
        "l3": l3_s,
        "total": round(time.time() - started, 2),
    })
    stats["cascade"] = cascade

    health = merge_health(out_dir, cascade)
    if health:
        paths["health.json"] = health
    # Same pattern for index.json. write_buckets has already run, so the cascade
    # files are on disk and merge_index can verify them before advertising.
    index = merge_index(out_dir, buckets)
    if index:
        paths["index.json"] = index
    return buckets


def _main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="four-layer verification cascade")
    parser.add_argument("input", help="file with one config per line")
    parser.add_argument("--out", default=".", help="output directory")
    parser.add_argument("--rounds", type=int, default=None)
    parser.add_argument("--fast-ms", type=int, default=None)
    parser.add_argument("--top-n", type=int, default=None)
    parser.add_argument("--json", default=None, help="write stats as JSON here")
    args = parser.parse_args(argv)

    with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()

    result = run_pipeline(lines, args.out, rounds=args.rounds,
                          fast_ms=args.fast_ms, top_n=args.top_n)
    stats = result["stats"]
    print(f"-> rounds={stats['rounds']} per_run_ok={stats['per_run_ok']} "
          f"ever_ok={stats['ever_ok']} stable={stats['stable']} "
          f"flaky={stats['flaky_pct']}%")
    print(f"-> verified={stats['verified']} fast={stats['fast']} "
          f"secure={stats['secure']} top={stats['top']}")
    if stats["top_short_by"]:
        print(f"WARN top file is {stats['top_short_by']} short of {TOP_N} - "
              f"published unpadded")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(stats, fh, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
