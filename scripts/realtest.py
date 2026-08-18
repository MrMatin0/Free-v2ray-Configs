#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L3 of the cascade: the *real* proxy test, via xray-knife.

    L0  endpoint dedup        filters.py
    L1  cheap offline filter  filters.py
    L2  TCP handshake         reachability.py
    L3  real proxy test       this module

L2 only proves a socket opened. L3 proves traffic actually traversed the proxy
and reached the internet. The gap is large on real data::

    raw input          8,028 configs
    after L0/L1/L2     3,845 configs  (47.91%)
    after L3             504 configs  (13.11% of L2, 6.28% of raw)

Seven measured decisions

1. `semi-passed` is accepted, correcting our own earlier plan. Across all 55
   semi-passed rows in a full census, with zero exceptions: success == total,
   code == 204, the endpoint column said ok(NNNms), and the only reason was
   `ip_info_failed` with ip and location both "null". The semi-passed set is
   bit-for-bit the set of successful rows with location == "null", while 449
   `passed` rows have zero null ips. So semi-passed means "the proxy worked but
   the optional --rip lookup failed", and rejecting it silently discarded 55
   healthy configs, 10.9% of final output.

2. `success == total` alone is not enough. `broken` rows carry
   success=0, total=0, which satisfies it (0 == 0), so 87 broken rows counted as
   successes. The correct lock is total >= 1 and success == total and
   200 <= code < 400; on the census it reproduces the 504-row success set exactly.

3. Two full CI-hang paths, found and closed. Given a missing or empty input the
   tool prints an error and then *waits on stdin* ("Please enter a config link").
   Under CI, where stdin never closes: empty file -> rc=124 hang, missing file ->
   rc=124 hang, empty file with </dev/null -> rc=1 clean failure. A hang burns
   the full 6 hour GitHub limit and the `aggregate` concurrency group queues
   every later run behind it. The empty-input case is realistic: it happens
   whenever L2 leaves zero open endpoints. Three defences: check the input
   exists and is non-blank, pass stdin=DEVNULL, and impose a hard Python timeout.

4. Stale output survives a failed run, the most dangerous finding here. A CSV
   containing STALE_MARKER, followed by a failing run against the same -o, gave
   rc=1 and left STALE_MARKER intact, so last run's data reads as fresh results.
   The output file is therefore deleted before every run.

5. `-o` does not create the parent directory and lies when it is missing:
   rc=0, "Results have been saved to ...", and no file on disk. So the parent is
   created here and the file's existence is verified afterwards.

6. The exit code never reflects result quality. A single completely dead link
   returns rc=0. Quality comes only from the CSV.

7. The CSV must be read with the `csv` module. On the 3,845 row census,
   `split(",")` produced the wrong field count for 236 rows, because 182 links
   contain commas and 3,321 rows are quoted. Naive splitting silently corrupted
   about 6% of the data.

Why --retries and --max-passed are unused: --retries hides flakiness *inside* a
run (measured flakiness is 32.7%, 17 of 52 links over 3 runs), and separating
stable from lucky is the caller's job, so repetition belongs a layer up.
--max-passed returns incomplete output (--max-passed 2 -t 5 returned 5 rows),
so a link's absence from the CSV can never be read as failure. Both flags are
still supported for manual use, and the result is flagged ``partial``.

``run_test`` output is the input contract for the branding/publishing layers::

    {ok: [...], failed: [...], broken: [...],
     rows: {link: row}, stats: {...}, partial: bool}
"""
from __future__ import annotations

import csv
import io
import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# --------------------------------------------------------------------------- #
# Tunables. All measured, all overridable from the environment.
# --------------------------------------------------------------------------- #

#: Binary path. CI installs a pinned, checksum-verified release.
XK_BIN = os.environ.get("L3_XK_BIN", "xray-knife")

#: Test URL, set explicitly rather than relying on the tool default. v10.1.1
#: defaults to cloudflare.com/cdn-cgi/trace, which answers 200, while our
#: reference runs recorded 204. Without pinning this, two runs are not comparable.
TEST_URL = os.environ.get("L3_TEST_URL", "https://cp.cloudflare.com/generate_204")

#: Worker threads. On the 3,845 config census: 50 -> 169s, 150 -> 61s,
#: 200 -> 43s, 300 -> no meaningful gain.
THREADS = int(os.environ.get("L3_THREADS", "200"))

#: Max acceptable delay in ms, the tool default made explicit.
MDELAY_MS = int(os.environ.get("L3_MDELAY", "5000"))

#: Per-request timeout in ms. The tool defaults to 0 (unbounded), which is
#: dangerous in CI, so it is closed explicitly.
TIMEOUT_MS = int(os.environ.get("L3_TIMEOUT", "5000"))

#: Last-resort net. The full census took 43s, so 1800s is 42x margin while
#: staying far below GitHub's 6 hour ceiling.
HARD_TIMEOUT = int(os.environ.get("L3_HARD_TIMEOUT", "1800"))

STATUS_PASSED = "passed"
STATUS_SEMI = "semi-passed"
STATUS_FAILED = "failed"
STATUS_BROKEN = "broken"

#: Statuses that mean "the proxy worked". semi-passed belongs here, see note 1.
#: Every member still has to clear the numeric lock in is_row_genuinely_ok().
OK_STATUSES = (STATUS_PASSED, STATUS_SEMI)

#: All four observed statuses. The failed/broken split matters:
#: failed = proxy was built but the request was rejected (dead server, transient)
#: broken = proxy was never built at all (bad data, fixable at the source)
ALL_STATUSES = (STATUS_PASSED, STATUS_SEMI, STATUS_FAILED, STATUS_BROKEN)

#: Column contract. An upstream schema change must break loudly rather than
#: silently shift which column we read.
CSV_COLUMNS = (
    "link", "status", "reason", "tls", "ip", "delay", "code", "download",
    "upload", "location", "ttfb", "connect_time", "success", "total",
    "endpoints",
)

#: The tool writes a literal "null" for absent values, never an empty field.
#: Measured: the ip column is exactly "null" in 3,396 rows and empty in zero.
NULL_TOKEN = "null"

#: Successful HTTP code range. The census only ever showed 204 (504 rows, all
#: successful) and -1 (3,341 rows, all unsuccessful).
CODE_MIN_OK = 200
CODE_MAX_OK = 400


class XrayKnifeMissing(RuntimeError):
    """The xray-knife binary was not found. An environment fault, not a data one."""


class XrayKnifeFailed(RuntimeError):
    """The tool ran but did not finish properly: non-zero exit or hard timeout."""


class EmptyInput(ValueError):
    """Input is missing or empty.

    Raised rather than returning zero results because both cases make the tool
    block on stdin (rc=124 under CI's open stdin). This closes that path before
    the process is ever started.
    """


class OutputNotWritten(RuntimeError):
    """The tool reported success but no file exists.

    Measured with -o pointing into a missing directory: rc=0, a cheerful
    "Results have been saved to ...", and no file. Without this check, total data
    loss looks like "zero healthy configs".
    """


class MalformedCsv(ValueError):
    """The CSV does not match the 15-column contract; upstream changed the schema."""


# --------------------------------------------------------------------------- #
# Row-level judgement
# --------------------------------------------------------------------------- #

def _as_int(value: Optional[str]) -> Optional[int]:
    """Integer value, or None when it is not numeric (covers "null" and empty)."""
    if value is None:
        return None
    text = value.strip()
    if not text or text == NULL_TOKEN:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def is_row_genuinely_ok(row: Dict[str, str]) -> bool:
    """Whether this row means "the proxy really worked".

    Four conditions, all required::

        status in OK_STATUSES     includes semi-passed, see note 1
        total >= 1                broken rows report total = 0
        success == total          every endpoint succeeded
        200 <= code < 400         the HTTP response really succeeded

    The total >= 1 clause exists only because of measurement: without it,
    success == total was also true for 87 broken rows (0 == 0).

    Validated on the full 3,845 row census: this lock accepts exactly 504 rows
    and its set is identical to the status-only set, so it is neither stricter
    nor looser, it confirms the same verdict two independent ways.
    """
    if (row.get("status") or "").strip() not in OK_STATUSES:
        return False
    total = _as_int(row.get("total"))
    success = _as_int(row.get("success"))
    code = _as_int(row.get("code"))
    if total is None or success is None or code is None:
        return False
    if total < 1 or success != total:
        return False
    return CODE_MIN_OK <= code < CODE_MAX_OK


def row_delay_ms(row: Dict[str, str]) -> Optional[int]:
    """Delay in ms, or None. Measured range across successes: 54 to 4,776."""
    delay = _as_int(row.get("delay"))
    if delay is None or delay < 0:
        return None
    return delay


def row_location(row: Dict[str, str]) -> Optional[str]:
    """Country code as reported by the tool, or None when null/empty."""
    location = (row.get("location") or "").strip()
    if not location or location == NULL_TOKEN:
        return None
    return location


def row_tls(row: Dict[str, str]) -> str:
    """Raw security layer. Observed values: tls 2,032, empty 828, none 565,
    reality 414, false 4, "..." 1, auto 1. Deciding what counts as "secure"
    belongs to the publishing layer, not here.
    """
    return (row.get("tls") or "").strip()


# --------------------------------------------------------------------------- #
# CSV reading
# --------------------------------------------------------------------------- #

def parse_csv(text: str) -> List[Dict[str, str]]:
    """Turn the tool's CSV into dict rows.

    Uses the `csv` module deliberately, see note 7. A header that does not match
    CSV_COLUMNS raises instead of returning an empty list, because reading the
    wrong column would mis-grade every config.
    """
    if not text.strip():
        return []
    reader = csv.DictReader(io.StringIO(text))
    header = tuple(reader.fieldnames or ())
    if header != CSV_COLUMNS:
        raise MalformedCsv(
            f"the CSV header does not match the measured 15-column contract.\n"
            f"  expected: {CSV_COLUMNS}\n"
            f"  actual  : {header}\n"
            f"An upstream schema change must break loudly; reading the wrong "
            f"column silently would mis-grade every config."
        )
    rows: List[Dict[str, str]] = []
    for raw in reader:
        if raw.get(None) is not None:
            raise MalformedCsv(
                f"a CSV row carries more fields than the 15-column contract: "
                f"{raw.get(None)!r}"
            )
        if any(value is None for value in raw.values()):
            raise MalformedCsv(
                f"a CSV row is short of the 15-column contract: {raw!r}")
        rows.append({key: (value or "") for key, value in raw.items()})
    return rows


def _delay_summary(ok_links: Sequence[str],
                   by_link: Dict[str, Dict[str, str]]) -> Dict[str, Optional[int]]:
    """min / median / max delay over successful rows.

    ``delay_median`` is the upper median for an even count. Kept as-is because
    the value is published in health.json and a true median would shift it.
    """
    delays = sorted(d for d in (row_delay_ms(by_link[link]) for link in ok_links)
                    if d is not None)
    if not delays:
        return {"delay_min": None, "delay_median": None, "delay_max": None}
    return {
        "delay_min": delays[0],
        "delay_median": delays[len(delays) // 2],
        "delay_max": delays[-1],
    }


def classify(rows: Sequence[Dict[str, str]]) -> Dict[str, Any]:
    """Sort rows into ok / failed / broken and build the stats block.

    The failed/broken split is deliberate: broken means the config was never
    built (bad data, fixable at the source), failed means the server did not
    answer (normal and transient). Merging them hides source quality.
    """
    ok: List[str] = []
    failed: List[str] = []
    broken: List[str] = []
    by_status: Dict[str, int] = {name: 0 for name in ALL_STATUSES}
    unknown_status: Dict[str, int] = {}
    by_link: Dict[str, Dict[str, str]] = {}

    for row in rows:
        link = row.get("link") or ""
        by_link[link] = row
        status = (row.get("status") or "").strip()
        if status in by_status:
            by_status[status] += 1
        else:
            unknown_status[status] = unknown_status.get(status, 0) + 1
        if is_row_genuinely_ok(row):
            ok.append(link)
        elif status == STATUS_BROKEN:
            broken.append(link)
        else:
            failed.append(link)

    stats: Dict[str, Any] = {
        "rows": len(rows),
        "ok": len(ok),
        "failed": len(failed),
        "broken": len(broken),
        "ok_pct": round(100.0 * len(ok) / len(rows), 2) if rows else 0.0,
        "by_status": by_status,
        "with_location": sum(1 for link in ok if row_location(by_link[link])),
        **_delay_summary(ok, by_link),
    }
    if unknown_status:
        # Not an error, but it must be visible: only four statuses were ever
        # measured, so a fifth means upstream changed something.
        stats["unknown_status"] = unknown_status
    return {"ok": ok, "failed": failed, "broken": broken,
            "rows": by_link, "stats": stats}


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #

def resolve_binary(binary: Optional[str] = None) -> str:
    """Absolute path of the tool, or raise :class:`XrayKnifeMissing`."""
    name = binary or XK_BIN
    if os.path.sep in name:
        if os.path.isfile(name) and os.access(name, os.X_OK):
            return os.path.abspath(name)
        raise XrayKnifeMissing(f"xray-knife is not an executable file at {name!r}")
    found = shutil.which(name)
    if not found:
        raise XrayKnifeMissing(
            f"xray-knife ({name!r}) is not on PATH. CI installs it pinned to "
            f"a checksum-verified release; locally, put the binary on PATH or "
            f"set L3_XK_BIN.")
    return found


def _non_blank_count(path: str) -> int:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.strip())


def _unique_links(path: str) -> List[str]:
    seen: Dict[str, None] = {}
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            text = line.strip()
            if text:
                seen.setdefault(text, None)
    return list(seen)


def build_argv(in_path: str, out_path: str, *,
               binary: str,
               test_url: Optional[str] = None,
               threads: Optional[int] = None,
               mdelay_ms: Optional[int] = None,
               timeout_ms: Optional[int] = None,
               max_passed: int = 0,
               retries: int = 0) -> List[str]:
    """Full command line. No flag is left to its default unless that default was
    measured and accepted.

    ``--rip`` is deliberately untouched: it defaults to true, and an A/B run
    showed --rip=false leaves the location column empty in every row, which makes
    country-from-xray-knife impossible.
    """
    argv = [
        binary, "http",
        "-f", in_path,
        "-x", "csv",
        "-o", out_path,
        "-t", str(int(THREADS if threads is None else threads)),
        "-d", str(int(MDELAY_MS if mdelay_ms is None else mdelay_ms)),
        "--timeout", str(int(TIMEOUT_MS if timeout_ms is None else timeout_ms)),
        "-u", TEST_URL if test_url is None else test_url,
    ]
    if max_passed:
        argv += ["--max-passed", str(int(max_passed))]
    if retries:
        argv += ["--retries", str(int(retries))]
    return argv


def _require_usable_input(in_path: str) -> int:
    """Number of non-blank lines, or raise :class:`EmptyInput`.

    Runs before the binary is resolved. The check is free and it closes the hang
    path, so ordering it first means the anti-hang guard is still exercised on a
    machine that does not have the tool installed.
    """
    if not os.path.isfile(in_path):
        raise EmptyInput(
            f"input file does not exist: {in_path!r}. Measured: xray-knife then "
            f"falls back to reading stdin and blocks forever (rc=124 under CI's "
            f"open stdin).")
    lines = _non_blank_count(in_path)
    if lines == 0:
        raise EmptyInput(
            f"input file has no non-blank line: {in_path!r}. Measured: an empty "
            f"file makes xray-knife wait on stdin (rc=124 under CI's open "
            f"stdin). This is exactly what happens when L2 leaves zero open "
            f"endpoints, so it must be handled, not hoped away.")
    return lines


def _prepare_output(out_path: Optional[str]) -> Tuple[str, bool]:
    """Return ``(path, owned)`` with the parent created and stale output removed.

    Ownership matters for cleanup: a caller-supplied path belongs to the caller
    and must survive, while a path we created with mkstemp is ours and must be
    removed on every exit path. Leak measured before this split: one leftover
    l3_*.csv per run without out_path, three per L3_ROUNDS=3 pipeline round, plus
    one on each exception path.

    Stale output is removed before the run because a failed run leaves the
    previous file intact, and it would then be read as fresh results.
    """
    owned = out_path is None
    if owned:
        handle, out_path = tempfile.mkstemp(prefix="l3_", suffix=".csv")
        os.close(handle)
    assert out_path is not None
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    if os.path.exists(out_path):
        os.remove(out_path)
    return out_path, owned


def _execute(argv: Sequence[str], limit: int) -> Tuple[str, float]:
    """Run the tool and return ``(output, elapsed_sec)``.

    ``stdin=DEVNULL`` is the second anti-hang defence and the timeout is the
    third. A non-zero exit or a timeout raises :class:`XrayKnifeFailed`.
    """
    started = time.time()
    try:
        proc = subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=limit,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise XrayKnifeFailed(
            f"xray-knife did not finish within {limit}s. The measured full "
            f"census of 3,845 configs took 43s, so this is not slowness - it is "
            f"a stuck run."
        ) from exc
    elapsed = round(time.time() - started, 2)
    output = (proc.stdout or b"").decode("utf-8", errors="replace")
    if proc.returncode != 0:
        raise XrayKnifeFailed(
            f"xray-knife exited {proc.returncode}.\n"
            f"--- last output ---\n{output[-2000:]}")
    return output, elapsed


def _read_result(out_path: str, output: str) -> Dict[str, Any]:
    """Verify the file exists, then parse and classify it."""
    if not os.path.isfile(out_path):
        raise OutputNotWritten(
            f"xray-knife exited 0 but wrote no file at {out_path!r}. Measured: "
            f"with a missing parent directory it prints 'Results have been saved "
            f"to ...' and creates nothing.\n"
            f"--- last output ---\n{output[-2000:]}")
    with open(out_path, encoding="utf-8", errors="replace") as handle:
        return classify(parse_csv(handle.read()))


def run_test(in_path: str, *,
             out_path: Optional[str] = None,
             binary: Optional[str] = None,
             test_url: Optional[str] = None,
             threads: Optional[int] = None,
             mdelay_ms: Optional[int] = None,
             timeout_ms: Optional[int] = None,
             max_passed: int = 0,
             retries: int = 0,
             hard_timeout: Optional[int] = None) -> Dict[str, Any]:
    """Run L3 over an input file and return the graded result.

    Step order, each step behind a measurement (see the module docstring)::

        1 input exists and is non-blank        -> EmptyInput
        2 binary resolved                      -> XrayKnifeMissing
        3 output parent created, stale removed
        4 run with stdin=DEVNULL and a hard timeout -> XrayKnifeFailed
        5 output file verified                 -> OutputNotWritten
        6 CSV parsed with the csv module and graded -> MalformedCsv

    ``partial`` means the CSV has fewer rows than the input had unique links. A
    missing link must never be read as a failure: --max-passed truncates output,
    and the tool also drops duplicates itself.

    ``out_path`` is still reported for contract stability, but when this function
    created the file it no longer exists on disk by the time you read the key.
    """
    n_lines = _require_usable_input(in_path)
    resolved = resolve_binary(binary)
    out_path, owned = _prepare_output(out_path)

    try:
        argv = build_argv(in_path, out_path, binary=resolved,
                          test_url=test_url, threads=threads,
                          mdelay_ms=mdelay_ms, timeout_ms=timeout_ms,
                          max_passed=max_passed, retries=retries)
        limit = int(HARD_TIMEOUT if hard_timeout is None else hard_timeout)
        output, elapsed = _execute(argv, limit)
        result = _read_result(out_path, output)

        unique_in = _unique_links(in_path)
        result["partial"] = len(result["rows"]) < len(unique_in)
        result["stats"].update(
            elapsed_sec=elapsed,
            lines_in=n_lines,
            unique_in=len(unique_in),
            test_url=TEST_URL if test_url is None else test_url,
            threads=int(THREADS if threads is None else threads),
        )
        result["out_path"] = out_path
        return result
    finally:
        # Outside every branch on purpose: our temp file goes even when an
        # exception propagates, and cleanup must never mask the original error.
        if owned:
            try:
                os.remove(out_path)
            except OSError:
                pass


def test_lines(lines: Iterable[str], **kwargs: Any) -> Dict[str, Any]:
    """L3 over in-memory lines. Written to a temp file first."""
    handle, path = tempfile.mkstemp(prefix="l3_in_", suffix=".txt")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            for line in lines:
                text = line.strip()
                if text:
                    out.write(text + "\n")
        return run_test(path, **kwargs)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def test_file(path: str, **kwargs: Any) -> Dict[str, Any]:
    return run_test(path, **kwargs)


def _main(argv: Sequence[str]) -> int:
    import json

    if len(argv) < 2:
        print(f"usage: {os.path.basename(argv[0])} <configs.txt> [out.csv]",
              file=sys.stderr)
        return 64

    try:
        result = test_file(argv[1], out_path=argv[2] if len(argv) > 2 else None)
    except (XrayKnifeMissing, EmptyInput) as exc:
        print(f"!! {exc}", file=sys.stderr)
        return 2
    except (XrayKnifeFailed, OutputNotWritten, MalformedCsv) as exc:
        print(f"!! {exc}", file=sys.stderr)
        return 3

    payload = {"stats": result["stats"], "partial": result["partial"]}
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
