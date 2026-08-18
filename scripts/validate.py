# -*- coding: utf-8 -*-
"""Output gate: validate generated client configs with the real clients.

One bad node makes a client reject the *whole* ``clash.yaml`` or
``singbox.json``, so one broken line means zero configs for the user.
"Almost valid" output is worthless, hence this gate runs the same binaries the
user runs:

    sing-box check -c <file>
    mihomo -t -d <tmpdir> -f <file>

When a binary is unavailable (local development) the check falls back to a
structural one (parsable JSON/YAML, required keys, no dangling references) and
is reported as ``skipped``, never as a false ``pass``.

Two kinds of category, two rules
    core     ``all/ heavy/ light/`` are always produced, so absence is an error.
    optional ``verified/ fast/ secure/`` only exist when the L3 real-proxy test
             ran. Rule is "mandatory if present": a missing directory is
             skipped, but a present directory with a broken file is a failure.
             They are kept out of ``CORE_CATEGORIES`` because ``report["ok"]``
             requires ``missing == 0``, so folding them in would have closed
             the gate before their producer existed.

Standalone use::

    python scripts/validate.py --out .
    python scripts/validate.py --out . --strict   # non-zero exit on failure
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple

#: Always produced by the pipeline. Absence is an error.
CORE_CATEGORIES = ("all", "heavy", "light")

#: Produced only when the L3 cascade ran. Mandatory if present, see module doc.
OPTIONAL_CATEGORIES = ("verified", "fast", "secure")

#: Backwards compatible export for external consumers.
CATEGORIES = CORE_CATEGORIES + OPTIONAL_CATEGORIES

# Import-time guard, not publish-time. If a rename ever made a core category
# optional, `all/` could silently count as "not produced" and the gate would go
# green with zero configs, the worst possible silent failure here.
assert not (set(CORE_CATEGORIES) & set(OPTIONAL_CATEGORIES)), \
    "a core category must never be optional"
assert len(set(CATEGORIES)) == len(CATEGORIES), "duplicate category name"

#: Per-binary wall clock budget, seconds.
CHECK_TIMEOUT = 180

#: Gate allow-list. Only these statuses pass; anything else, including a status
#: added in the future, closes the gate.
#:
#: This is module level on purpose: the invariant test looks it up with
#: `hasattr(validate, "ACCEPTABLE_STATUSES")`. While it was a local variable the
#: test silently fell back to its own copy, and widening the local tuple to a
#: fully fail-open one kept all five tests green. One source of truth only.
#:
#: `skipped` is acceptable because it only happens without client binaries, and
#: a broken structural check reports `fail`, not `skipped`. In CI the install
#: step is fail-closed, so reaching `skipped` there means the job already broke.
ACCEPTABLE_STATUSES = ("pass", "skipped")

#: sing-box and mihomo colourise output, which corrupts string comparisons in
#: CI logs.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _clean(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _find_binary(*names: str) -> Optional[str]:
    """Locate a binary on PATH, then in the usual CI install locations."""
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    for name in names:
        for candidate in (f"/usr/local/bin/{name}", f"/usr/bin/{name}", f"./{name}"):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


def _run(cmd: List[str]) -> Tuple[int, str]:
    """Run a command, returning ``(returncode, combined_output)``.

    Exit codes 124 and 125 are synthetic: timeout and launch failure.
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=CHECK_TIMEOUT)
        return proc.returncode, _clean((proc.stdout or "") + (proc.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {CHECK_TIMEOUT}s"
    except Exception as exc:  # noqa: BLE001
        return 125, f"{type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------- #
# Structural fallback checks, used when a client binary is unavailable
# --------------------------------------------------------------------------- #

StructuralCheck = Callable[[str], Tuple[bool, str]]


def _total_check(fn: StructuralCheck) -> StructuralCheck:
    """Make a structural check total: it reports, it never raises.

    The checks below used to assume the document's shape. Fuzzing malformed
    documents found 23 distinct shapes that raised (route as a string, tag as a
    list, selector.outbounds as an int, proxy-groups as a mapping, ...), and
    neither call site wrapped them, so one broken file killed the entire gate
    instead of scoring a single ``fail``.

    Turning an exception into ``(False, ...)`` is not softening the gate: these
    functions decide whether a file is acceptable, and an unexpected shape is by
    definition not acceptable. It stays fail-closed, ``False`` maps to ``fail``,
    which clears ``report["ok"]`` and stops publication under ``--strict``. The
    exception type is kept in the message so debugging is not blind.
    """
    def wrapper(path: str) -> Tuple[bool, str]:
        try:
            return fn(path)
        except Exception as exc:  # noqa: BLE001
            return False, (f"unexpected document shape "
                           f"({type(exc).__name__}: {str(exc)[:120]})")
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    wrapper.__wrapped__ = fn  # type: ignore[attr-defined]
    return wrapper


def _is_unhashable(value: Any) -> bool:
    """True for container types that cannot be used as a tag/name."""
    return isinstance(value, (dict, list, set))


@_total_check
def _structural_singbox(path: str) -> Tuple[bool, str]:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        return False, f"JSON parse error: {exc}"
    # Valid JSON need not be an object: `[]`, `"x"`, `42`, `null`, `true` are
    # all valid documents and all used to raise AttributeError here.
    if not isinstance(doc, dict):
        return False, f"top-level JSON must be an object, got {type(doc).__name__}"
    outbounds = doc.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        return False, "missing/empty outbounds"

    tags = set()
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            return False, "non-object outbound"
        tag = outbound.get("tag")
        if _is_unhashable(tag):
            return False, f"outbound tag must be a scalar, got {type(tag).__name__}"
        tags.add(tag)

    # Every selector/urltest reference must resolve, or sing-box rejects the
    # whole file with "outbound not found".
    for outbound in outbounds:
        if outbound.get("type") not in ("selector", "urltest"):
            continue
        refs = outbound.get("outbounds", [])
        # Only lists are walked. An int raised TypeError, and a string or dict
        # iterated per character or per key and produced a misleading
        # "dangling reference: 'a'".
        if not isinstance(refs, list):
            return False, (f"{outbound.get('tag')!r}: selector/urltest outbounds "
                           f"must be a list, got {type(refs).__name__}")
        for ref in refs:
            if ref not in tags:
                return False, f"dangling reference: {ref!r}"

    route = doc.get("route")
    if route is not None and not isinstance(route, dict):
        return False, f"route must be an object, got {type(route).__name__}"
    final = (route or {}).get("final")
    if final and final not in tags:
        return False, f"route.final points to unknown tag: {final!r}"
    return True, f"structural ok ({len(outbounds)} outbounds)"


@_total_check
def _structural_clash(path: str) -> Tuple[bool, str]:
    try:
        import yaml
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except Exception as exc:  # noqa: BLE001
        return False, f"YAML parse error: {exc}"
    # safe_load returns None for an empty or comment-only file and a non-dict
    # for a list/scalar document.
    if not isinstance(doc, dict):
        got = "empty document" if doc is None else type(doc).__name__
        return False, f"top-level YAML must be a mapping, got {got}"
    proxies = doc.get("proxies")
    if not isinstance(proxies, list) or not proxies:
        return False, "missing/empty proxies"

    names = set()
    for proxy in proxies:
        # A non-dict entry used to just fall out of `names` and get reported as
        # a misleading "duplicate proxy names".
        if not isinstance(proxy, dict):
            return False, "non-object proxy entry"
        name = proxy.get("name")
        if _is_unhashable(name):
            return False, f"proxy name must be a scalar, got {type(name).__name__}"
        names.add(name)
    if len(names) != len(proxies):
        return False, "duplicate proxy names (mihomo rejects the file)"

    groups = doc.get("proxy-groups") or []
    if not isinstance(groups, list):
        return False, f"proxy-groups must be a list, got {type(groups).__name__}"
    group_names = {g.get("name") for g in groups if isinstance(g, dict)}
    for group in groups:
        if not isinstance(group, dict):
            return False, "non-object proxy-group entry"
        refs = group.get("proxies", [])
        if not isinstance(refs, list):
            return False, (f"group {group.get('name')!r}: proxies must be a list, "
                           f"got {type(refs).__name__}")
        for ref in refs:
            if ref not in names and ref not in group_names:
                return False, f"group {group.get('name')!r} references unknown proxy {ref!r}"
    return True, f"structural ok ({len(proxies)} proxies)"


# --------------------------------------------------------------------------- #
# Real client checks
# --------------------------------------------------------------------------- #

def _fallback(path: str, check: StructuralCheck, note: str) -> Dict[str, Any]:
    ok, detail = check(path)
    return {"status": "skipped" if ok else "fail", "detail": detail, "note": note}


def check_singbox(path: str, binary: Optional[str]) -> Dict[str, Any]:
    """Validate a ``singbox.json`` with sing-box, or structurally."""
    if not os.path.isfile(path):
        return {"status": "missing", "detail": "file not found"}
    if not binary:
        return _fallback(path, _structural_singbox,
                         "sing-box binary unavailable; structural check only")
    code, out = _run([binary, "check", "-c", path])
    if code == 0:
        return {"status": "pass", "detail": "sing-box check OK"}
    detail = out.splitlines()[0][:300] if out else f"exit {code}"
    return {"status": "fail", "detail": detail}


def check_clash(path: str, binary: Optional[str]) -> Dict[str, Any]:
    """Validate a ``clash.yaml`` with mihomo, or structurally."""
    if not os.path.isfile(path):
        return {"status": "missing", "detail": "file not found"}
    if not binary:
        return _fallback(path, _structural_clash,
                         "mihomo binary unavailable; structural check only")
    # mihomo -t needs a writable working directory.
    with tempfile.TemporaryDirectory() as workdir:
        code, out = _run([binary, "-t", "-d", workdir, "-f", path])
    bad = [line for line in out.splitlines()
           if "level=error" in line or "level=fatal" in line]
    if code == 0 and not bad:
        return {"status": "pass", "detail": "mihomo -t OK"}
    detail = bad[0] if bad else (out.splitlines()[0] if out else f"exit {code}")
    return {"status": "fail", "detail": detail[:300]}


def validate_outputs(out_dir: str) -> Dict[str, Any]:
    """Validate every Clash/sing-box output and return the gate report."""
    singbox_bin = _find_binary("sing-box")
    mihomo_bin = _find_binary("mihomo", "clash-meta", "clash")
    report: Dict[str, Any] = {
        "tools": {"sing_box": singbox_bin or None, "mihomo": mihomo_bin or None},
        "results": {},
        "summary": {"pass": 0, "fail": 0, "skipped": 0, "missing": 0},
    }

    absent: List[str] = []
    for category in CATEGORIES:
        cat_dir = os.path.join(out_dir, category)
        # An optional category that does not exist at all was simply not
        # produced. If the directory *is* there it is judged exactly like a core
        # category, never more leniently.
        if category in OPTIONAL_CATEGORIES and not os.path.isdir(cat_dir):
            absent.append(category)
            continue
        report["results"][category] = {
            "singbox": check_singbox(os.path.join(cat_dir, "singbox.json"), singbox_bin),
            "clash": check_clash(os.path.join(cat_dir, "clash.yaml"), mihomo_bin),
        }
    report["absent_optional"] = absent

    # Invariant: a core category is never skipped. With no directory its files
    # come back `missing` and the gate closes there.
    assert all(c in report["results"] for c in CORE_CATEGORIES), \
        "every core category must be checked"

    for results in report["results"].values():
        for result in results.values():
            status = result["status"]
            report["summary"][status] = report["summary"].get(status, 0) + 1

    # Allow-list, not deny-list. The old `fail == 0 and missing == 0` shape was
    # fail-open: a future status such as "timeout" would be counted in summary
    # but matched by neither condition, so the gate went green with errors
    # present. Verified equivalent to the old shape across all 81 combinations
    # of the four real statuses; it only differs on unknown ones.
    offending = {status: count for status, count in report["summary"].items()
                 if count > 0 and status not in ACCEPTABLE_STATUSES}
    report["offending"] = offending
    report["ok"] = not offending

    # "Nothing was proven" has to be visible. With no binaries the run is
    # pass=0 skipped=6 ok=True rc=0, which is by design and must not become a
    # failure, but it should not be invisible either.
    report["real_validation"] = report["summary"]["pass"] > 0
    return report


def _print_report(rep: Dict[str, Any]) -> None:
    icons = {"pass": "\N{WHITE HEAVY CHECK MARK}", "fail": "\N{CROSS MARK}",
             "skipped": "\N{WARNING SIGN}", "missing": "\N{NO ENTRY SIGN}"}
    print("\N{LEFT-POINTING MAGNIFYING GLASS} Client validation")
    print(f"   sing-box: {rep['tools']['sing_box'] or 'NOT FOUND (structural fallback)'}")
    print(f"   mihomo  : {rep['tools']['mihomo'] or 'NOT FOUND (structural fallback)'}")
    for category, results in rep["results"].items():
        for kind, result in results.items():
            print(f"   {icons.get(result['status'], '?')} {category:<5} {kind:<8} "
                  f"{result['status']:<8} {result['detail']}")
    for category in rep.get("absent_optional", []):
        print(f"   \N{HEAVY MINUS SIGN} {category:<5} {'-':<8} not produced in this run")

    summary = rep["summary"]
    print(f"   -> pass={summary['pass']} fail={summary['fail']} "
          f"skipped={summary['skipped']} missing={summary['missing']}")
    # Name any unknown status that closed the gate, otherwise "why is it red?"
    # has no answer.
    extra = {k: v for k, v in summary.items()
             if v > 0 and k not in ("pass", "fail", "skipped", "missing")}
    if extra:
        print(f"   \N{WARNING SIGN} unrecognised statuses (gate closed): {extra}")
    if not rep.get("real_validation", False):
        print("   \N{WARNING SIGN} structural fallback only - no real client validated this run")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate generated client configs")
    parser.add_argument("--out", default=os.getcwd(),
                        help="repo root containing all/ heavy/ light/")
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero when any file fails validation")
    parser.add_argument("--json", dest="json_path", default="",
                        help="also write the report to this path")
    args = parser.parse_args()

    rep = validate_outputs(os.path.abspath(args.out))
    _print_report(rep)

    if args.json_path:
        target = os.path.abspath(args.json_path)
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, ensure_ascii=False, indent=2)

    if args.strict and not rep["ok"]:
        print("\N{CROSS MARK} Validation gate FAILED - outputs must not be published.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
