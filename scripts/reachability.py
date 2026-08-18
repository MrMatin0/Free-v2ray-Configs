#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L2 of the cascade: TCP reachability.

    L0  endpoint dedup        filters.py
    L1  cheap offline filter  filters.py
    L2  TCP handshake         this module
    L3  real proxy test       realtest.py

L2 exists because L3 is expensive: it boots a full core per config, so any
endpoint whose socket will not even open is pure waste.

Four measured design decisions

1. DNS is separated from TCP. `asyncio.open_connection(host, port)` resolves via
   getaddrinfo on asyncio's default executor, which has only
   min(32, nproc + 4) threads, i.e. 6 on this runner. That made any concurrency
   setting meaningless because DNS, not sockets, was the bottleneck. So names are
   resolved once through a dedicated 64-thread pool and TCP then works on IPs.

2. Concurrency 800 is a measured ceiling, not taste. On 6,921 unique endpoints:
   200 -> 53.87s, 400 -> 30.63s, 800 -> 19.45s (peak fd 806, zero EMFILE),
   1200 -> collapse: 5,700 EMFILE errors, measured open rate fell from 48.0% to
   1.1%, and the exit code was still 0. The soft `ulimit -n` here is 1024.

3. EMFILE is counted separately and is fatal. Decision 2 was only discoverable
   because errno 24 was not lumped in with "refused"; otherwise fd exhaustion
   looks like "99% of servers are broken". There is a second invariant, no socket
   left open after the run, and it is judged by counting *sockets*, not by the
   total fd delta, which was measurably wrong in both directions. See
   socket_fd_count().

4. Up to three addresses per host are probed. 439 hosts have more than one
   address; on that subset cap 1 -> 390 open, cap 2 -> 406, cap 3 -> 409,
   cap 4 -> 409, uncapped -> 411. So "first address only" lost 5.1% of open
   endpoints and cap 3 recovers 99.5% of them for 13.9% more probes.

Why geo.resolve_all is not reused: the house rule is delegate, do not rewrite,
but geo is deliberately AF_INET because country labels come from an IPv4
database. Over 1,354 real named hosts the two agree within noise, except
`litev6.abalahrar.ir`, which was IPv6-only in 3 of 3 repeats and raised
gaierror under AF_INET every time. Irrelevant for a country label, wrong for
"does it connect?", so AF_UNSPEC is required here.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

Endpoint = Tuple[str, int]
Target = Tuple[Endpoint, Tuple[str, ...]]

# --------------------------------------------------------------------------- #
# Tunables. All measured, all overridable from the environment.
# --------------------------------------------------------------------------- #

#: TCP concurrency. 800 is the measured ceiling under a soft ulimit of 1024.
CONCURRENCY = int(os.environ.get("L2_CONCURRENCY", "800"))

#: TCP handshake budget. Recovery was identical at 1, 2, 3 and 5 seconds, so
#: this is the smallest value with safe margin.
TCP_TIMEOUT = float(os.environ.get("L2_TCP_TIMEOUT", "3"))

#: DNS pool size. Deliberately aligned with geo.py.
DNS_WORKERS = int(os.environ.get("L2_DNS_WORKERS", "64"))

#: Per-lookup DNS budget.
DNS_TIMEOUT = float(os.environ.get("L2_DNS_TIMEOUT", "4"))

#: Max addresses probed per host. 3 recovers 99.5% of multi-address endpoints.
ADDR_CAP = int(os.environ.get("L2_ADDR_CAP", "3"))

#: Spare descriptors we want left over before warning about concurrency.
_FD_HEADROOM = 200

ERR_TIMEOUT = "timeout"
ERR_REFUSED = "refused"
ERR_UNREACHABLE = "unreachable"
ERR_DNS = "dns_failed"
ERR_EMFILE = "emfile"
ERR_OTHER = "other"
ALL_ERRORS = (ERR_TIMEOUT, ERR_REFUSED, ERR_UNREACHABLE, ERR_DNS,
              ERR_EMFILE, ERR_OTHER)

# errno values worth distinguishing. Anything else is ERR_OTHER.
_ERRNO_REASON = {
    24: ERR_EMFILE,        # EMFILE, the tool is broken, not the server
    111: ERR_REFUSED,      # ECONNREFUSED, host is up
    101: ERR_UNREACHABLE,  # ENETUNREACH
    113: ERR_UNREACHABLE,  # EHOSTUNREACH
}


class FileDescriptorExhaustion(RuntimeError):
    """fd exhaustion happened, so the measurement is void, not just noisy.

    Raised rather than logged because at concurrency 1200 the process exited 0
    and reported a 1.1% open rate when the truth was 48.0%. A 44x silent
    failure; the only defence is for the error to be loud.
    """


# --------------------------------------------------------------------------- #
# DNS stage
# --------------------------------------------------------------------------- #

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip().strip("[]"))
        return True
    except ValueError:
        return False


def _resolve_one(host: str) -> Tuple[str, Tuple[str, ...]]:
    """Every address of a host, sorted and de-duplicated.

    AF_UNSPEC (the getaddrinfo default) is deliberate: this repo's real data
    contains IPv6-only hosts that AF_INET makes invisible. Sorting is deliberate
    too, otherwise "the first three addresses" is a different set per run and the
    result stops being reproducible.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:  # noqa: BLE001
        return host, ()
    return host, tuple(sorted({info[4][0] for info in infos}))


def resolve_hosts(hosts: Iterable[str]) -> Tuple[Dict[str, Tuple[str, ...]], float]:
    """host -> addresses, concurrently. IP literals return without a lookup.

    The default socket timeout is set around the pool and restored afterwards,
    never inside a worker: workers all write the same global, so one worker's
    saved "previous" value can be another worker's value.
    """
    out: Dict[str, Tuple[str, ...]] = {}
    named: List[str] = []
    for host in hosts:
        host = (host or "").strip()
        if not host:
            continue
        if _is_ip(host):
            out[host] = (host.strip("[]"),)
        else:
            named.append(host)

    started = time.monotonic()
    if named:
        prev = socket.getdefaulttimeout()
        socket.setdefaulttimeout(DNS_TIMEOUT)
        try:
            with ThreadPoolExecutor(max_workers=max(1, DNS_WORKERS)) as pool:
                for host, addrs in pool.map(_resolve_one, sorted(set(named))):
                    out[host] = addrs
        finally:
            socket.setdefaulttimeout(prev)
    return out, time.monotonic() - started


# --------------------------------------------------------------------------- #
# Descriptor accounting
# --------------------------------------------------------------------------- #

def fd_count() -> int:
    """Open descriptors for this process, or -1 when /proc is unavailable."""
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1


def socket_fd_count() -> int:
    """Descriptors that are *sockets*, or -1 when /proc is unavailable.

    The leak invariant used to be `fd_after > fd_before`, i.e. the total fd delta
    over a window that also covers resolve_hosts() and asyncio.run(). Measured,
    that was wrong in both directions:

    - false positive: a harmless `open(os.devnull)` living across the window
      failed a perfectly clean run with "4 open before, 5 after" and pointed the
      blame at code that had no defect.
    - false negative: the delta is two-sided, so leaking 2 real sockets while
      2 unrelated descriptors closed netted zero and the guard stayed silent.

    `/proc/self/fd/N` is a symlink that starts with `socket:` for sockets, which
    distinguishes them from files and from the event loop's `pipe:` self-pipe, so
    leftover sockets can be counted directly. This is never weaker than the old
    measure, since a leaked socket is also part of the total.

    Zero leftover sockets is achievable, not aspirational: over 25 real runs,
    resolve_hosts drifted 0/10, asyncio.run 0/10 and full check_endpoints 0/5.

    A descriptor closed between listdir() and readlink() is ignored. It did not
    stay open, so counting it would be exactly the phantom leak this replaces.
    """
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        return -1
    total = 0
    for name in names:
        try:
            if os.readlink(f"/proc/self/fd/{name}").startswith("socket:"):
                total += 1
        except OSError:
            continue
    return total


def _soft_nofile() -> int:
    try:
        import resource
        return resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except Exception:  # noqa: BLE001
        return -1


def headroom_warning(concurrency: Optional[int] = None) -> Optional[str]:
    """Warning text when concurrency crowds the fd limit, else None."""
    conc = int(concurrency or CONCURRENCY)
    soft = _soft_nofile()
    if soft > 0 and conc + _FD_HEADROOM > soft:
        return (f"concurrency={conc} leaves less than {_FD_HEADROOM} spare "
                f"descriptors under a soft limit of {soft}; at 1200 this "
                f"collapsed a 48.0% measurement to 1.1% with exit code 0")
    return None


# --------------------------------------------------------------------------- #
# TCP stage
# --------------------------------------------------------------------------- #

async def _probe(ip: str, port: int, sem: asyncio.Semaphore,
                 timeout: float, tally: Dict[str, int]) -> Optional[int]:
    """One TCP handshake. Latency in ms, or None if it did not open.

    The socket is closed immediately: holding 800 open sockets until the end of
    the run recreates the exact fd collapse this module exists to catch.
    """
    async with sem:
        started = time.monotonic()
        writer = None
        try:
            conn = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=timeout)
            return int((time.monotonic() - started) * 1000)
        except asyncio.TimeoutError:
            tally[ERR_TIMEOUT] += 1
        except OSError as exc:
            tally[_ERRNO_REASON.get(getattr(exc, "errno", None), ERR_OTHER)] += 1
        except Exception:  # noqa: BLE001
            tally[ERR_OTHER] += 1
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
        return None


async def _probe_endpoint(addrs: Sequence[str], port: int,
                          sem: asyncio.Semaphore, timeout: float,
                          tally: Dict[str, int]) -> Optional[int]:
    """One endpoint over at most ADDR_CAP addresses. Lowest successful latency.

    Lowest rather than first: a multi-address host is usually anycast or a CDN,
    so the nearest address represents the user experience.
    """
    results = await asyncio.gather(*[_probe(ip, port, sem, timeout, tally)
                                     for ip in addrs[:max(1, ADDR_CAP)]])
    successful = [r for r in results if r is not None]
    return min(successful) if successful else None


async def _run_tcp(targets: Sequence[Target], conc: int, timeout: float,
                   tally: Dict[str, int]) -> List[Optional[int]]:
    sem = asyncio.Semaphore(conc)
    return list(await asyncio.gather(*[
        _probe_endpoint(addrs, port, sem, timeout, tally)
        for (_host, port), addrs in targets
    ]))


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def _normalize(endpoints: Sequence[Endpoint]) -> List[Endpoint]:
    """Strip IPv6 brackets and coerce ports, with an attributable error."""
    out: List[Endpoint] = []
    for host, port in endpoints:
        try:
            out.append((str(host).strip().strip("[]"), int(port)))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid endpoint {(host, port)!r}: {exc}") from exc
    return out


def _assert_no_fd_damage(tally: Dict[str, int], conc: int,
                         sock_before: int, sock_after: int,
                         fd_before: int, fd_after: int) -> None:
    """Both post-run invariants. Checked after the run, never before.

    `sock_before >= 0` keeps the old contract: -1 means "/proc was unavailable,
    I do not know", and not knowing must not void a measurement.
    """
    if tally[ERR_EMFILE]:
        raise FileDescriptorExhaustion(
            f"{tally[ERR_EMFILE]} EMFILE errors at concurrency={conc}; "
            f"the measurement is void. Lower L2_CONCURRENCY or raise "
            f"`ulimit -n` (soft limit is currently {_soft_nofile()}). In a past "
            f"run this exact condition reported 1.1% instead of the true 48.0% "
            f"- with exit code 0."
        )
    if sock_before >= 0 and sock_after > sock_before:
        raise FileDescriptorExhaustion(
            f"socket leak: {sock_after - sock_before} socket descriptor(s) "
            f"still open after the measurement ({sock_before} before, "
            f"{sock_after} after). Every socket opened by a probe must be "
            f"closed before returning. (Total file descriptors went "
            f"{fd_before} -> {fd_after}; only the socket count is judged, "
            f"because an unrelated non-socket descriptor opened during the "
            f"measurement is not a leak of this module.)"
        )


def check_endpoints(endpoints: Sequence[Endpoint],
                   concurrency: Optional[int] = None,
                   timeout: Optional[float] = None) -> Dict[str, Any]:
    """Run L2 over a list of ``(host, port)``.

    Returned keys are part of the ``health.json`` contract::

        open    {(host, port): delay_ms}, open endpoints only
        closed  [(host, port)] in input order
        addrs   {host: (ip, ...)} DNS result, for inspection
        errors  {reason: count}, every reason present even at zero
        stats   counters and timings

    Raises :class:`FileDescriptorExhaustion` on any EMFILE or on a leftover
    socket: an fd-tainted result is meaningless and must not be published.

    ``stats`` carries four descriptor numbers. ``fd_before``/``fd_after`` are the
    process totals, kept for reporting only, and ``sock_before``/``sock_after``
    are the socket counts that actually decide the leak invariant.
    """
    conc = int(concurrency or CONCURRENCY)
    tmo = float(timeout or TCP_TIMEOUT)

    eps = _normalize(endpoints)
    fd_before = fd_count()
    sock_before = socket_fd_count()

    addrs, dns_s = resolve_hosts({host for host, _ in eps})
    targets: List[Target] = [(ep, addrs.get(ep[0], ())) for ep in eps]
    resolvable = [(ep, a) for ep, a in targets if a]

    tally = {reason: 0 for reason in ALL_ERRORS}
    tally[ERR_DNS] = sum(1 for _ep, a in targets if not a)

    started = time.monotonic()
    delays = asyncio.run(_run_tcp(resolvable, conc, tmo, tally))
    tcp_s = time.monotonic() - started
    fd_after = fd_count()
    sock_after = socket_fd_count()

    open_map: Dict[Endpoint, int] = {
        ep: delay for (ep, _a), delay in zip(resolvable, delays) if delay is not None
    }
    closed = [ep for ep in eps if ep not in open_map]
    probes = sum(min(max(1, ADDR_CAP), len(a)) for _ep, a in resolvable)

    result: Dict[str, Any] = {
        "open": open_map,
        "closed": closed,
        "addrs": addrs,
        "errors": tally,
        "stats": {
            "endpoints": len(eps),
            "hosts": len({host for host, _ in eps}),
            "dns_failed": tally[ERR_DNS],
            "probes": probes,
            "open": len(open_map),
            "closed": len(closed),
            "open_pct": round(100.0 * len(open_map) / len(eps), 2) if eps else 0.0,
            "concurrency": conc,
            "tcp_timeout": tmo,
            "addr_cap": max(1, ADDR_CAP),
            "dns_s": round(dns_s, 2),
            "tcp_s": round(tcp_s, 2),
            # fd_* are kept for backwards compatibility: pipeline.py publishes
            # them under cascade.layers.l2 and health.json readers expect them.
            "fd_before": fd_before,
            "fd_after": fd_after,
            "sock_before": sock_before,
            "sock_after": sock_after,
        },
    }

    _assert_no_fd_damage(tally, conc, sock_before, sock_after, fd_before, fd_after)
    return result


def check_lines(lines: Iterable[str]) -> Dict[str, Any]:
    """L0 + L1 + L2 over raw lines, attributing results back to *configs*.

    Added to the :func:`check_endpoints` output::

        kept_open   lines whose endpoint was open, in input order
        line_delay  index into kept_open -> latency in ms
        filter      L0/L1 stats from filters.py
    """
    import filters

    pre = filters.filter_lines(lines)
    res = check_endpoints(pre["endpoints"])
    open_map = res["open"]

    # Walk kept lines in order. Iterating ep_to_lines instead would group configs
    # that share an endpoint, reshuffling output for no reason.
    kept_open: List[str] = []
    line_delay: List[int] = []
    for line, endpoint in zip(pre["kept"], pre["line_endpoint"]):
        delay = open_map.get(endpoint)
        if delay is not None:
            kept_open.append(line)
            line_delay.append(delay)

    total_in = pre["stats"]["input"]
    res["kept_open"] = kept_open
    res["line_delay"] = line_delay
    res["filter"] = pre["stats"]
    res["stats"]["configs_in"] = total_in
    res["stats"]["configs_open"] = len(kept_open)
    res["stats"]["configs_open_pct"] = (
        round(100.0 * len(kept_open) / total_in, 2) if total_in else 0.0
    )
    return res


def check_file(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return check_lines(fh)


def _main(argv: Sequence[str]) -> int:
    import json

    path = argv[1] if len(argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "all", "configs.txt")

    warning = headroom_warning()
    if warning:
        print(f"# warning: {warning}", file=sys.stderr)

    try:
        res = check_file(path)
    except FileDescriptorExhaustion as exc:
        print(f"!! {exc}", file=sys.stderr)
        return 2

    print(json.dumps({"stats": res["stats"], "errors": res["errors"],
                      "filter": res["filter"]},
                     ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
