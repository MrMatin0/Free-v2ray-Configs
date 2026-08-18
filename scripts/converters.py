# -*- coding: utf-8 -*-
"""Convert V2Ray-style config URIs into Clash (Mihomo) YAML and sing-box JSON.

Supported: vless, vmess, trojan, shadowsocks, hysteria2, tuic.

hysteria2 and tuic were added because the repo README advertised them while
neither converter emitted them: 80 hysteria2 and 1 tuic config were published in
the text files and appeared zero times in clash.yaml and singbox.json. A gap
between what is advertised and what is delivered is itself a trust defect.

wireguard is deliberately excluded: unlike the rest it needs a client private key
and an assigned internal address, neither of which exists in a public URI, so any
conversion would have to invent values and produce a config that never connects.
Live count is zero wireguard configs anyway.

Golden rule: never emit invalid output. One invalid entry makes the *whole* file
unusable, because sing-box and mihomo reject the entire document on load. So any
value a client will not accept is either repaired or dropped, never passed
through raw. A config that loads cleanly and then never connects counts as
invalid too.

Every whitelist below was verified by running the real clients:
sing-box 1.13.14 and mihomo (Clash.Meta) v1.19.29.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import urllib.parse
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

import core

# --------------------------------------------------------------------------- #
# Brand: one source of truth
#
# "@Raydikalx" used to be a literal in six places here while core.BRAND_CHANNEL
# claimed to be the only definition. That was a dormant bug: changing the brand in
# core would have left clash/sing-box output on the old one.
# --------------------------------------------------------------------------- #
BRAND = core.BRAND_CHANNEL

#: Output group names, all branded, because the group is the first thing a user
#: sees in a client UI. Defined once: the names are referenced from the selector's
#: proxy list, the rules/final, the default, and the DNS detour.
GROUP_MAIN: str = f"\N{ROCKET} {BRAND}"
GROUP_AUTO: str = f"\N{BLACK UNIVERSAL RECYCLING SYMBOL} Auto | {BRAND}"
GROUP_FALLBACK: str = f"\N{DINGBAT NEGATIVE CIRCLED SANS-SERIF DIGIT NINE} Fallback | {BRAND}"


def _branded_fallback(kind: Optional[str]) -> str:
    """Branded default name for a node with no upstream remark.

    Several fallbacks here used to be unbranded (`... or "vmess"`, `... or scheme`).
    None of them fire today, because aggregate.py brands everything before the
    converters run, but a defensive default should point the right way: if data
    ever reaches the converter by another route, the default must carry the brand.

    Deterministic: a function of `kind` only.
    """
    label = (kind or "").strip() or "node"
    return f"{label} | {BRAND}"


def _enforce_brand(name: Optional[str], kind: Optional[str]) -> str:
    """Invariant gate on the final output name or tag.

    Repo policy binds the invariant at three levels: remark, name, tag. The line
    level was already covered by the branding gate in aggregate.py, but name/tag
    had none, and that gap let one unbranded node reach clash.yaml and
    singbox.json.

    Behaviour is deliberately minimal so the change delta is exactly one name:
      - already branded -> returned byte for byte, no strip, no normalising.
      - empty -> _branded_fallback(kind), i.e. exactly the old
        `cp["name"] or _branded_fallback(...)` behaviour.
      - non-empty but unbranded -> _branded_fallback(kind). This is the only delta.

    Replace rather than append: appending produced
    "...(@SomeoneElse) | @Raydikalx", which still advertises a rival channel, and
    this project treats that as the defect, not merely a missing brand.

    Never drops a node: the owner explicitly rejected the strict option.
    Idempotent, since the output always contains BRAND and the first branch
    returns it untouched.
    """
    value = name or ""
    if BRAND in value:
        return value
    return _branded_fallback(kind)


# --------------------------------------------------------------------------- #
# Validation whitelists, all extracted by running the real clients
# --------------------------------------------------------------------------- #

#: Shadowsocks methods accepted by *both* sing-box 1.13 and mihomo 1.19. Anything
#: outside this set raises "unknown method" and the whole file is rejected. Real
#: failure seen in the wild: a UUID sitting where the cipher belongs.
SS_CIPHERS: frozenset = frozenset({
    # Modern AEAD
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    # Shadowsocks 2022 (key must be base64 of an exact length, checked separately)
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    # Legacy stream ciphers: insecure, but accepted by both clients
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "chacha20-ietf", "none",
})

#: Required key length in bytes per Shadowsocks-2022 method. A wrong length makes
#: sing-box reject the whole file with "bad key length".
SS2022_KEY_BYTES: Dict[str, int] = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}

# --- ShadowsocksR ---------------------------------------------------------- #
# Policy: ssr is emitted to neither converter.
#
# sing-box removed it in 1.6.0 and now registers a stub that errors with
# "ShadowsocksR is deprecated and removed in sing-box 1.6.0", rejecting the whole
# document.
#
# Clash was the harder call. Hiddify converts the Clash file with
# xmdhs/clash2singbox, where `"ssr": "shadowsocksr"` in typeMap is commented out.
# An unsupported type is skipped but the error is accumulated and returned, and
# hiddify-core treats any conversion error as fatal. So one ssr node burns the
# entire clash.yaml. Measured on live output: all/heavy/light all exit 1 with
# "converting clash to sing-box error: comm: unsupported type ssr", while
# fast/secure/verified (no ssr) exit 0. After removing ssr all three exit 0 with
# 10,659 / 9,009 / 2,523 outbounds. 28 ssr nodes were holding 22,191 healthy ones
# hostage.
#
# This is strictly better, not a trade-off: mihomo parses `ssr://` links itself,
# and those nodes still ship untouched in configs.txt, configs_base64.txt and
# protocols/shadowsocksr.txt. Only their presence in clash.yaml changes, the one
# file they made useless for Hiddify.
#
# The three sets below are kept because _sanitize_ssr still validates ssr links on
# the text path; deleting them would remove a real validation. All values are
# taken verbatim from mihomo v1.19.29 source, nothing is guessed:
#   transport/shadowsocks/core/cipher.go -> streamList
#   transport/ssr/obfs/*.go              -> register() calls in init()
#   transport/ssr/protocol/*.go          -> register() calls in init()

#: No AEAD ciphers here, deliberately: NewShadowSocksR type-asserts to
#: *core.StreamCipher after PickCipher and rejects AEAD with "... is not none or a
#: supported stream cipher in ssr". So SS_CIPHERS is too permissive for ssr and
#: reusing it would be a silent trap. mihomo maps "none" to "dummy" internally and
#: that comparison is case sensitive, hence the lowercasing.
SSR_CIPHERS: frozenset = frozenset({
    "rc4-md5",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "chacha20", "chacha20-ietf", "xchacha20",
    "none", "dummy",
})

#: obfs registered in mihomo. tls1.2_ticket_fastauth shares a constructor with
#: tls1.2_ticket_auth but is registered under its own name, so both are allowed.
SSR_OBFS: frozenset = frozenset({
    "plain", "http_simple", "http_post", "random_head",
    "tls1.2_ticket_auth", "tls1.2_ticket_fastauth",
})

#: Protocols registered in mihomo. auth_chain_c..f exist upstream in ssr but
#: mihomo never registered them, so they must be dropped rather than published to
#: break a user's file.
SSR_PROTOCOLS: frozenset = frozenset({
    "origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1",
    "auth_chain_a", "auth_chain_b",
})

#: Valid uTLS fingerprints in sing-box 1.13. An invalid value gives
#: "unknown uTLS fingerprint".
UTLS_FINGERPRINTS: frozenset = frozenset({
    "chrome", "firefox", "edge", "safari", "ios", "android",
    "random", "randomized", "qq", "360",
})

#: Default fingerprint when a REALITY config has no fp. sing-box *requires* uTLS
#: for reality; without it the error is fatal.
DEFAULT_UTLS_FINGERPRINT = "chrome"

#: flow values valid in *both* clients. "xtls-rprx-vision-udp443" is mihomo-only
#: and gives "unsupported flow" in sing-box; -direct/-origin work in neither.
#: Since one invalid flow rejects the whole file, only the safe value is kept.
VLESS_FLOWS: frozenset = frozenset({"xtls-rprx-vision"})

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

#: tuic congestion controllers accepted by sing-box. Anything else is a load
#: error that rejects the document, so unknown values fall back to cubic.
_TUIC_CONGESTION = frozenset({"cubic", "new_reno", "bbr"})

#: Allowed ALPN values. A user-supplied string is not passed through, because a
#: meaningless value makes the client-side TLS handshake fail.
_ALPN_ALLOWED = frozenset({"h3", "h2", "http/1.1", "hysteria", "tuic", "quic"})

#: Values that are not hostnames but a textual "empty". The upstream generator
#: printed a Python or JavaScript None/null straight into the URI. Real case in
#: live data: `sni=None` (2 occurrences), which also fails DNS.
_SNI_SENTINELS = frozenset({
    "none", "null", "undefined", "nil", "nan", "false", "true",
    "localhost", "0.0.0.0", "127.0.0.1", "::1", "example.com",
})

#: One hostname label. Underscore is deliberately allowed, see _clean_sni.
_SNI_LABEL = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")


# --------------------------------------------------------------------------- #
# Field sanitisers
# --------------------------------------------------------------------------- #

def _sanitize_flow(flow: str) -> str:
    """Drop an invalid flow rather than break the whole file.

    udp443 is only a UDP path optimisation; removing it does not break the
    connection, while keeping it makes the sing-box file entirely unusable.
    """
    value = (flow or "").strip().lower()
    if value in VLESS_FLOWS:
        return value
    if value.startswith("xtls-rprx-vision"):
        return "xtls-rprx-vision"  # -udp443 variants -> the compatible base
    return ""


def _sanitize_short_id(sid: str) -> Optional[str]:
    """REALITY short-id: hex, even length, at most 16 chars.

    None means the value is corrupt (e.g. a remark glued on) and the config must
    be dropped; both clients reject the whole file with "invalid REALITY short ID".
    An empty string is legal, meaning a server without a short-id.
    """
    value = (sid or "").strip()
    if value == "":
        return ""
    if len(value) > 16 or len(value) % 2 != 0:
        return None
    if any(ch not in _HEX_DIGITS for ch in value):
        return None
    return value


def _sanitize_pbk(pbk: str) -> Optional[str]:
    """REALITY public key: unpadded base64url, 43 chars, decoding to 32 bytes."""
    value = (pbk or "").strip()
    if len(value) != 43:
        return None
    try:
        if len(base64.urlsafe_b64decode(value + "=")) != 32:
            return None
    except Exception:  # noqa: BLE001
        return None
    return value


def _sanitize_ss(cipher: str, password: str) -> Optional[Tuple[str, str]]:
    """Validate a shadowsocks (cipher, password) pair.

    None means a real client would fail on it, so it must be dropped rather than
    corrupt the whole file.
    """
    cipher = (cipher or "").strip().lower()
    if cipher not in SS_CIPHERS or not password:
        return None
    needed = SS2022_KEY_BYTES.get(cipher)
    if needed is not None:
        # SS-2022 keys are base64 of an exact length. The multi-user "PSK:PSK"
        # form is allowed, each part checked separately.
        for part in password.split(":"):
            try:
                raw = base64.b64decode(
                    part + "=" * ((4 - len(part) % 4) % 4), validate=False)
            except Exception:  # noqa: BLE001
                return None
            if len(raw) != needed:
                return None
    return cipher, password


def _ub64_text(value: Optional[str], *, allow_empty: bool = False) -> Optional[str]:
    """base64 (standard or url-safe, padded or not) -> UTF-8 text.

    Deliberately strict: invalid UTF-8 returns None instead of being silently
    truncated with errors="ignore" like elsewhere in this module. This reads the
    ssr password, and a half-decoded password produces a config that looks valid
    and never connects, the worst outcome for a user. Measured: all 28 live ssr
    lines decode cleanly and are pure ASCII, so this strictness costs nothing today.

    ``allow_empty=True`` is for optional parameters where absence is legal; it
    returns "" so the caller can tell "absent" from "corrupt".
    """
    text = (value or "").strip()
    if not text:
        return "" if allow_empty else None
    text = text.replace("-", "+").replace("_", "/")
    text += "=" * ((4 - len(text) % 4) % 4)
    try:
        return base64.b64decode(text, validate=False).decode("utf-8")
    except Exception:  # noqa: BLE001
        return None


def _sanitize_ssr(cipher: str, password: str, obfs: str,
                  protocol: str) -> Optional[Tuple[str, str, str, str]]:
    """Validate all four ssr fields against mihomo's actual registry.

    None means mihomo rejects the config and burns the whole file, so it must be
    dropped. All values are lowercased, because every registered name in mihomo is
    lowercase and PickObfs/PickProtocol do no case normalisation.
    """
    cipher = (cipher or "").strip().lower()
    if cipher not in SSR_CIPHERS or not password:
        return None
    obfs = (obfs or "").strip().lower()
    if obfs not in SSR_OBFS:
        return None
    protocol = (protocol or "").strip().lower()
    if protocol not in SSR_PROTOCOLS:
        return None
    return cipher, password, obfs, protocol


def _b64_json(value: str) -> Optional[dict]:
    try:
        text = value.strip()
        text += "=" * ((4 - len(text) % 4) % 4)
        return json.loads(base64.b64decode(text).decode("utf-8", errors="ignore"))
    except Exception:  # noqa: BLE001
        return None


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:  # noqa: BLE001
        return default


def _remark_of(line: str) -> str:
    if "#" not in line:
        return ""
    fragment = line.split("#", 1)[1]
    try:
        return urllib.parse.unquote(fragment).strip()
    except Exception:  # noqa: BLE001
        return fragment.strip()


def _truthy(value: Any) -> bool:
    """Interpret textual yes/no flags in a URI.

    Sources write "1", "true" and "yes" for the same meaning. Accepting only one
    silently reads the others as "no", so the client rejects a certificate the
    server expected it to accept.
    """
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _alpn_list(raw: Any) -> List[str]:
    """Comma-separated alpn string -> cleaned list.

    Unknown values are discarded rather than passed through: a meaningless ALPN
    fails the TLS handshake and the user reads that as "broken config".
    """
    if not raw:
        return []
    out: List[str] = []
    for part in str(raw).split(","):
        value = urllib.parse.unquote(part).strip().lower()
        if value in _ALPN_ALLOWED and value not in out:
            out.append(value)
    return out


# --------------------------------------------------------------------------- #
# Server address validation
# --------------------------------------------------------------------------- #

def _is_unroutable_server(host: Any) -> bool:
    """Whether the server address is inherently unconnectable.

    Unrelated to SNI; this is a separate upstream defect where the server address
    is 127.0.0.1 or 0.0.0.0, so the client connects to itself. Measured 32
    occurrences on live output, including 127.0.0.53 x20, which is
    systemd-resolved's local resolver: the upstream generator printed its own DNS
    address instead of the server's. Keeping them only inflates the counts, so
    they are dropped and counted in the drop telemetry.

    A non-IP hostname is not rejected here; judging that needs DNS. Its
    *structural* shape is checked by _is_structurally_invalid_server.
    """
    text = str(host or "").strip().strip("[]")
    if not text:
        return True
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False  # a hostname, not an IP; not judged here
    return bool(address.is_loopback or address.is_unspecified
                or address.is_multicast or address.is_reserved
                or address.is_link_local)


def _is_structurally_invalid_server(host: Any) -> bool:
    """Whether the server address cannot possibly be a hostname.

    Sibling of _clean_sni but on a different field: _clean_sni only cleaned `sni`
    and `host`, while `server`, the address the client actually dials, was never
    shape-checked. Advertising and placeholder values therefore reached client
    files. Measured on live output (8,152 configs), 6 configs:

        trojan 'masir_sefid', vless 'black_raven_ir', vless 'ip', vless '',
        vmess 'https://github.com/ALIILAPRO/v2rayNG-Config',
        vmess a Chinese advertising string

    Four of the six were present in the published client files, 16 occurrences
    across 6 files.

    Reject rather than repair, and DNS proved it: all six fail with gaierror, and
    the only possible repair for the URL case is `github.com`, which is the wrong
    destination entirely, so the client would dial GitHub instead of a proxy.
    Corroborating evidence: that row's uuid is "aliilapro-v2rayng-config", so the
    row is a repo advertisement, not a server.

    A single label with no dot is rejected because it only resolves on a local
    network with a search domain, never for an internet proxy.

    Not rejected: IPs, v4 or v6, bracketed or not. An IPv6 literal has no
    structural dot, and judging IP addresses is _is_unroutable_server's job.
    Underscores stay legal because names like
    `TM_AZARBAYJAB1.new.99.workers.dev` really do resolve.
    """
    text = str(host or "").strip()
    if not text:
        return True
    try:
        ipaddress.ip_address(text.strip("[]"))
        return False
    except ValueError:
        pass
    # Signs the value is a URL, a path or free text rather than a hostname.
    if any(ch in text for ch in ("/", "?", "#", "@", "\\")) or "://" in text:
        return True
    if any(ch.isspace() for ch in text):
        return True
    if ":" in text:  # leftover port on a non-IPv6 name
        return True
    if "." not in text:  # single label, never resolves on the internet
        return True
    if len(text) > 253:
        return True
    return not all(_SNI_LABEL.match(label)
                   for label in text.rstrip(".").split("."))


def _clean_sni(raw: Any) -> str:
    """Clean an SNI value: repair first, then reject.

    Real live input: `sni=https%3A%2F%2Ft.me%2Foneclickvpnkeys`, an advertising URL
    sitting where a hostname belongs. Both clients *load* it fine (verified,
    rc=0), so the file does not break, but the TLS handshake fails at connect time
    and the user sees "broken config" with no explanation. Dropping a meaningless
    SNI is better: the client then falls back to the server's own name.

    Repair before judging, because measurement showed many "invalid" values are
    correct hostnames carrying one extra character::

        $$hn.xiaohouzi.club     gaierror, while hn.xiaohouzi.club resolves
        world.yahoo.com:443     glued port, the name itself is valid
        .afrcloud22.mmv.kr      leading dot, resolves without it
        t.me%2Fripaojiedian     double-encoded, inherently a URL, unrepairable

    So: multi-layer percent-decode, strip a glued port, strip a source-marker `$`,
    strip leading/trailing dots, and only then judge. A/B over three output
    categories: old rule 2,593 unique values / 8,779 occurrences, new rule 2,625 /
    8,876 (+97), with 59 values repaired in place and 4 newly rejected. Each of
    those 4 was DNS-tested and none resolves.

    Underscore is allowed, tested rather than argued: RFC 1123 disallows it, but
    `TM_AZARBAYJAB1.new.99.workers.dev` resolves to 104.21.61.74. It is also not
    rewritten to a hyphen, because the TLS certificate was issued for the original
    name.

    A trailing dot is stripped rather than rejected: `wwwuk.mobilex55.com.`
    resolves, but RFC 6066 section 3 says the server_name extension carries the
    name without a trailing dot.

    A dotless name is rejected: `Telegram-Leviko_v2ray` is a channel name, has no
    dot and does not resolve.
    """
    text = str(raw or "").strip()
    if not text:
        return ""

    # Multi-layer percent-decode: live data contains both %2F and %252F.
    for _ in range(3):
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            break
        text = decoded
    text = text.strip()

    text = re.sub(r":\d{1,5}$", "", text)  # glued port
    text = text.strip("$").strip(".").strip()  # source marker, edge dots

    if not text or len(text) > 253:
        return ""
    if text.lower() in _SNI_SENTINELS:
        return ""
    # A URL, path or userinfo is never repairable.
    if any(ch in text for ch in ("://", "/", "?", "@", " ", ":")):
        return ""

    labels = text.split(".")
    if len(labels) < 2:
        return ""
    if not all(_SNI_LABEL.match(label) for label in labels):
        return ""
    return text


# --------------------------------------------------------------------------- #
# Drop accounting
#
# Before this, any config a converter could not express was dropped silently.
# Measured on 8,017 live configs (after hysteria2/tuic support landed):
#   Clash    68 drops  -> unparsable 60, not_expressible 8
#   Sing-box 313 drops -> unparsable 60, not_expressible 253
# Nobody knew those numbers, because there was neither a log nor a counter. A user
# importing the Clash file after reading "8,017 configs" in the README sees a
# different number and cannot find out why. The largest item, 240 vless drops in
# sing-box, had only ever been suspected.
#
# Recording the reason puts these numbers into health.json, so a change that
# suddenly drops 2,000 configs shows up in the report.
# --------------------------------------------------------------------------- #

REASON_UNPARSABLE = "unparsable"
REASON_UNROUTABLE = "unroutable_server"
REASON_INVALID_SERVER = "invalid_server"
REASON_NOT_EXPRESSIBLE = "not_expressible"
REASON_OVER_LIMIT = "over_limit"


class _DropRecorder:
    """Counts drop reasons per target and protocol.

    Counts only; the configs themselves are not retained. Holding thousands of
    strings in memory gains nothing and would bloat the report.
    """

    def __init__(self) -> None:
        self.data: Dict[str, Dict[str, Any]] = {}

    def clear_target(self, target: str) -> None:
        self.data[target] = {"total": 0, "by_reason": {}, "by_protocol": {}}

    def record(self, target: str, reason: str, line: str,
               proto: Optional[str] = None) -> None:
        entry = self.data.setdefault(
            target, {"total": 0, "by_reason": {}, "by_protocol": {}})
        entry["total"] += 1
        entry["by_reason"][reason] = entry["by_reason"].get(reason, 0) + 1
        key = proto or _scheme_of(line)
        if key:
            entry["by_protocol"][key] = entry["by_protocol"].get(key, 0) + 1

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        """Copy of the stats, for the health report."""
        return {
            target: {
                "total": entry["total"],
                "by_reason": dict(sorted(entry["by_reason"].items())),
                "by_protocol": dict(sorted(entry["by_protocol"].items(),
                                           key=lambda kv: (-kv[1], kv[0]))),
            }
            for target, entry in sorted(self.data.items())
        }


_drops = _DropRecorder()


def _scheme_of(line: str) -> str:
    """Raw scheme of a line, for grouping drops when the type is unknown."""
    text = (line or "").strip()
    index = text.find("://")
    return text[:index].lower() if 0 < index < 20 else ""


def drop_stats() -> Dict[str, Dict[str, Any]]:
    """Drop stats from the most recent conversion, written to health.json."""
    return _drops.snapshot()


# --------------------------------------------------------------------------- #
# Parsing: URI -> intermediate dict
# --------------------------------------------------------------------------- #

def _parse_vmess(line: str) -> Optional[Dict[str, Any]]:
    """Parse a base64 vmess URI.

    Name resolution order is fragment, then `ps`, then a branded fallback. vmess
    used to be the only branch reading its inner `ps` directly while the other six
    read the fragment, and that exception produced a measured defect: when the
    base64 body contains an out-of-alphabet character, core.brand_remark falls back
    to rewriting only the `#...` fragment, so a stale `ps` shipped unbranded to
    clash and sing-box. Live measurement: 1 node out of 9,706 advertising a rival
    channel.

    `ps` is not dropped like ssr's `remarks`, because 2,980 real nodes take their
    branded, country-tagged name from `ps` (they have no fragment). So this is an
    order, not a replacement. _remark_of already unquotes and strips, so an
    empty or whitespace fragment defers to `ps`.
    """
    obj = _b64_json(line[8:].split("#")[0])
    if not obj:
        return None
    security = str(obj.get("tls") or "").lower()
    path = str(obj.get("path") or "")
    return {
        "type": "vmess",
        "name": (_remark_of(line)
                 or str(obj.get("ps") or obj.get("name") or "")
                 or _branded_fallback("vmess")),
        "server": str(obj.get("add") or ""),
        "port": _safe_int(obj.get("port")),
        "uuid": str(obj.get("id") or ""),
        "alterId": _safe_int(obj.get("aid"), 0),
        "cipher": str(obj.get("scy") or "auto"),
        "network": (str(obj.get("net") or "tcp") or "tcp").lower(),
        "tls": security in ("tls", "reality"),
        # These three used to pass through raw while _clean_sni was applied only
        # to hysteria2/tuic. Live output had 431 structurally invalid hostname
        # values across vmess/vless/trojan. Every hostname input now goes through
        # one gate.
        "sni": _clean_sni(obj.get("sni") or obj.get("host")),
        "host": _clean_sni(obj.get("host")),
        "path": path,
        # For grpc, vmess uses `type` as serviceName and path usually carries it.
        "servicename": path.lstrip("/"),
        "fp": str(obj.get("fp") or "").lower(),
        "reality": security == "reality",
        "mode": str(obj.get("mode") or ""),
        "extra": str(obj.get("extra") or ""),
    }


def _parse_shadowsocks(line: str, scheme: str, name: str) -> Optional[Dict[str, Any]]:
    """Parse SIP002 ``ss://base64(method:pass)@host:port`` and the plain form."""
    rest = line[len(scheme) + 3:].split("#")[0]
    method = password = ""
    host = ""
    port = 0

    if "@" in rest:
        userinfo, hostpart = rest.rsplit("@", 1)
        hostpart = hostpart.split("?")[0]
        try:
            decoded = base64.urlsafe_b64decode(userinfo + "==").decode(
                "utf-8", errors="ignore")
            if ":" in decoded:
                userinfo = decoded
        except Exception:  # noqa: BLE001
            pass
        userinfo = urllib.parse.unquote(userinfo)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        host, _, port_text = hostpart.rpartition(":")
        port = _safe_int(port_text)
    else:
        try:
            decoded = base64.urlsafe_b64decode(rest + "==").decode(
                "utf-8", errors="ignore")
            credentials, _, hostpart = decoded.rpartition("@")
            if ":" in credentials:
                method, password = credentials.split(":", 1)
            host, _, port_text = hostpart.rpartition(":")
            port = _safe_int(port_text)
        except Exception:  # noqa: BLE001
            return None

    if not host or not port:
        return None
    # Strict validation: an invalid cipher, e.g. a UUID landing where the method
    # belongs, breaks the entire Clash/sing-box file for the user.
    validated = _sanitize_ss(method, password)
    if not validated:
        return None
    method, password = validated
    return {"type": "shadowsocks", "name": name, "server": host, "port": port,
            "cipher": method, "password": password}


def _parse_ssr(line: str, name: str) -> Optional[Dict[str, Any]]:
    """Parse ``ssr://base64(host:port:protocol:method:obfs:base64(pass)/?params)``.

    Unlike the other schemes the whole body is base64, so it is decoded by hand
    like the ss branch. Splitting on "#" is safe because "#" is in neither base64
    alphabet.
    """
    raw = _ub64_text(line[len("ssr://"):].split("#", 1)[0])
    if raw is None:
        return None
    main, _sep, query = raw.partition("/?")
    parts = main.split(":")
    if len(parts) != 6:
        # Six parts are mandatory in the ssr spec. This also rejects IPv6 hosts,
        # because ":" breaks the count, and that is correct: the ssr spec defines
        # no IPv6 form, so such a line is meaningless to mihomo too.
        return None
    host, port_text, protocol, method, obfs, password_b64 = parts
    port = _safe_int(port_text)
    password = _ub64_text(password_b64)
    if password is None or not host or not port:
        return None
    # Port range is deliberately not checked here: filters.is_invalid_port owns
    # that rule, and duplicating it would create two diverging truths.
    validated = _sanitize_ssr(method, password, obfs, protocol)
    if not validated:
        return None
    method, password, obfs, protocol = validated

    params = {k: v[0] for k, v in urllib.parse.parse_qs(query).items()}
    # The inner base64 `remarks` is deliberately unused for the name: the pipeline
    # applies core.brand_remark before building output, so a branded "#..." always
    # exists in production and _remark_of wins. Reading remarks would be dead code.
    #
    # Optional params: corrupt base64 must not drop the whole config, but it must
    # not silently become "" either, or the user thinks obfuscation is on. Empty
    # means the key is simply not written to the YAML.
    return {
        "type": "shadowsocksr",
        "name": name,
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
        "obfs": obfs,
        "protocol": protocol,
        "obfs_param": _ub64_text(params.get("obfsparam"), allow_empty=True) or "",
        "protocol_param": _ub64_text(params.get("protoparam"),
                                     allow_empty=True) or "",
    }


def _parse_hysteria2(parsed: Any, query: Dict[str, str],
                     name: str) -> Optional[Dict[str, Any]]:
    """Parse hysteria2:// or hy2://.

    Both schemes appear in real input (measured 77 and 3), so both are accepted;
    otherwise three configs would vanish silently.
    """
    if not parsed.hostname or not parsed.port:
        return None
    # The password may arrive in userinfo with or without a user part.
    password = urllib.parse.unquote(parsed.username or "")
    if parsed.password:
        extra = urllib.parse.unquote(parsed.password)
        password = f"{password}:{extra}" if password else extra
    if not password:
        return None
    obfs = (query.get("obfs") or "").strip().lower()
    # Only salamander is standard in hysteria2. An unknown value is ignored so
    # the client does not reject the whole file.
    if obfs and obfs != "salamander":
        obfs = ""
    return {
        "type": "hysteria2",
        "name": name,
        "server": parsed.hostname,
        "port": _safe_int(parsed.port),
        "password": password,
        "sni": _clean_sni(query.get("sni") or query.get("peer")),
        "insecure": _truthy(query.get("insecure") or query.get("allowInsecure")
                            or query.get("allow_insecure")),
        "obfs": obfs,
        "obfs_password": urllib.parse.unquote(
            query.get("obfs-password") or query.get("obfs_password") or ""),
        "alpn": _alpn_list(query.get("alpn")),
        "tls": True,  # hysteria2 is always QUIC/TLS
    }


def _parse_tuic(parsed: Any, query: Dict[str, str],
                name: str) -> Optional[Dict[str, Any]]:
    """Parse ``tuic://uuid:password@host:port/?...``."""
    if not parsed.hostname or not parsed.port:
        return None
    uuid = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    if not uuid or not password:
        return None
    congestion = (query.get("congestion_control")
                  or query.get("congestion-control")
                  or query.get("congestion") or "cubic").strip().lower()
    if congestion not in _TUIC_CONGESTION:
        congestion = "cubic"
    relay = (query.get("udp_relay_mode") or query.get("udp-relay-mode")
             or "native").strip().lower()
    if relay not in ("native", "quic"):
        relay = "native"
    return {
        "type": "tuic",
        "name": name,
        "server": parsed.hostname,
        "port": _safe_int(parsed.port),
        "uuid": uuid,
        "password": password,
        "congestion_control": congestion,
        "udp_relay_mode": relay,
        "sni": _clean_sni(query.get("sni")),
        "insecure": _truthy(query.get("allow_insecure") or query.get("insecure")
                            or query.get("allowInsecure")),
        "alpn": _alpn_list(query.get("alpn")),
        "tls": True,  # tuic is always QUIC/TLS
    }


def parse_proxy(line: str) -> Optional[Dict[str, Any]]:
    """One config URI -> the intermediate dict, or None."""
    line = line.strip()
    try:
        if line.startswith("vmess://"):
            return _parse_vmess(line)

        parsed = urllib.parse.urlparse(line.split("#")[0])
        query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        scheme = parsed.scheme.lower()
        name = _remark_of(line) or _branded_fallback(scheme)

        if scheme == "vless":
            security = (query.get("security") or "").lower()
            return {
                "type": "vless",
                "name": name,
                "server": parsed.hostname or "",
                "port": _safe_int(parsed.port),
                "uuid": urllib.parse.unquote(parsed.username or ""),
                "network": (query.get("type") or "tcp").lower(),
                "tls": security in ("tls", "reality"),
                "reality": security == "reality",
                "sni": _clean_sni(query.get("sni") or query.get("host")),
                "host": _clean_sni(query.get("host")),
                "path": query.get("path") or "",
                "flow": query.get("flow") or "",
                "pbk": query.get("pbk") or "",
                "sid": query.get("sid") or "",
                "fp": query.get("fp") or "",
                "servicename": (query.get("serviceName")
                                or query.get("servicename") or ""),
                # XHTTP parameters (Xray 2025/2026)
                "mode": query.get("mode") or "",
                "extra": query.get("extra") or "",
            }

        if scheme == "trojan":
            return {
                "type": "trojan",
                "name": name,
                "server": parsed.hostname or "",
                "port": _safe_int(parsed.port),
                "password": urllib.parse.unquote(parsed.username or ""),
                "network": (query.get("type") or "tcp").lower(),
                "sni": _clean_sni(query.get("sni") or query.get("host")),
                "host": _clean_sni(query.get("host")),
                "path": query.get("path") or "",
                "tls": True,  # trojan is always TLS
                "fp": query.get("fp") or "",
                "servicename": (query.get("serviceName")
                                or query.get("servicename") or ""),
                "mode": query.get("mode") or "",
                "extra": query.get("extra") or "",
            }

        if scheme in ("ss", "shadowsocks"):
            return _parse_shadowsocks(line, scheme, name)
        if scheme == "ssr":
            return _parse_ssr(line, name)
        if scheme in ("hysteria2", "hy2"):
            return _parse_hysteria2(parsed, query, name)
        if scheme == "tuic":
            return _parse_tuic(parsed, query, name)
    except Exception:  # noqa: BLE001
        return None
    return None


# --------------------------------------------------------------------------- #
# REALITY
# --------------------------------------------------------------------------- #

def _reality_params(p: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Valid ``(pbk, sid)`` for REALITY, or None.

    None in two cases: this config is not reality at all, or its values are
    corrupt. Use :func:`_reality_broken` to tell them apart.
    """
    if not p.get("reality"):
        return None
    pbk = _sanitize_pbk(p.get("pbk", ""))
    if not pbk:
        return None
    sid = _sanitize_short_id(p.get("sid", ""))
    if sid is None:
        return None
    return pbk, sid


def _reality_broken(p: Dict[str, Any]) -> bool:
    """Whether the config declares REALITY but its parameters are unusable.

    Such a config must be dropped, for both targets and for every protocol.

    This used to be checked only on the sing-box vless branch. parse_proxy also
    sets ``reality: True`` for a vmess link whose tls field is "reality", and that
    path reached _singbox_tls(), where ``reality = rp is not None`` quietly became
    False. The emitted outbound then had plain TLS and no reality block: it loads,
    so the file is accepted, and it never connects. _to_clash_proxy() had the same
    gap. That is exactly the failure the module's golden rule forbids.
    """
    return bool(p.get("reality")) and _reality_params(p) is None


# --------------------------------------------------------------------------- #
# Transport normalisation
# --------------------------------------------------------------------------- #

#: URI transport name -> the name mihomo expects. "raw" and "tcp" are the same
#: thing (Xray renamed tcp to raw in 25.x). mihomo silently falls back to TCP for
#: an unknown network, so explicit normalisation is needed or data is lost.
_CLASH_NETWORK_MAP: Dict[str, str] = {
    "tcp": "tcp", "raw": "tcp", "": "tcp", "none": "tcp",
    "ws": "ws", "websocket": "ws",
    "httpupgrade": "ws",  # mihomo builds this as ws + v2ray-http-upgrade
    "grpc": "grpc", "gun": "grpc",
    "xhttp": "xhttp", "splithttp": "xhttp",
    "h2": "h2", "http": "http",
    "kcp": "tcp", "mkcp": "tcp",  # unsupported by mihomo -> TCP
    "quic": "tcp",                # unsupported -> TCP
}

#: Transports sing-box 1.13 actually knows, verified by running it. xhttp does
#: *not* exist there, so such a config must be dropped rather than silently
#: downgraded to TCP, which would never connect while looking fine.
_SINGBOX_TRANSPORTS: frozenset = frozenset(
    {"ws", "grpc", "http", "httpupgrade", "quic"})


class _Unsupported:
    """Sentinel: this transport cannot be expressed for the target at all.

    A distinct type rather than ``False``, which the old code returned from a
    function annotated ``Optional[Dict]``. It only worked because the one caller
    compared with ``is False``; any ``if not transport`` would have merged
    "unsupported" with "no transport needed" and silently downgraded xhttp to TCP.
    """

    __slots__ = ()

    def __bool__(self) -> bool:  # pragma: no cover - guard against truthiness use
        raise TypeError("UNSUPPORTED must be compared with `is`, not truth-tested")


UNSUPPORTED = _Unsupported()

TransportResult = Union[Dict[str, Any], None, _Unsupported]


def _clash_network(raw: str) -> str:
    return _CLASH_NETWORK_MAP.get((raw or "").lower(), "tcp")


def _clash_transport_opts(p: Dict[str, Any], out: Dict[str, Any]) -> None:
    """Add transport options to a Clash proxy dict.

    Each schema is taken from real mihomo v1.19 structs
    (adapter/outbound/vless.go: WSOptions / GrpcOptions / XHTTPOptions /
    HTTP2Options).
    """
    raw = (p.get("network") or "").lower()
    net = _clash_network(raw)
    host = p.get("host") or p.get("sni") or ""
    path = p.get("path") or "/"
    out["network"] = net

    if net == "ws":
        options: Dict[str, Any] = {"path": path}
        if host:
            options["headers"] = {"Host": host}
        if raw == "httpupgrade":
            # httpupgrade is not a separate network in mihomo, it is ws + a flag.
            options["v2ray-http-upgrade"] = True
            options["v2ray-http-upgrade-fast-open"] = True
        out["ws-opts"] = options
    elif net == "grpc":
        service = p.get("servicename") or (p.get("path") or "").lstrip("/")
        out["grpc-opts"] = {"grpc-service-name": service}
    elif net == "xhttp":
        options = {"path": path}
        if host:
            options["host"] = host
        if p.get("mode"):
            options["mode"] = p["mode"]
        if p.get("extra"):
            # `extra` is raw JSON from Xray; only known keys are lifted out.
            try:
                extra = json.loads(p["extra"])
                if isinstance(extra, dict):
                    if isinstance(extra.get("xPaddingBytes"), (str, int)):
                        options["x-padding-bytes"] = str(extra["xPaddingBytes"])
                    if isinstance(extra.get("noGRPCHeader"), bool):
                        options["no-grpc-header"] = extra["noGRPCHeader"]
            except Exception:  # noqa: BLE001
                pass
        out["xhttp-opts"] = options
    elif net == "h2":
        options = {"path": path}
        if host:
            options["host"] = [host]
        out["h2-opts"] = options
    elif net == "http":
        options = {"path": [path]}
        if host:
            options["headers"] = {"Host": [host]}
        out["http-opts"] = options
    # net == "tcp" needs no transport section


def _singbox_transport(p: Dict[str, Any]) -> TransportResult:
    """sing-box transport section, None when none is needed, or UNSUPPORTED.

    UNSUPPORTED means the config cannot be expressed in sing-box (e.g. xhttp,
    unknown to 1.13) and must be dropped. Silently converting it to TCP gives the
    user a config that never connects.
    """
    raw = (p.get("network") or "").lower()
    host = p.get("host") or p.get("sni") or ""
    path = p.get("path") or "/"

    if raw in ("", "tcp", "raw", "none"):
        return None
    if raw in ("ws", "websocket"):
        transport: Dict[str, Any] = {"type": "ws", "path": path}
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if raw == "httpupgrade":
        transport = {"type": "httpupgrade", "path": path}
        if host:
            transport["host"] = host
        return transport
    if raw in ("grpc", "gun"):
        service = p.get("servicename") or (p.get("path") or "").lstrip("/")
        return {"type": "grpc", "service_name": service}
    if raw in ("h2", "http"):
        transport = {"type": "http", "path": path}
        if host:
            transport["host"] = [host]
        return transport
    if raw == "quic":
        return {"type": "quic"}
    # xhttp / splithttp / kcp / mkcp are not supported by sing-box
    return UNSUPPORTED


# --------------------------------------------------------------------------- #
# Clash / Mihomo proxies
# --------------------------------------------------------------------------- #

def _to_clash_proxy(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Intermediate dict -> one Clash proxy entry, or None to drop it."""
    kind = p["type"]
    if not p["server"] or not p["port"]:
        return None
    # Declared REALITY with unusable parameters can never connect, for any
    # protocol. See _reality_broken.
    if _reality_broken(p):
        return None

    base = {"name": p["name"], "server": p["server"], "port": p["port"]}
    try:
        if kind == "vmess":
            out = {**base, "type": "vmess", "uuid": p["uuid"],
                   "alterId": p.get("alterId", 0),
                   "cipher": p.get("cipher", "auto"),
                   "udp": True, "tls": p["tls"]}
            if p["sni"]:
                out["servername"] = p["sni"]
            _clash_transport_opts(p, out)
            return out

        if kind == "vless":
            out = {**base, "type": "vless", "uuid": p["uuid"], "udp": True,
                   "tls": p["tls"]}
            flow = _sanitize_flow(p.get("flow", ""))
            if flow:
                out["flow"] = flow
            if p["sni"]:
                out["servername"] = p["sni"]
            reality = _reality_params(p)
            if reality is not None:
                out["reality-opts"] = {"public-key": reality[0],
                                       "short-id": reality[1]}
            # client-fingerprint is not reality-only: it is valid for any TLS and
            # makes mihomo mimic a browser ClientHello, which matters for
            # censorship resistance.
            fingerprint = (p.get("fp") or "").lower()
            if fingerprint in UTLS_FINGERPRINTS:
                out["client-fingerprint"] = fingerprint
            elif p.get("reality"):
                out["client-fingerprint"] = DEFAULT_UTLS_FINGERPRINT
            _clash_transport_opts(p, out)
            return out

        if kind == "trojan":
            out = {**base, "type": "trojan", "password": p["password"],
                   "udp": True}
            if p["sni"]:
                out["sni"] = p["sni"]
            fingerprint = (p.get("fp") or "").lower()
            if fingerprint in UTLS_FINGERPRINTS:
                out["client-fingerprint"] = fingerprint
            _clash_transport_opts(p, out)
            return out

        if kind == "shadowsocks":
            return {**base, "type": "ss", "cipher": p["cipher"],
                    "password": p["password"], "udp": True}

        if kind == "shadowsocksr":
            # Deliberately not expressed: one ssr node breaks the whole
            # clash.yaml for Hiddify. See the ShadowsocksR note at the top.
            return None

        if kind == "hysteria2":
            # Key names verified against mihomo v1.19.29 (rc=0).
            out = {**base, "type": "hysteria2", "password": p["password"]}
            if p.get("sni"):
                out["sni"] = p["sni"]
            if p.get("insecure"):
                out["skip-cert-verify"] = True
            # obfs without a password is a no-op in mihomo, so both keys are
            # written together or neither; otherwise the user believes
            # obfuscation is on when it is not.
            if p.get("obfs") and p.get("obfs_password"):
                out["obfs"] = p["obfs"]
                out["obfs-password"] = p["obfs_password"]
            if p.get("alpn"):
                out["alpn"] = list(p["alpn"])
            return out

        if kind == "tuic":
            out = {**base, "type": "tuic", "uuid": p["uuid"],
                   "password": p["password"],
                   "congestion-controller": p.get("congestion_control", "cubic"),
                   "udp-relay-mode": p.get("udp_relay_mode", "native")}
            if p.get("sni"):
                out["sni"] = p["sni"]
            if p.get("insecure"):
                out["skip-cert-verify"] = True
            # tuic runs on QUIC and needs an ALPN; h3 is the standard default.
            # Without one, the handshake fails against many servers.
            out["alpn"] = list(p["alpn"]) if p.get("alpn") else ["h3"]
            return out
    except Exception:  # noqa: BLE001
        return None
    return None


# --------------------------------------------------------------------------- #
# sing-box outbounds
# --------------------------------------------------------------------------- #

def _singbox_tls(p: Dict[str, Any]) -> Dict[str, Any]:
    """sing-box tls section, guaranteeing uTLS whenever REALITY is present.

    Critical: without uTLS, reality is a fatal error in sing-box and the *whole
    file* is rejected, not just that outbound. Callers must already have dropped
    configs where :func:`_reality_broken` is true, so reality here is either valid
    or absent.
    """
    tls: Dict[str, Any] = {
        "enabled": True,
        "server_name": p.get("sni") or p["server"],
    }
    reality = _reality_params(p)
    if reality is not None:
        tls["reality"] = {"enabled": True, "public_key": reality[0],
                          "short_id": reality[1]}
    fingerprint = (p.get("fp") or "").lower()
    if fingerprint not in UTLS_FINGERPRINTS:
        # An unknown fingerprint gives "unknown uTLS fingerprint" and rejects the
        # file, so either use a valid default (mandatory for reality) or omit it.
        fingerprint = DEFAULT_UTLS_FINGERPRINT if reality is not None else ""
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if p.get("alpn"):
        tls["alpn"] = p["alpn"]
    return tls


def _quic_tls(p: Dict[str, Any], default_alpn: Optional[List[str]] = None) -> Dict[str, Any]:
    """tls section for the QUIC-based protocols (hysteria2, tuic)."""
    tls: Dict[str, Any] = {
        "enabled": True,
        "server_name": p.get("sni") or p["server"],
        "insecure": bool(p.get("insecure")),
    }
    alpn = list(p["alpn"]) if p.get("alpn") else default_alpn
    if alpn:
        tls["alpn"] = alpn
    return tls


def _to_singbox_outbound(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Intermediate dict -> one sing-box outbound, or None to drop it."""
    kind = p["type"]

    # Deliberate, documented rejection of ShadowsocksR. Not a defect, do not
    # "fix" it. sing-box removed ssr in 1.6.0 and now registers a stub that
    # errors with "ShadowsocksR is deprecated and removed in sing-box 1.6.0",
    # rejecting the entire singbox.json and taking thousands of healthy proxies
    # with it. The drop is recorded, not silent: the caller records
    # not_expressible, so it appears in health.json.
    if kind == "shadowsocksr":
        return None
    if not p["server"] or not p["port"]:
        return None
    if _reality_broken(p):
        return None

    try:
        transport = _singbox_transport(p)
        if transport is UNSUPPORTED:
            return None  # drop rather than silently downgrade to TCP

        if kind == "vmess":
            outbound = {"type": "vmess", "tag": p["name"], "server": p["server"],
                        "server_port": p["port"], "uuid": p["uuid"],
                        "security": p.get("cipher", "auto"),
                        "alter_id": p.get("alterId", 0)}
            if p["tls"]:
                outbound["tls"] = _singbox_tls(p)
            if transport:
                outbound["transport"] = transport
            return outbound

        if kind == "vless":
            outbound = {"type": "vless", "tag": p["name"], "server": p["server"],
                        "server_port": p["port"], "uuid": p["uuid"]}
            flow = _sanitize_flow(p.get("flow", ""))
            if flow:
                outbound["flow"] = flow
            if p["tls"]:
                outbound["tls"] = _singbox_tls(p)
            if transport:
                outbound["transport"] = transport
            return outbound

        if kind == "trojan":
            outbound = {"type": "trojan", "tag": p["name"],
                        "server": p["server"], "server_port": p["port"],
                        "password": p["password"], "tls": _singbox_tls(p)}
            if transport:
                outbound["transport"] = transport
            return outbound

        if kind == "shadowsocks":
            return {"type": "shadowsocks", "tag": p["name"],
                    "server": p["server"], "server_port": p["port"],
                    "method": p["cipher"], "password": p["password"]}

        if kind == "hysteria2":
            # Verified against sing-box 1.13.14 (rc=0). Unlike Clash, obfuscation
            # here is a nested object rather than two separate keys.
            outbound = {"type": "hysteria2", "tag": p["name"],
                        "server": p["server"], "server_port": p["port"],
                        "password": p["password"], "tls": _quic_tls(p)}
            if p.get("obfs") and p.get("obfs_password"):
                outbound["obfs"] = {"type": p["obfs"],
                                    "password": p["obfs_password"]}
            return outbound

        if kind == "tuic":
            return {"type": "tuic", "tag": p["name"], "server": p["server"],
                    "server_port": p["port"], "uuid": p["uuid"],
                    "password": p["password"],
                    "congestion_control": p.get("congestion_control", "cubic"),
                    "udp_relay_mode": p.get("udp_relay_mode", "native"),
                    "tls": _quic_tls(p, default_alpn=["h3"])}
    except Exception:  # noqa: BLE001
        return None
    return None


# --------------------------------------------------------------------------- #
# Shared preparation for both targets
# --------------------------------------------------------------------------- #

#: Proxy cap for the Clash/sing-box files. The old cap of 1,500 discarded ~65% of
#: configs, while the full output (~4,200 proxies) is only 1.3-1.8 MB and both
#: clients load it without trouble (verified with sing-box 1.13.14 and mihomo
#: 1.19.29).
OUTPUT_PROXY_LIMIT = 20000


def _prepare_nodes(lines: Iterable[str], target: str, limit: int,
                   convert: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
                   name_key: str,
                   reserved: Set[str]) -> List[Dict[str, Any]]:
    """Parse, validate, convert, brand and uniquify nodes for one target.

    Shared by both builders. They ran two near-identical loops before, which is
    how a drop reason could be recorded for one target and forgotten for the other.

    ``reserved`` seeds the used-name set with the group names. In Clash, groups and
    nodes share one namespace, so a node that happens to match a group name breaks
    the group reference: the client resolves to the node instead. sing-box has the
    same property for outbound tags. Branding makes a collision impossible today,
    but reserving moves correctness from luck to structure; on collision the loop
    below appends " #n".

    Order matters: brand first, then uniquify. The other way round, "... #1" could
    land after the brand and break the legal name shape.
    """
    nodes: List[Dict[str, Any]] = []
    used: Set[str] = set(reserved)
    _drops.clear_target(target)

    for line in lines:
        if len(nodes) >= limit:
            _drops.record(target, REASON_OVER_LIMIT, line)
            continue
        parsed = parse_proxy(line)
        if not parsed:
            _drops.record(target, REASON_UNPARSABLE, line)
            continue
        server = parsed.get("server")
        # Two separate reasons on purpose: unroutable is about the IP
        # *destination*, invalid_server about the *shape* of the value. Merging
        # them blinds root-cause analysis.
        if _is_unroutable_server(server):
            _drops.record(target, REASON_UNROUTABLE, line, parsed.get("type"))
            continue
        if _is_structurally_invalid_server(server):
            _drops.record(target, REASON_INVALID_SERVER, line, parsed.get("type"))
            continue
        node = convert(parsed)
        if not node:
            _drops.record(target, REASON_NOT_EXPRESSIBLE, line, parsed.get("type"))
            continue

        name = _enforce_brand(node[name_key], node["type"])
        candidate = name
        suffix = 1
        while candidate in used:
            candidate = f"{name} #{suffix}"
            suffix += 1
        node[name_key] = candidate
        used.add(candidate)
        nodes.append(node)
    return nodes


# --------------------------------------------------------------------------- #
# Clash / Mihomo YAML
#
# PyYAML implements the YAML 1.1 schema and does not recognise `9e63` as a number
# (1.1 requires a dot for scientific notation), so it emits it unquoted. But
# gopkg.in/yaml.v3, which mihomo uses, is YAML 1.2 and reads `9e63` as the float
# 9e63, turning a hex string into a number; mihomo then rejects the *whole file*
# with "invalid REALITY short ID".
#
# The same trap applies to any string: short-ids, digit-only passwords like
# `123456` (Go reads an int, then a type error), odd UUIDs, `0x...`, `true`,
# `null`. So instead of patching one case, the Dumper force-quotes any string that
# YAML 1.2 might read as a non-string.
# --------------------------------------------------------------------------- #

_YAML12_AMBIGUOUS = re.compile(
    r"""^(?:
          [-+]?[0-9]+                                  # decimal int
        | 0[oO][0-7]+ | 0[xX][0-9a-fA-F]+              # octal / hex
        | [-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+|[0-9]+)      # float, with or without
              (?:[eE][-+]?[0-9]+)?                     #   an exponent
        | [-+]?\.(?:inf|Inf|INF) | \.(?:nan|NaN|NAN)   # infinity / NaN
        | true|True|TRUE|false|False|FALSE             # boolean
        | null|Null|NULL|~                             # null
        )$""",
    re.VERBOSE,
)


def _yaml_str_representer(dumper, data):  # type: ignore[no-untyped-def]
    """Single-quote ambiguous strings so Go does not read them as numbers."""
    if data == "" or _YAML12_AMBIGUOUS.match(data):
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="'")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


def _clash_dumper():  # type: ignore[no-untyped-def]
    """A dedicated Dumper, without mutating PyYAML's global state.

    Uses CSafeDumper when libyaml is available: on a 7,831 proxy benchmark that is
    3.99s -> 0.97s, about 4x. Output is generated three times per run
    (all/heavy/light), so this alone saves several seconds of CI time. Falls back
    to the pure-Python implementation silently.
    """
    import yaml

    base = getattr(yaml, "CSafeDumper", None) or yaml.SafeDumper

    class _SafeClashDumper(base):  # type: ignore[misc,valid-type]
        pass

    _SafeClashDumper.add_representer(str, _yaml_str_representer)
    return _SafeClashDumper


def build_clash_yaml(lines: List[str], limit: int = OUTPUT_PROXY_LIMIT) -> str:
    """Config list -> a complete Clash YAML document, with proxy groups."""
    import yaml  # PyYAML

    proxies = _prepare_nodes(
        lines, "clash", limit, _to_clash_proxy, "name",
        reserved={GROUP_MAIN, GROUP_AUTO, GROUP_FALLBACK},
    )
    names = [proxy["name"] for proxy in proxies]
    doc = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": GROUP_MAIN, "type": "select",
             "proxies": [GROUP_AUTO, GROUP_FALLBACK] + names},
            {"name": GROUP_AUTO, "type": "url-test",
             "url": "http://www.gstatic.com/generate_204",
             "interval": 300, "tolerance": 50, "proxies": names},
            {"name": GROUP_FALLBACK, "type": "fallback",
             "url": "http://www.gstatic.com/generate_204",
             "interval": 300, "proxies": names},
        ],
        "rules": [f"MATCH,{GROUP_MAIN}"],
    }
    header = f"# Clash subscription - generated by {BRAND} aggregator\n"
    return header + yaml.dump(
        doc,
        Dumper=_clash_dumper(),
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        # Never wrap: wrapping corrupts long base64 values.
        width=10 ** 6,
    )


# --------------------------------------------------------------------------- #
# sing-box JSON
# --------------------------------------------------------------------------- #

def _singbox_document(tags: List[str],
                      outbounds: List[Dict[str, Any]]) -> Dict[str, Any]:
    """A complete, ready-to-use document for the sing-box >= 1.12/1.13 schema.

    Notable choices, all required by that schema:
      - DNS in the new type/server form; the old `address` form is deprecated.
      - route.default_domain_resolver, whose absence emits a deprecation warning.
      - action-based route rules (sniff / hijack-dns) instead of outbound=block.
      - real inbounds: tun for mobile/desktop plus mixed for a browser.
    """
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "proxy-dns", "type": "https", "server": "1.1.1.1",
                 "detour": GROUP_MAIN},
                {"tag": "local-dns", "type": "local"},
            ],
            "rules": [
                {"clash_mode": "Direct", "server": "local-dns"},
                {"clash_mode": "Global", "server": "proxy-dns"},
            ],
            "final": "proxy-dns",
            "strategy": "prefer_ipv4",
            "independent_cache": True,
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in",
             "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
             "auto_route": True, "strict_route": True, "stack": "mixed"},
            {"type": "mixed", "tag": "mixed-in",
             "listen": "127.0.0.1", "listen_port": 2080},
        ],
        "outbounds": [
            {"type": "selector", "tag": GROUP_MAIN,
             "outbounds": [GROUP_AUTO] + tags, "default": GROUP_AUTO},
            {"type": "urltest", "tag": GROUP_AUTO, "outbounds": tags,
             "url": "https://www.gstatic.com/generate_204",
             "interval": "5m", "tolerance": 50},
            *outbounds,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct"},
            ],
            "final": GROUP_MAIN,
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": "local-dns"},
        },
        "experimental": {
            "cache_file": {"enabled": True, "store_fakeip": True},
            "clash_api": {"external_controller": "127.0.0.1:9090"},
        },
    }


def build_singbox_json(lines: List[str], limit: int = OUTPUT_PROXY_LIMIT) -> str:
    """Config list -> a complete sing-box JSON document, with selector/urltest."""
    outbounds = _prepare_nodes(
        lines, "singbox", limit, _to_singbox_outbound, "tag",
        reserved={GROUP_MAIN, GROUP_AUTO},
    )
    tags = [outbound["tag"] for outbound in outbounds]
    if not tags:
        # A document with no valid outbound is useless, and an empty
        # selector/urltest is an error in sing-box, so return a minimal valid one.
        return json.dumps(
            {"log": {"level": "info"},
             "outbounds": [{"type": "direct", "tag": "direct"}]},
            ensure_ascii=False, indent=2)
    return json.dumps(_singbox_document(tags, outbounds),
                      ensure_ascii=False, indent=2)
