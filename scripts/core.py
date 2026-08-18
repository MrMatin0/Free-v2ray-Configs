# -*- coding: utf-8 -*-
"""Standalone V2Ray config processing engine for the aggregator.

This is the proven RaydikalxBot logic rewritten self-contained, without the
Telegram/database dependencies, so it can run inside GitHub Actions:

  * dedup_key()                  server identity fingerprint, CDN aware
  * is_dummy_config()            broken / fake config detection
  * detect_country_from_remark() country detection from the remark, fallback only
  * brand_remark()               branding: "{CC} {flag} | @Raydikalx | {tag}"
  * protocol_of()                protocol detection
  * try_base64_decode()          safe base64 decode with a quality gate
  * extract_valid_lines()        valid config extraction from a blob
  * _normalize_packet_encoding() strips packetEncoding that crashes Hiddify

Source logic: raydikalx/freeconfigs.py, fetcher.py, subscription.py.
Equivalent behaviour, only made standalone and CI-runnable.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Branding policy: product requirement, not taste.
#
# The repo owner was explicit: branding is intentional, must stay, and the channel
# id @Raydikalx must always be written onto configs. So this invariant is not
# negotiable:
#
#   every published node, in configs.txt, configs_base64.txt, clash.yaml,
#   singbox.json, protocols/* and archive/*, must carry BRAND_CHANNEL in its
#   remark, name or tag.
#
# Consequences for future readers, human or agent:
#   - reducing branding is a regression, not an improvement. Old planning docs may
#     mention "reduce branding to <5%"; that item is explicitly won't-do.
#   - unbranded fallbacks in converters.py are intentionally aimed at a branded
#     value. Reverting them to "vmess" / scheme / type is a regression.
#   - branding is idempotent, measured over repeated application, so reapplying it
#     is safe. That is why aggregate.py has a fail-safe gate that retries branding
#     once and, only if the line is still unbranded, drops just that line and
#     counts it in health.json. It never breaks the whole run.
#   - test_pipeline.py locks this invariant over all four output formats. If a test
#     fails because of the brand, the test is right.
BRAND_CHANNEL = "@Raydikalx"

# Hiddify in-file profile headers.
#
# Hiddify reads metadata not only from HTTP headers but also from the subscription
# body itself. That was read from source and reproduced exactly with a Go replica:
#
#   1. profile_repository.go feeds the body into parseHeadersFromContent and then
#      writes the result back onto the HTTP header map, so in-file headers
#      override HTTP headers.
#   2. parseHeadersFromContent first calls safeDecodeBase64, so these headers also
#      work *inside a base64 payload*.
#   3. strings.SplitN(content, "\n", 30) and iterating to len(lines)-1 means only
#      the first 29 lines are scanned. Measured: 30 lines of padding hide the
#      headers, 23 still work. So this block must be the first thing in the file.
#   4. The line must start with `#` or `//` with no leading space and contain a
#      `:` not followed by `/`, so an empty URL is not mistaken for a header.
#
# Why subscription-userinfo is mandatory: in ProfileEntity.Parse,
# Profile-Web-Page-Url and Support-Url are only applied when subInfo != nil, and
# parseSubscriptionInfo never returns nil. So the mere *presence* of that header is
# enough. Without it, the two URLs are dropped silently, measured.
#
# total=0 and expire=0 are deliberate: they map to Hiddify's infinity thresholds,
# so the client shows "unlimited", which is the most honest state for a free public
# subscription.
#
# This block is *not* added to singbox.json: Hiddify's own JSON parser tolerates
# comments, but standard JSON consumers do not, including jq and
# validate.py::check_singbox (json.load). Measured: json.loads(header + singbox)
# raises JSONDecodeError. It is also not added to archive/*, which are debugging
# artefacts rather than subscriptions.
HIDDIFY_UPDATE_INTERVAL_HOURS = os.environ.get("AGG_HIDDIFY_UPDATE_HOURS", "1")
SUPPORT_URL = os.environ.get(
    "AGG_SUPPORT_URL", "https://t.me/" + BRAND_CHANNEL.lstrip("@").lower())
PROJECT_URL = os.environ.get(
    "AGG_PROJECT_URL", "https://github.com/0xRadikal/Free-v2ray-Configs")
HIDDIFY_SUBSCRIPTION_USERINFO = "upload=0; download=0; total=0; expire=0"
HIDDIFY_HEADER_KEYS = (
    "profile-title",
    "profile-update-interval",
    "subscription-userinfo",
    "support-url",
    "profile-web-page-url",
)


def hiddify_profile_header(label: str) -> str:
    """Five-line Hiddify header block for a subscription file.

    Always ends with ``\n`` so callers can prepend it directly to any text format
    (txt, base64 payload, yaml).

    `label` is the human-readable category, e.g. ALL or TOP 100. The final title
    is ``@Raydikalx — LABEL``. The em dash was measured and passes Hiddify's
    parser fine.
    """
    title = f"{BRAND_CHANNEL} — {label}".strip()
    return (
        f"#profile-title: {title}\n"
        f"#profile-update-interval: {HIDDIFY_UPDATE_INTERVAL_HOURS}\n"
        f"#subscription-userinfo: {HIDDIFY_SUBSCRIPTION_USERINFO}\n"
        f"#support-url: {SUPPORT_URL}\n"
        f"#profile-web-page-url: {PROJECT_URL}\n"
    )

# Smart protocol detection: dynamic, future-proof.
#
# Instead of a fixed allow-list, any URI shaped like scheme://... is accepted as a
# config unless its scheme is in the non-proxy deny-list. So if sources add a new
# protocol tomorrow (anytls, juicity, snell, mieru, ssh, ...), it is detected,
# aggregated, deduplicated and categorised automatically without a code change.
_SCHEME_ALIASES: Dict[str, str] = {
    "ss": "shadowsocks",
    "shadowsocks": "shadowsocks",
    "ssr": "shadowsocksr",
    "hy": "hysteria",
    "hysteria": "hysteria",
    "hy2": "hysteria2",
    "hysteria2": "hysteria2",
    "wg": "wireguard",
    "wireguard": "wireguard",
    "warp": "wireguard",
    "socks": "socks",
    "socks5": "socks",
}

#: Non-proxy schemes to ignore entirely, so noisy source text is not treated as a
#: config.
_NON_PROXY_SCHEMES: frozenset = frozenset({
    "http", "https", "ftp", "ftps", "file", "data", "mailto", "tel", "sms",
    "magnet", "git", "ssh+git", "ws", "wss", "tcp", "udp", "ipfs",
    "android-app", "intent", "javascript", "blob", "about", "chrome",
})

#: A proxy URI scheme: scheme://..., where scheme follows the RFC grammar.
_URI_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+\-.]*)://", re.IGNORECASE)

#: Anything shorter than this is noise, not a usable config.
_MIN_CONFIG_LEN = 12

#: Preferred display order for well-known protocols. Unknown/new ones come after
#: these in alphabetical order.
PROTOCOL_ORDER: Tuple[str, ...] = (
    "vless", "vmess", "trojan", "shadowsocks", "shadowsocksr",
    "hysteria2", "hysteria", "tuic", "wireguard",
    "juicity", "anytls", "snell", "mieru", "socks",
)


def normalize_scheme(scheme: str) -> str:
    """Canonical protocol name for a scheme, with a safe fallback."""
    value = (scheme or "").strip().lower()
    return _SCHEME_ALIASES.get(value, value)


def is_proxy_config(line: str) -> bool:
    """Smart detection of whether a line is a valid proxy config.

    Rules:
      - it must look like ``scheme://``
      - the scheme must not be in the non-proxy deny-list
      - it must be long enough and contain no spaces before the fragment

    Any future protocol that satisfies those rules is accepted automatically.
    """
    if not line:
        return False
    line = line.strip()
    if len(line) < _MIN_CONFIG_LEN or " " in line.split("#", 1)[0]:
        return False
    match = _URI_SCHEME_RE.match(line)
    if not match:
        return False
    scheme = match.group(1).lower()
    if scheme in _NON_PROXY_SCHEMES:
        return False
    after = line.split("://", 1)[1]
    return bool(after) and not after.startswith(("/", "#"))

# A former VALID_PREFIXES allow-list was removed on purpose, not forgotten. It had
# exactly one live occurrence, its own definition, while the real design here is a
# deny-list via is_proxy_config(). Keeping a dead allow-list beside it is the same
# future bug pattern validate.py had to fix: two truths that drift. That tuple had
# already drifted measurably, with seven non-canonical aliases and no
# shadowsocksr.

# Country detection from the remark, vendored from freeconfigs.py.
_FLAG_EMOJI_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")

_COUNTRY_KEYWORD_MAP: Dict[str, Tuple[str, str]] = {
    "united states": ("US", "🇺🇸"), "usa": ("US", "🇺🇸"), "america": ("US", "🇺🇸"),
    "آمریکا": ("US", "🇺🇸"), "امریکا": ("US", "🇺🇸"),
    "germany": ("DE", "🇩🇪"), "deutschland": ("DE", "🇩🇪"), "آلمان": ("DE", "🇩🇪"),
    "finland": ("FI", "🇫🇮"), "فنلاند": ("FI", "🇫🇮"),
    "turkey": ("TR", "🇹🇷"), "turkiye": ("TR", "🇹🇷"), "ترکیه": ("TR", "🇹🇷"),
    "united kingdom": ("GB", "🇬🇧"), "uk": ("GB", "🇬🇧"), "england": ("GB", "🇬🇧"),
    "انگلیس": ("GB", "🇬🇧"), "بریتانیا": ("GB", "🇬🇧"),
    "france": ("FR", "🇫🇷"), "فرانسه": ("FR", "🇫🇷"),
    "netherlands": ("NL", "🇳🇱"), "holland": ("NL", "🇳🇱"), "هلند": ("NL", "🇳🇱"),
    "switzerland": ("CH", "🇨🇭"), "سوئیس": ("CH", "🇨🇭"),
    "sweden": ("SE", "🇸🇪"), "سوئد": ("SE", "🇸🇪"),
    "norway": ("NO", "🇳🇴"), "نروژ": ("NO", "🇳🇴"),
    "ireland": ("IE", "🇮🇪"), "ایرلند": ("IE", "🇮🇪"),
    "italy": ("IT", "🇮🇹"), "ایتالیا": ("IT", "🇮🇹"),
    "austria": ("AT", "🇦🇹"), "اتریش": ("AT", "🇦🇹"),
    "belgium": ("BE", "🇧🇪"), "بلژیک": ("BE", "🇧🇪"),
    "portugal": ("PT", "🇵🇹"), "پرتغال": ("PT", "🇵🇹"),
    "spain": ("ES", "🇪🇸"), "اسپانیا": ("ES", "🇪🇸"),
    "denmark": ("DK", "🇩🇰"), "دانمارک": ("DK", "🇩🇰"),
    "poland": ("PL", "🇵🇱"), "لهستان": ("PL", "🇵🇱"),
    "czech republic": ("CZ", "🇨🇿"), "czechia": ("CZ", "🇨🇿"), "czech": ("CZ", "🇨🇿"),
    "romania": ("RO", "🇷🇴"), "رومانی": ("RO", "🇷🇴"),
    "hungary": ("HU", "🇭🇺"), "مجارستان": ("HU", "🇭🇺"),
    "serbia": ("RS", "🇷🇸"), "صربستان": ("RS", "🇷🇸"),
    "bulgaria": ("BG", "🇧🇬"), "بلغارستان": ("BG", "🇧🇬"),
    "croatia": ("HR", "🇭🇷"), "کرواسی": ("HR", "🇭🇷"),
    "luxembourg": ("LU", "🇱🇺"), "لوکزامبورگ": ("LU", "🇱🇺"),
    "latvia": ("LV", "🇱🇻"), "لتونی": ("LV", "🇱🇻"),
    "lithuania": ("LT", "🇱🇹"), "لیتوانی": ("LT", "🇱🇹"),
    "estonia": ("EE", "🇪🇪"), "استونی": ("EE", "🇪🇪"),
    "greece": ("GR", "🇬🇷"), "یونان": ("GR", "🇬🇷"),
    "slovakia": ("SK", "🇸🇰"), "اسلواکی": ("SK", "🇸🇰"),
    "moldova": ("MD", "🇲🇩"), "مولداوی": ("MD", "🇲🇩"),
    "russia": ("RU", "🇷🇺"), "روسیه": ("RU", "🇷🇺"),
    "ukraine": ("UA", "🇺🇦"), "اوکراین": ("UA", "🇺🇦"),
    "kazakhstan": ("KZ", "🇰🇿"), "قزاقستان": ("KZ", "🇰🇿"),
    "singapore": ("SG", "🇸🇬"), "سنگاپور": ("SG", "🇸🇬"),
    "japan": ("JP", "🇯🇵"), "ژاپن": ("JP", "🇯🇵"),
    "south korea": ("KR", "🇰🇷"), "korea": ("KR", "🇰🇷"), "کره": ("KR", "🇰🇷"),
    "hong kong": ("HK", "🇭🇰"), "hongkong": ("HK", "🇭🇰"), "هنگ کنگ": ("HK", "🇭🇰"),
    "taiwan": ("TW", "🇹🇼"), "تایوان": ("TW", "🇹🇼"),
    "china": ("CN", "🇨🇳"), "چین": ("CN", "🇨🇳"),
    "india": ("IN", "🇮🇳"), "هند": ("IN", "🇮🇳"),
    "iran": ("IR", "🇮🇷"), "ایران": ("IR", "🇮🇷"),
    "indonesia": ("ID", "🇮🇩"), "اندونزی": ("ID", "🇮🇩"),
    "vietnam": ("VN", "🇻🇳"), "ویتنام": ("VN", "🇻🇳"),
    "thailand": ("TH", "🇹🇭"), "تایلند": ("TH", "🇹🇭"),
    "malaysia": ("MY", "🇲🇾"), "مالزی": ("MY", "🇲🇾"),
    "pakistan": ("PK", "🇵🇰"), "پاکستان": ("PK", "🇵🇰"),
    "uae": ("AE", "🇦🇪"), "dubai": ("AE", "🇦🇪"), "امارات": ("AE", "🇦🇪"),
    "egypt": ("EG", "🇪🇬"), "مصر": ("EG", "🇪🇬"),
    "south africa": ("ZA", "🇿🇦"), "آفریقای جنوبی": ("ZA", "🇿🇦"),
    "canada": ("CA", "🇨🇦"), "کانادا": ("CA", "🇨🇦"),
    "australia": ("AU", "🇦🇺"), "استرالیا": ("AU", "🇦🇺"),
    "new zealand": ("NZ", "🇳🇿"), "نیوزیلند": ("NZ", "🇳🇿"),
    "brazil": ("BR", "🇧🇷"), "برزیل": ("BR", "🇧🇷"),
    "argentina": ("AR", "🇦🇷"), "آرژانتین": ("AR", "🇦🇷"),
    "mexico": ("MX", "🇲🇽"), "مکزیک": ("MX", "🇲🇽"),
}

_VALID_CC = frozenset(value[0] for value in _COUNTRY_KEYWORD_MAP.values())
_SORTED_KEYWORDS = sorted(_COUNTRY_KEYWORD_MAP.items(),
                          key=lambda item: len(item[0]), reverse=True)


def _flag_to_country_code(flag: str) -> Optional[str]:
    if len(flag) != 2:
        return None
    try:
        c1 = chr(ord(flag[0]) - 0x1F1E6 + 65)
        c2 = chr(ord(flag[1]) - 0x1F1E6 + 65)
        code = f"{c1}{c2}"
        return code if code in _VALID_CC else None
    except Exception:
        return None


def detect_country_from_remark(remark: str) -> Tuple[str, str]:
    """Country detection from the remark, last resort only.

    This used to be the *main* country source and had three stages. The last
    stage assumed any two-letter Latin word was a country code, which was a guess,
    not a measurement. Real examples from this repo's output:

        "join-us-on-Telegram"      -> US   (`us` is an English word, not a country)
        "剩余流量：55.26 GB"        -> GB   (gigabytes, not Great Britain)
        "Speed: 20 mb/s NO limit"  -> NO   (negation, not Norway)

    Accuracy measured over 675 configs with independent ground truth from
    ip-api.com: 53.6% correct, 14.7% wrong, 31.7% gave up. A wrong label is worse
    than none, because a user trusts it.

    The main source is now the real network location (geo.py). This function is
    only used in the degraded mode where the GeoIP database is unavailable, so:

      - the Unicode flag stage stays: a flag is an explicit machine-readable claim
      - the keyword stage stays, but only with word boundaries
      - the two-letter guess loop is gone. No label is better than a wrong label.

    The obvious question, "what about a cautious guess, only at the start of the
    remark?" was tested, not waved away. Over 4,291 *upstream* remarks (not our
    branded output, which already carries flags):

        guess anywhere          39.5% correct, 8.2% wrong, 52.3% gave up
        no guess (current)      39.1% correct, 6.0% wrong, 55.0% gave up
        guess only at the start 39.2% correct, 6.3% wrong, 54.5% gave up

    The guarded guess buys +0.16% more correct labels and +0.33% more wrong ones,
    i.e. two wrong labels for every fresh correct one. Real failures:
    "AE_speednode_0001" whose server is in France, and "CN_speednode_0005" whose
    server is in the US. So even the cautious guess is not worth it.

    Losing the guess raises the give-up rate from 52.3% to 55.0%. That is the
    cost, not a bug. In normal operation GeoIP fills that 55% and the give-up rate
    falls to 0.
    """
    if not remark:
        return ("Global", "🌐")
    for flag in _FLAG_EMOJI_RE.findall(remark):
        code = _flag_to_country_code(flag)
        if code:
            return (code, flag)
    lowered = remark.lower()
    for keyword, info in _SORTED_KEYWORDS:
        # Word boundaries matter: without them, short keywords like `us` hit inside
        # words such as "trust" or "status". Measurement showed most keyword-stage
        # errors came from exactly that.
        if _keyword_hit(lowered, keyword):
            return info
    return ("Global", "🌐")


def _keyword_hit(haystack: str, needle: str) -> bool:
    """Whether a keyword appears as an independent word in the text.

    Keywords up to three chars require word boundaries, because a short string
    easily appears inside unrelated words. Longer ones like "netherlands" are
    fine with a plain substring search, which also correctly finds
    "amsterdam-netherlands-01".
    """
    if len(needle) > 3:
        return needle in haystack
    pos = haystack.find(needle)
    while pos != -1:
        before = haystack[pos - 1] if pos > 0 else ""
        after = haystack[pos + len(needle)] if pos + len(needle) < len(haystack) else ""
        if not before.isalnum() and not after.isalnum():
            return True
        pos = haystack.find(needle, pos + 1)
    return False

# Country label stability.
#
# Country used to be read only from the source remark. Different sources label the
# same server differently, so one stable config was "RU" in one run and "US" in
# the next. Practical effect: 3,268 of 3,537 lines changed every run purely
# because of the remark, so each publish rewrote almost the whole file.
#
# Fix: the label is keyed to the connection target, not to the source text. The
# same host/IP therefore always gets one label, independent of which source it
# came from. If no source can tell us the country, it stays "Global 🌐".
_HOST_COUNTRY_CACHE: Dict[str, Tuple[str, str]] = {}
_GEO_MODULE: Any = ...


def _load_geo_module() -> Any:
    """Best-effort geo import, cached.

    country_for_endpoint() used to inline the nested relative-import / plain-import
    fallback on every call. This helper keeps the behaviour identical and makes
    the call-site readable.
    """
    global _GEO_MODULE
    if _GEO_MODULE is not ...:
        return _GEO_MODULE
    try:
        from . import geo as geo_module  # type: ignore
    except Exception:
        try:
            import geo as geo_module  # type: ignore
        except Exception:
            geo_module = None  # type: ignore
    _GEO_MODULE = geo_module
    return _GEO_MODULE

# Version-stable base64 decoding.
#
# Why it exists, measured not hypothetical:
# `base64.urlsafe_b64decode` behaves differently across CPython versions on input
# that contains padding in the *middle*.
#
#     s = "QUJDRA==EFGH"       -> 3.10: b"ABCD"                 3.13: b"ABCD\x01\x05\x18"
#     s = "QUJDRA==@host:443"  -> 3.10: b"ABCD"                 3.13: binascii.Error
#     s = "QUJDRQ=XYZ"         -> 3.10: binascii.Error          3.13: binascii.Error
#     s = "QUJD@RA=="          -> 3.10: b"ABCD"                 3.13: b"ABCD"
#
# Three behaviours, one of them an exception. Because dedup_key() swallows errors
# with `except: pass`, the result is a *different identity key* with no noise.
#
# Measured consequence: two of the 8,136 published configs had labels that Python
# 3.13 could not reproduce, while 3.10 and CI (3.12) both did. The input was
# proven identical by sha256 of the sample file and the userinfo fragment; only the
# decoded output differed (74 vs 80 bytes).
#
# dedup_key() is the repo's identity function: deduping, output ordering, remark
# tags, and unique_yield() in phase D all depend on it. An identity function must
# not depend on the Python version.
#
# Fix: remove the problem itself. If the input is not syntactically base64, do not
# pretend to decode it; return None. For clean input, 99.97% of cases, the result
# is identical across versions, measured.
#
# Deliberately *not* used in try_base64_decode(), which handles whole source blobs.
# On all 21 real sources, including 4 base64 sources, 3.10 and 3.13 produced
# exactly the same output there (20,520 lines in both, 0 sources different), and
# the 20% density guard already makes that path robust. A strict syntax gate there
# could have fully rejected a source that currently decodes partly, losing configs
# for a problem that does not exist.
_B64_BODY_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")


def decode_base64_text(candidate: str) -> Optional[str]:
    """Decoded text if `candidate` is syntactically base64, else None.

    Deterministic: the output is a function of the input, not of the CPython
    version. Details in the note above.
    """
    text = (candidate or "").strip()
    if not text or not _B64_BODY_RE.match(text):
        return None
    body = text.rstrip("=")
    # length 4k+1 is impossible in base64; every version rejects it
    if len(body) % 4 == 1:
        return None
    body += "=" * ((4 - len(body) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(body)
    except Exception:
        return None
    return raw.decode("utf-8", errors="ignore")


def _ssr_b64_text(value: Optional[str], *, allow_empty: bool = False) -> Optional[str]:
    """base64, either alphabet, padded or not -> UTF-8 text, or None.

    This is an exact mirror of converters._ub64_text and must stay that way.
    Deliberately does *not* call decode_base64_text above, and deliberately does
    not soften it: that function builds identity keys for every scheme, and
    loosening it could reshuffle thousands of records. This one only touches ssr.

    Two deliberate differences from decode_base64_text:
      - no errors="ignore": invalid bytes -> None, not a half-eaten password.
      - no _B64_BODY_RE syntax gate, because the converter does not have one
        either. Any difference here means drifting from the real output parser.
    """
    text = (value or "").strip()
    if not text:
        return "" if allow_empty else None
    text = text.replace("-", "+").replace("_", "/")
    text += "=" * ((4 - len(text) % 4) % 4)
    try:
        return base64.b64decode(text, validate=False).decode("utf-8")
    except Exception:
        return None


def _ssr_parts(line: str) -> Optional[Tuple[str, str, str, str, str, str, str, str]]:
    """Identity parts of an ssr:// config, or None if it does not parse.

    The grammar is copied *exactly* from converters.parse_proxy's ssr branch:

        ssr://base64(host:port:protocol:method:obfs:base64(password)
                     /?obfsparam=b64&protoparam=b64&remarks=b64&group=b64)

    Four small rules from there are mirrored here, or we build two parsers that
    drift, which this project has already paid for once:
      1. split off `#` *before* decoding, because `#` is in neither base64 alphabet
      2. use partition("/?") to split query from body
      3. require exactly six sections, rejecting IPv6 too because the ssr spec has
         no IPv6 form either
      4. require a non-empty host and a numeric port

    Output is (host, port, protocol, method, obfs, password, obfsparam,
    protoparam), all decoded and *raw*, i.e. before _sanitize_ssr. Deliberate:
    sanitising maps several different values onto one value, and building the key
    on that could merge two distinct configs. The project rule is "when in doubt,
    do not merge", so raw values are the safe, splitting direction.

    This is exactly what the converter emits (`server, port, cipher, password,
    obfs, protocol, obfs_param, protocol_param`) minus `name`, which branding
    rewrites and therefore does not define identity. `remarks` and `group` never
    reach output either, so they get no weight in the key.
    """
    if not line.startswith("ssr://"):
        return None
    body = line[len("ssr://"):].split("#", 1)[0].strip()
    text = _ssr_b64_text(body)
    if not text:
        return None
    main, _sep, query = text.partition("/?")
    parts = main.split(":")
    if len(parts) != 6:
        return None
    host, port_text, protocol, method, obfs, password_b64 = parts
    if not host or not port_text.isdigit():
        return None
    password = _ssr_b64_text(password_b64, allow_empty=True)
    if password is None:
        return None
    parsed_qs = urllib.parse.parse_qs(query)
    obfsparam = _ssr_b64_text((parsed_qs.get("obfsparam") or [""])[0],
                              allow_empty=True) or ""
    protoparam = _ssr_b64_text((parsed_qs.get("protoparam") or [""])[0],
                               allow_empty=True) or ""
    return (host, port_text, protocol, method, obfs, password,
            obfsparam, protoparam)


def _vmess_json(line: str) -> Optional[dict]:
    """Decoded vmess JSON object, or None when this vmess line is not JSON-backed."""
    if not line.startswith("vmess://"):
        return None
    body = line[8:].split("#")[0].strip()
    text = decode_base64_text(body)
    if text is None:
        return None
    try:
        obj = json.loads(text)
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def _vmess_remark_source(line: str) -> Optional[Tuple[dict, str]]:
    """vmess JSON plus the old visible remark, if this is a JSON-backed vmess line."""
    obj = _vmess_json(line)
    if obj is None:
        return None
    return obj, str(obj.get("ps") or obj.get("name") or "")


def endpoint_of(line: str) -> str:
    """Connection target, host or IP without the port.

    vmess usually carries base64+JSON, but not always; some sources publish vmess
    in the standard URI form, just like vless:

      vmess://<uuid>@91.107.139.186:51459?encryption=auto&type=tcp#…

    On such lines, the old JSON path fell through to "unknown". That did more
    than lose a label: because brand_remark() does nothing without a target, the
    upstream remark shipped untouched and with it a rival channel advert
    (measured, 1 line out of 8,018). So vmess only takes the JSON path when it is
    *actually* JSON; otherwise it falls through to the generic URI parser below
    and gets the correct host there.

    ssr is different again: the whole body is base64, so the generic URI parser
    below saw only that base64 string as the host. Measured: all 112 ssr lines had
    a nonsense endpoint, so GeoIP always failed and every one became Global 🌐.
    Decoding fixes 96 of those 112.
    """
    line = (line or "").strip()
    if not line:
        return ""
    try:
        vmess = _vmess_json(line)
        if vmess is not None:
            host = str(vmess.get("add") or vmess.get("host") or "").strip().lower()
            if host:
                return host
        if line.startswith("ssr://"):
            parts = _ssr_parts(line)
            if parts:
                return parts[0].strip().lower()
        # All other schemes: scheme://[userinfo@]host[:port][?query][#fragment]
        rest = line.split("://", 1)[1] if "://" in line else line
        rest = rest.split("#", 1)[0].split("?", 1)[0]
        if "@" in rest:
            rest = rest.rsplit("@", 1)[1]
        rest = rest.split("/", 1)[0]
        if rest.startswith("["):  # IPv6 literal
            return rest.split("]", 1)[0][1:].lower()
        return rest.rsplit(":", 1)[0].lower() if ":" in rest else rest.lower()
    except Exception:
        return ""


def country_for_endpoint(endpoint: str, remark_hint: str = "") -> Tuple[str, str]:
    """Stable country label for a target, by this priority:

        1. GeoIP on the real network address   most trustworthy, measured 97.9% correct
        2. a Unicode flag in the remark        degraded mode only
        3. a country keyword in the remark     degraded mode only
        4. Global 🌐                           honest admission of not knowing

    GeoIP outranks the source flag because the source flag is hand-written by the
    source author, and measurement showed 14.7% of labels derived from remarks do
    not match the server's real country. The actual network location is measurable;
    the remark is not. Wrong upstream flags are therefore overwritten.

    Stability: a label is computed once per target and cached. If ten sources bring
    the same server with ten different remarks, they all get one label and the
    output stops drifting between runs.
    """
    endpoint = (endpoint or "").strip().lower()
    if not endpoint:
        return detect_country_from_remark(remark_hint)
    cached = _HOST_COUNTRY_CACHE.get(endpoint)
    if cached is not None:
        return cached

    # 1) The real network location. If the GeoIP database is missing, geo returns
    # None and we fall through; its absence never raises here.
    geo = _load_geo_module()
    if geo is not None:
        try:
            hit = geo.country_for_host(endpoint)
        except Exception:
            hit = None
        if hit:
            _HOST_COUNTRY_CACHE[endpoint] = hit
            return hit

    # 2 and 3) degraded mode: read the remark
    info = detect_country_from_remark(remark_hint)
    # Cache only definitive labels. "Global" means we still do not know, so let a
    # later source upgrade it.
    if info[0] != "Global":
        _HOST_COUNTRY_CACHE[endpoint] = info
    return info


def reset_country_cache() -> None:
    """Clear the country-label cache, for isolated tests."""
    _HOST_COUNTRY_CACHE.clear()


def stable_label(line: str) -> str:
    """Stable per-config suffix for the remark.

    This used to come from the line number, so inserting or deleting one config
    shifted every later line's label and rewrote the whole file. It now derives
    from the config content, so the label changes only when the config itself does.
    """
    key = dedup_key(line) or (line or "").strip()
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:6].upper()

# dedup_key(), vendored from freeconfigs._dedup_key.
_IDENTITY_PARAMS = frozenset({
    "security", "sni", "pbk", "sid", "host", "path", "servicename",
    "flow", "type", "headertype", "encryption", "mode",
    # alpn and extra provably affect reachability: the measured dependency map
    # showed alpn is emitted to alpn and extra to extra. Without them,
    # "alpn=h3" and "no alpn" got one key and one died silently as a duplicate.
    "alpn", "extra",
    "obfs", "obfs-password", "obfspassword",
    "congestion_control", "congestion",
    "publickey", "presharedkey", "address",
})


def _norm_type(value: str) -> str:
    value = (value or "").strip().lower()
    return "tcp" if value in ("", "raw", "none", "tcp") else value

#: Schemes that really emit `insecure`: hysteria2/tuic. vless/trojan emit neither
#: skip-cert-verify nor tls.insecure.
_INSECURE_SCHEMES = frozenset({"hysteria2", "hy2", "tuic"})

#: Literal spellings the converter actually reads. Intentionally not lowercased:
#: if a source writes `allowinsecure` all-lowercase, the converter does *not* see
#: it, so it must not influence the identity key either.
_INSECURE_KEYS = ("insecure", "allowInsecure", "allow_insecure")

#: Exactly converters.py:_truthy.
_TRUTHY_VALUES = frozenset({"1", "true", "yes", "on"})


def _insecure_flag(raw_params: dict) -> str:
    """"1" or "0", exactly what the converter will read from the line."""
    for key in _INSECURE_KEYS:
        values = raw_params.get(key)
        if values:
            return "1" if str(values[0] or "").strip().lower() in _TRUTHY_VALUES else "0"
    return "0"


_FRONT_HOST_BAD_CHARS = frozenset(' \t\r\n/:@?#{}"\\,;|<>()[]')


def _is_plausible_fronting_host(value: str) -> bool:
    """Can this value really be a fronting domain? Syntax only, no DNS.

    Why it still matters after phase I: before phase I, having sni/host made the
    key throw away the real server host and hand identity to that fronting value.
    A shared garbage value then merged two different servers and one died in
    aggregate.py as a duplicate. Today the real server host always stays in the
    key, so that merge path is closed; the validator still matters for the *other*
    direction: if garbage survives into `ep`, two otherwise identical lines, one
    with that garbage and one without, split into two keys and publish twice.
    Measured, 36 false splits behaved exactly that way.

    Rules and why:
      - no DNS and no TLD list: this runs on every line, so it must stay pure and
        cheap. A host like `fuck.rkn`, whose TLD is not in IANA, is intentionally
        not caught.
      - at least one dot. A public fronting domain is always an FQDN. Allowing a
        single-label value caused 12 false splits, i.e. one real endpoint broken
        into two keys.
      - one trailing dot is allowed. The first version of the measuring tool got
        this wrong and produced four false positives.
    """
    if not value or len(value) > 253:
        return False
    if value.startswith("[") and value.endswith("]") and len(value) > 2:
        return True  # IPv6 literal
    for ch in value:
        if ch in _FRONT_HOST_BAD_CHARS:
            return False
    if value.endswith("."):
        value = value[:-1]
    if not value or ".." in value or "." not in value:
        return False
    for label in value.split("."):
        if not label or len(label) > 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        for ch in label:
            if not (ch.isascii() and (ch.isalnum() or ch == "-")):
                return False
    return True


def _sni_is_endpoint(security: str) -> bool:
    """Whether `sni` can count as the server's real endpoint.

    Only for normal TLS. Two protocol facts:

      1. SNI is a TLS extension. If security is none or absent, no TLS handshake
         happens, so the client never sends SNI and that parameter is inert; it
         cannot define a distinct backend.

      2. In REALITY, serverName is intentionally a *third-party* site's domain
         whose certificate is being borrowed, not the server's own hostname. The
         official XTLS docs say REALITY uses the appearance and handshake of a
         target site as camouflage, and serverNames should usually stay consistent
         with target. So two totally different servers borrowing the same camouflage
         domain used to get one identity and one was dropped.

    Measured over the live 18,735-line corpus, keys that grouped two or more
    different *real* endpoints fell from 641 to 500, and false merges newly
    introduced = 0.

    host is intentionally exempt from this rule: the HTTP Host header is a
    different mechanism and in type=ws it routes even without TLS.
    """
    return security == "tls"


def _norm_aid(value: Any) -> str:
    """Normalise alterId exactly the way the product does.

    converters.parse_proxy reads it with `_safe_int(obj.get("aid"), 0)`, so a
    missing aid, aid=0 and aid="" all produce *identical* output. If the key kept
    the raw string, the same config would get two keys and publish twice. That is
    the cheap, avoidable duplicate direction, so it is normalised.
    """
    try:
        return str(int(str(value).strip() or "0"))
    except Exception:
        return "0"


_CASE_SENSITIVE_PARAMS = frozenset({
    "path", "servicename", "pbk", "publickey", "presharedkey",
    "obfs-password", "obfspassword",
})


def _norm_identity_value(key: str, value: str) -> str:
    # Lowercasing everything used to silently merge distinct HTTP paths such as
    # `path=TG%40ZDYZ2` and `path=tg%40zdyz2`, while the product emits the path
    # byte for byte and HTTP paths are case sensitive. It is worse for public keys:
    # lowercasing base64url yields a *different* key.
    if key in _CASE_SENSITIVE_PARAMS:
        return (value or "").strip()
    out = (value or "").strip().lower()
    if key in ("sni", "host"):
        for _ in range(2):
            decoded = urllib.parse.unquote(out)
            if decoded == out:
                break
            out = decoded
        out = out.strip().lower()
    if key == "type":
        # `_norm_type` returns "tcp" for the default forms. The general branch then
        # keeps that value because `nv != ""`, while an actually *missing* `type`
        # never enters `meaningful`. So `?type=tcp` and `?` produced different keys
        # for one server. Returning "" for the default collapses those two, while
        # leaving _norm_type untouched because the vmess branch uses it differently.
        normalised = _norm_type(out)
        return "" if normalised == "tcp" else normalised
    if key == "encryption":
        return "" if out in ("", "none") else out
    if key == "security":
        return "" if out in ("", "none") else out
    if key == "headertype":
        return "" if out in ("", "none") else out
    if key == "flow":
        return "" if out == "" else out
    return out


def _vmess_identity(obj: dict, line: str) -> str:
    """The identity key for a JSON-backed vmess line.

    The logic here is intentionally dense because this is the repo's identity
    function: deduping, output order, remark labels and unique-yield all lean on
    it. The algorithm itself is left intact; only the comments were compressed and
    the helper extracted so dedup_key() is readable again.
    """
    add = str(obj.get("add") or "").strip().lower()
    host = _norm_identity_value("host", str(obj.get("host") or ""))
    sni = _norm_identity_value("sni", str(obj.get("sni") or ""))
    tls = (str(obj.get("tls") or "")).strip().lower()
    # Anything the converter does not itself treat as TLS is identical to no TLS.
    # See converters.parse_proxy (`in ("tls", "reality")`) and pipeline's
    # FS_TLS_VALUES. So auto/none/""/junk all produce identical output. `xtls` is
    # deliberately kept only so the rule can split, never merge, a future case.
    tls = tls if tls in ("tls", "reality", "xtls") else ""
    net = _norm_type(str(obj.get("net") or ""))
    path = str(obj.get("path") or "")
    # Only the proven equivalence is kept: "" == "/". rstrip("/") used to merge
    # `/abc/` and `/abc`, which are distinct HTTP paths.
    path = "/" if path == "" else path

    # fronting-domain validation.
    # Two distinct rejection modes, with different consequences:
    #   (1) the value is not even a valid hostname -> garbage, carries no identity,
    #       so it leaves `meaningful` entirely. If it merely stayed in the query it
    #       would split identity on garbage; measured, 36 false splits were exactly
    #       one real endpoint broken into multiple keys by `host=/?bia_telegram...`.
    #   (2) the value is valid but this TLS/REALITY rule does not count it as an
    #       endpoint -> it is still a real config parameter and stays in the query,
    #       preserving today's distinctions without introducing new false splits.
    if host and not _is_plausible_fronting_host(host):
        host = ""
    if sni and not (_is_plausible_fronting_host(sni) and _sni_is_endpoint(tls)):
        sni = ""

    # Effective servername. converters.parse_proxy writes
    # `sni = _clean_sni(obj.get("sni") or obj.get("host"))`, and both converters
    # can therefore emit that value even when TLS is absent. Three direct byte-level
    # measurements showed tcp+with-sni vs tcp+without-sni, host-vs-sni, and grpc
    # with-sni vs without-sni all produce different client output. Without this
    # component those pairs would get one key and one would die silently as a
    # duplicate.
    srv = _norm_identity_value("sni", str(obj.get("sni") or "") or
                               str(obj.get("host") or ""))
    if srv and not _is_plausible_fronting_host(srv):
        srv = ""

    # host or sni merged "host=X, sni=∅" with "host=∅, sni=X" even though the
    # product emits them to *different* fields (HTTP Host vs TLS servername), so
    # they are different artefacts and must split.
    fronting = f"{host}~{sni}" if sni else host

    # The real server host never leaves the key now. fronting no longer replaces
    # it, which was the phase-I fix.
    return (
        f"vmess:{add}|ep={fronting}"
        f":{str(obj.get('port', '')).strip()}"
        f":{str(obj.get('id', '')).strip().lower()}"
        # alterId is emitted to both targets and mihomo feeds it into newAlterIDs.
        # No equivalence was proven, so the safe direction is to split, not merge.
        f":{net}:{path}:{tls}"
        f":{_norm_aid(obj.get('aid'))}"
        # `scy` is emitted verbatim to both targets. Lowercasing it would have
        # merged AUTO and auto while their output differs byte for byte.
        f":{str(obj.get('scy') or 'auto')}"
        f":srv={srv}"
    )


def dedup_key(line: str) -> str:
    """The server identity fingerprint, CDN aware.

    Exactly the same semantics as the bot, only refactored into a couple of small
    helpers so the function is readable without changing how the repo keys itself.
    """
    line = line.strip()
    if not line:
        return line

    vmess = _vmess_json(line)
    if vmess is not None:
        try:
            return _vmess_identity(vmess, line)
        except Exception:
            return line.split("#")[0].strip()[:120]

    if line.startswith("ss://"):
        try:
            without_remark = line.split("#")[0].strip()
            rest = without_remark[5:]
            # Split authority from query before any rsplit("@"). If the query itself
            # contains '@' (common in real data, e.g. `?note=@SomeChannel`), a raw
            # rsplit on the whole string makes the last @ come from the query and the
            # host collapses to nonsense. Measured on the live corpus: 14 bad keys
            # among 3,006 ss lines (12 query @ cases + 2 '/' after port cases).
            authority = rest.split("?", 1)[0]
            if "@" in authority:
                userinfo, hostpart = authority.rsplit("@", 1)
                hostpart = hostpart.split("/", 1)[0]
                decoded_ui = decode_base64_text(userinfo)
                if decoded_ui and ":" in decoded_ui:
                    userinfo = decoded_ui
                userinfo = urllib.parse.unquote(userinfo).lower()
                host, _, port = hostpart.rpartition(":")
                return f"ss:sip002:{userinfo}@{host.lower()}:{port}"
            decoded = decode_base64_text(rest)
            if decoded is None:
                raise ValueError("ss legacy body is not base64")
            # Unify the two Shadowsocks forms. The decoded legacy body is exactly
            # `method:pass@host:port`, i.e. the same structure as the SIP002 branch.
            # Before this, one server published in both forms got two keys and was
            # emitted twice. Real duplicates fixed: 4. No new false merge is
            # structurally possible unless method, password, host and port all match.
            decoded_no_frag = decoded.split("#")[0].split("?")[0]
            if "@" in decoded_no_frag:
                userinfo, hostpart = decoded_no_frag.rsplit("@", 1)
                hostpart = hostpart.split("/", 1)[0]
                host, _, port = hostpart.rpartition(":")
                if host and port:
                    userinfo = urllib.parse.unquote(userinfo).lower()
                    return f"ss:sip002:{userinfo}@{host.lower()}:{port}"
            return f"ss:legacy:{decoded.lower()}"
        except Exception:
            return line.split("#")[0].strip()[:120]

    # Structural ssr key instead of the raw base64 text.
    #
    # The old generic branch urlparsed `ssr://<base64>`, so the key was effectively
    # just the encrypted blob, including remarks/group. Consequences measured on the
    # 33,066-line corpus (112 ssr lines):
    #   1) one identical node published with different padding/alphabet or
    #      different remarks/group got different keys -> false splits. 52 groups
    #      collapsed to 28, a perfectly uniform {4: 28} histogram.
    #   2) endpoint_of() saw the same blob as the host -> GeoIP always failed -> all
    #      112 lines became Global 🌐. With decoding, 96 get their real country.
    #
    # Safety was measured before the change:
    #   - data_killing_merges = 0. None of the 24 merges collapsed distinct
    #     artefacts; each merged group had exactly one unique artefact.
    #   - false_splits = 0, total loss unchanged.
    #   - keys of the 32,954 non-ssr lines were byte-for-byte identical.
    #   - cross-scheme collisions = 0 thanks to the unique `ssr:` prefix.
    if line.startswith("ssr://"):
        try:
            parts = _ssr_parts(line)
            if parts:
                host, port, proto, method, obfs, pwd, obfsparam, protoparam = parts
                quote = urllib.parse.quote
                return (
                    f"ssr:{host.strip().lower()}:{port}"
                    f":{proto.strip().lower()}:{method.strip().lower()}"
                    f":{obfs.strip().lower()}:{quote(pwd, safe='')}"
                    f":op={quote(obfsparam, safe='')}:pp={quote(protoparam, safe='')}"
                )
        except Exception:
            pass
        # Unparseable -> unchanged legacy behaviour. Do *not* slice to 120 chars like
        # vmess/ss: those slices create artificial merges on long ssr bodies, i.e. the
        # exact false-merge direction this phase exists to close.

    try:
        without_remark = line.split("#")[0].strip()
        parsed = urllib.parse.urlparse(without_remark)
        raw_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        meaningful: Dict[str, str] = {}
        for param_key, param_values in raw_params.items():
            key = param_key.strip().lower()
            if key not in _IDENTITY_PARAMS:
                continue
            normalised = _norm_identity_value(key, str(param_values[0]) if param_values else "")
            if normalised != "":
                meaningful[key] = normalised
        # `insecure` is identity-bearing for hysteria2/tuic because it reaches the
        # output there. Adding it out of scope created 76 false splits in testing,
        # because vless/trojan never emit skip-cert-verify.
        if parsed.scheme.lower() in _INSECURE_SCHEMES:
            meaningful["insecure"] = _insecure_flag(raw_params)
        username = urllib.parse.unquote(parsed.username or "").lower()
        password = urllib.parse.unquote(parsed.password or "").lower()
        conn_host = (parsed.hostname or "").lower()
        try:
            port = str(parsed.port or "")
        except Exception:
            port = ""
        path = parsed.path.rstrip("/")
        sni_value = meaningful.get("sni", "")
        host_value = meaningful.get("host", "")

        # fronting validation.
        # Two kinds of rejection, with different effects:
        #   (1) the value is not even a valid hostname -> it is garbage and leaves
        #       `meaningful` entirely, or garbage splits one real endpoint into
        #       several keys.
        #   (2) the value is valid but this TLS/REALITY rule does not let it define
        #       the endpoint -> it is still a real config param and stays in the
        #       query, preserving current distinctions without creating new splits.
        security_value = meaningful.get("security", "")
        if sni_value and not _is_plausible_fronting_host(sni_value):
            sni_value = ""
            meaningful.pop("sni", None)
        elif sni_value and not _sni_is_endpoint(security_value):
            sni_value = ""
        if host_value and not _is_plausible_fronting_host(host_value):
            host_value = ""
            meaningful.pop("host", None)

        fronting_domain = sni_value or host_value
        sorted_query = "&".join(f"{k}={meaningful[k]}" for k in sorted(meaningful))
        return (
            f"{parsed.scheme.lower()}:"
            f"{username}:{password}"
            f"@{conn_host}|ep={fronting_domain}"
            f":{port}{path}?{sorted_query}"
        )
    except Exception:
        pass
    return line.split("#")[0].strip()[:200]

# Broken/fake config detection, vendored from subscription._is_dummy_config.
_DUMMY_INDICATORS = (
    "00000000-0000-0000-0000-000000000000",
    "app%20not%20supported",
    "app not supported",
    "proxies: []",
)


def is_dummy_config(config: str) -> bool:
    """Whether the config is fake or broken."""
    if not config:
        return False
    lowered = config.lower()
    return any(indicator in lowered for indicator in _DUMMY_INDICATORS)

# Remark branding, vendored from freeconfigs._rename_free_config_remark.

def brand_remark(line: str, idx=None) -> str:
    """Brand a config as ``{CC} {flag} | @Raydikalx | {tag}``.

    The `tag` is derived from the config content, not from the line position. The
    `idx` parameter is still accepted for backwards compatibility with old callers,
    but it is no longer used in the label. Putting positional numbering back in the
    remark would shift every later line's remark when one config is inserted and
    make the whole file look rewritten.
    """
    line = line.strip()
    if not line:
        return line

    tag = stable_label(line)
    vmess = _vmess_remark_source(line)
    if vmess is not None:
        try:
            obj, old_ps = vmess
            code, flag = country_for_endpoint(endpoint_of(line), old_ps)
            label = "Global 🌐" if code == "Global" else f"{code} {flag}"
            new_ps = f"{label} | {BRAND_CHANNEL} | {tag}"
            obj["ps"] = new_ps
            if "name" in obj:
                obj["name"] = new_ps
            encoded = base64.b64encode(
                json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("utf-8")
            return f"vmess://{encoded}"
        except Exception:
            return line

    if "#" in line:
        core, old_remark_enc = line.split("#", 1)
        try:
            old_remark = urllib.parse.unquote(old_remark_enc).strip()
        except Exception:
            old_remark = old_remark_enc.strip()
    else:
        core = line
        old_remark = ""

    code, flag = country_for_endpoint(endpoint_of(line), old_remark)
    label = "Global 🌐" if code == "Global" else f"{code} {flag}"
    new_remark = f"{label} | {BRAND_CHANNEL} | {tag}"
    return f"{core}#{new_remark}"

# Brand verification.

def remark_of(line: str) -> str:
    """The user-visible remark, or an empty string.

    "Visible" is deliberate: in vmess:// the remark lives inside base64 JSON (`ps`)
    and is *not* visible in the raw line, yet the client shows it to the user. Any
    brand check that just does ``BRAND_CHANNEL in line`` is therefore false-negative
    on every vmess node (measured: 2,373 out of 8,136 in live data).
    """
    if not line:
        return ""
    text = line.strip()
    if text.startswith("vmess://"):
        vmess = _vmess_json(text)
        if vmess is not None:
            return str(vmess.get("ps") or vmess.get("name") or "")
        # URI-style vmess is branded through the fragment, so fall through
    if "#" in text:
        return text.split("#", 1)[1]
    return ""


def is_branded(line: str) -> bool:
    """Whether the visible remark carries BRAND_CHANNEL.

    This is the executable definition of the branding invariant. It has to live in
    one place because three consumers rely on it and must not drift:
    aggregate.py's publish gate, test_pipeline.py, and any future inspection tool.

    The check is on the remark, not the whole line: ``BRAND_CHANNEL in line`` is
    both false-negative on vmess and false-positive on e.g. a host/query that
    happens to contain the brand while the user sees none.
    """
    return BRAND_CHANNEL in remark_of(line)

# Protocol detection.

def protocol_of(line: str) -> Optional[str]:
    """Canonical protocol name of a config, smart and future-proof."""
    if not line:
        return None
    match = _URI_SCHEME_RE.match(line.strip())
    if not match:
        return None
    scheme = match.group(1).lower()
    if scheme in _NON_PROXY_SCHEMES:
        return None
    return normalize_scheme(scheme)

# base64 decoding for whole source blobs, vendored from fetcher._try_base64_decode.

def try_base64_decode(raw: str) -> Optional[str]:
    """Safe base64 decode with a quality gate: at least 20% valid config lines."""
    clean = re.sub(r"\s+", "", raw)
    if not clean:
        return None
    padded = clean + "=" * (-len(clean) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded_bytes = decoder(padded)
        except Exception:
            continue
        for encoding in ("utf-8", "latin-1"):
            try:
                text = decoded_bytes.decode(encoding)
                non_empty = [ln.strip() for ln in text.splitlines() if ln.strip()]
                if not non_empty:
                    continue
                # Smart: count any valid scheme:// line, not just a fixed prefix list
                valid = [ln for ln in non_empty if is_proxy_config(ln)]
                if valid and (len(valid) / len(non_empty)) >= 0.20:
                    return text
            except UnicodeDecodeError:
                continue
    return None

# Repair `&amp;` when it was an HTML separator.
#
# parse_qs splits on `&`. If a source was copied out of HTML, `&` became `&amp;`
# and parameter names turned into `amp;security`, etc. Neither dedup_key() nor
# converters.parse_proxy() repaired this. Live output measurement over all 10
# affected lines showed `tls=False`, `sni=''`, `host=''`, `path=''` and network
# collapsing to tcp, i.e. the config was published and did not work.
#
# The rule is deliberately conditional: replace `&amp;` only where it is followed by
# a valid parameter name and `=`. Live corpus measurement: 55/55 `&amp;` instances
# were separators and 0 were not. So this is complete on real data and still
# conservative: if `&amp;` ever appears *inside* a parameter value, it is left alone.
_AMP_SEP = re.compile(r"&amp;(?=[A-Za-z_][A-Za-z0-9_.\-]*=)")


def _repair_amp_separator(line: str) -> str:
    """Restore `&amp;` to `&` only when it acts as a separator."""
    if "&amp;" not in line:
        return line
    return _AMP_SEP.sub("&", line)

# Repair raw control bytes in config text.
#
# A full scan of the published output (50 files, 37 MB) found exactly one config
# containing raw control bytes, and that one line injected six control bytes into
# three text files and their three base64 versions:
#
#     ss://…@37.32.27.224:9147?prefix=\x16\x03\x01\x00…#IR 🇮🇷 | @Raydikalx | …
#
# Origin: the `prefix` parameter in shadowsocks intentionally carries raw bytes
# (here, the start of a TLS ClientHello for obfuscation). Not malicious, but raw
# control bytes in a published text file are an integrity defect: NUL can truncate
# a C-based consumer, and 0x16 can confuse terminals/logs.
#
# Repair, not delete: measurement showed the converters ignore `prefix`, so the
# same node is present and healthy in clash.yaml and singbox.json. Deleting the
# line would remove a node the repo publishes today.
#
# The rule is deliberately two-zone:
#   - in query and fragment -> percent-encode, lossless and idempotent. RFC 3986
#     recommends exactly that for a non-legal byte, and the client reconstructs the
#     original byte with unquote, so the config still works.
#   - before `?` (scheme/authority) -> drop the line entirely. A control byte in the
#     host or port means the line is broken; percent-encoding it would only make it
#     *look* acceptable.
#
# Two independent measurements on real published corpora, intentionally dated
# because the repo rebuilds every 15 minutes:
#   - 2026-08-01, 10,091-line corpus -> 10,090 unchanged, 1 repaired, 0 dropped
#   - 2026-08-01, live re-run of this very implementation on a 10,019-line corpus
#     -> 10,018 unchanged, 1 repaired, 0 dropped
# In both, dedup_key() and stable_label() stayed the same before/after the repair,
# and Clash/sing-box output was byte-for-byte unchanged.
_CTRL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def _pct_encode_ctrl(text: str) -> str:
    """Percent-encode every control byte as %XX (RFC 3986)."""
    return _CTRL_CHAR_RE.sub(lambda m: "%%%02X" % ord(m.group(0)), text)


def _repair_control_chars(line: str) -> str:
    """Percent-encode raw control bytes in query/fragment.

    If a control byte appears *before* `?`, return the empty string so the caller
    drops the line. extract_valid_lines() short-circuits on that empty string.
    """
    if not _CTRL_CHAR_RE.search(line):
        return line
    head, frag_sep, frag = line.partition("#")
    authority, query_sep, query = head.partition("?")
    if _CTRL_CHAR_RE.search(authority):
        return ""
    repaired = authority + query_sep + _pct_encode_ctrl(query)
    if frag_sep:
        repaired += frag_sep + _pct_encode_ctrl(frag)
    return repaired

# packetEncoding normalisation for Hiddify / sing-box compatibility.
#
# The owner's field report was that importing top100 into the latest Hiddify fails
# with "failed to start background core". That was isolated by running the *official
# hiddify-core* on the live published corpus and pinned to one parameter value:
# packetEncoding=none.
#
# The exact chain, from the pinned source:
#   1. ray2sing/url_schema.go::ParseUrl normalises the *key* by lowercasing and
#      removing `_`, but leaves the *value* case sensitive.
#   2. ray2sing/vless.go reads decoded["packetencoding"] and defaults the empty
#      string to "xudp", then stores a *pointer* to that string.
#   3. hiddify-sing-box/protocol/vless/outbound.go accepts nil, "", "packetaddr"
#      and "xudp", and errors on anything else. Because the value is a *string
#      pointer*, format.ToString panics with "unknown value" instead of just
#      printing the string.
#   4. config/parser.go checks the *entire* profile, so one bad line burns the
#      whole subscription. That was proven live: 1 good config + 1 bad config ->
#      total failure.
#
# Crucial conclusion: `none`, which means "no xudp" in Xray, simply does not exist
# in sing-box. The semantic equivalent would be an empty string, and because of
# step 2 that is unreachable via the URL path. So the only values actually accepted
# through a link are exactly xudp and packetaddr.
#
# Why remove the parameter instead of rewriting it to xudp? Deleting it activates
# ray2sing's own default, which is xudp, so the outcome is the same but we do not
# impose a value onto the source config. If ray2sing ever changes its default, our
# output stays "silence" rather than becoming "the wrong claim".
#
# Zero regression for other clients was verified by reading their source directly:
# v2rayNG, v2rayN and mihomo have zero references to packetEncoding/xudp/
# packetaddr, so removing it costs nobody anything.
#
# Live measurement (2026-08-02, 10,728 lines in all/configs.txt):
#   - packetEncoding=xudp -> 124 lines, kept unchanged
#   - packetEncoding=none -> 27 lines, parameter removed
#   - no alternate spellings were seen in the wild
#   - among 3,257 vmess:// lines, zero JSON objects carried packetEncoding -> the
#     vmess branch is totally dormant today and produces zero churn, but exists
#     deliberately because sing-box validates vmess the same way.
_PACKET_ENCODING_SUPPORTED = frozenset({"xudp", "packetaddr"})

#: A `%` not followed by two hex digits: Go's net/url.QueryUnescape errors there
#: and the pair is dropped entirely. This regex reproduces that exactly.
_BAD_PCT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _go_query_unescape(text: str) -> Optional[str]:
    """Equivalent of net/url.QueryUnescape, returning None on a bad escape."""
    if _BAD_PCT_ESCAPE_RE.search(text):
        return None
    return urllib.parse.unquote_plus(text)


def _strip_vless_packet_encoding(line: str) -> str:
    """Drop a vless packetEncoding query param if it is not accepted.

    This follows net/url.ParseQuery plus ray2sing's key normalisation exactly:
      - only `&` separates pairs; any pair containing `;` is dropped by Go
      - key and value are percent-decoded (`+` -> space)
      - the key is compared lowercased and with `_` removed; the value is exact
      - multiple values for the *same* key are joined with `,`

    The parameter is kept only when every equal-key group resolves to one of the
    supported values. Otherwise *all* occurrences are removed, making the outcome
    deterministic even though Go iterates maps in random order.
    """
    head, frag_sep, frag = line.partition("#")
    base, query_sep, query = head.partition("?")
    if not query_sep or not query:
        return line
    pairs = query.split("&")
    hits: List[int] = []
    groups: Dict[str, List[str]] = {}
    for i, pair in enumerate(pairs):
        if not pair or ";" in pair:
            continue  # Go ignores empty pairs and any pair containing `;`
        raw_key, _eq, raw_val = pair.partition("=")
        key = _go_query_unescape(raw_key)
        val = _go_query_unescape(raw_val)
        if key is None or val is None:
            continue  # bad unescape: the pair never reaches the map in Go either
        if key.lower().replace("_", "") != "packetencoding":
            continue
        hits.append(i)
        groups.setdefault(key, []).append(val)
    if not hits:
        return line
    if all(",".join(vals) in _PACKET_ENCODING_SUPPORTED for vals in groups.values()):
        return line
    drop = set(hits)
    kept = [pair for i, pair in enumerate(pairs) if i not in drop]
    new_query = "&".join(kept)
    rebuilt = base + ("?" + new_query if new_query else "")
    if frag_sep:
        rebuilt += frag_sep + frag
    return rebuilt


def _strip_vmess_packet_encoding(line: str) -> str:
    """Drop the vmess JSON key `packetEncoding` when the value is unsupported.

    ray2sing/vmess.go reads this key *exactly* in camelCase, and convertToStrings
    turns any non-string into text via fmt.Sprintf (e.g. null -> <nil>). So only
    the exact strings xudp and packetaddr are safe.
    """
    body = line[8:].split("#")[0].strip()
    if not body:
        return line
    try:
        text = decode_base64_text(body)
        obj = json.loads(text) if text is not None else None
    except Exception:
        return line
    if not isinstance(obj, dict) or "packetEncoding" not in obj:
        return line
    value = obj["packetEncoding"]
    if isinstance(value, str) and value in _PACKET_ENCODING_SUPPORTED:
        return line
    try:
        del obj["packetEncoding"]
        encoded = base64.b64encode(
            json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
    except Exception:
        return line
    frag = line[8:].partition("#")
    return f"vmess://{encoded}" + (frag[1] + frag[2] if frag[1] else "")


def _normalize_packet_encoding(line: str) -> str:
    """Remove packetEncoding that sing-box/Hiddify cannot accept.

    Effective only for vless/vmess; all other schemes pass through unchanged.
    """
    if not line:
        return line
    scheme = line[:8].lower()
    if scheme == "vless://":
        return _strip_vless_packet_encoding(line)
    if scheme == "vmess://":
        return _strip_vmess_packet_encoding(line)
    return line


def extract_valid_lines(content: str) -> List[str]:
    """Extract valid config lines from one blob, direct or base64."""
    if not content:
        return []
    first_real = next(
        (ln.strip() for ln in content.splitlines()
         if ln.strip() and not ln.strip().startswith("//") and not ln.strip().startswith("#")),
        "",
    )
    # If the first real line is not a proxy config, the blob is probably base64.
    if not is_proxy_config(first_real):
        decoded = try_base64_decode(content)
        if decoded:
            content = decoded
    # Smart: any valid scheme:// is accepted, even future protocols.
    # The order is deliberate: repair `&amp;` first so query keys really become
    # keys, then repair control bytes, and only then normalise packetEncoding over
    # the cleaned query. No later step can reintroduce raw control bytes, so every
    # line leaving this function is guaranteed to contain none and no
    # packetEncoding value that sinks sing-box.
    return [
        line for raw in content.splitlines()
        if (line := _normalize_packet_encoding(
            _repair_control_chars(_repair_amp_separator(raw.strip()))))
        and is_proxy_config(line)
    ]

# `#` shield against ray2sing swallowing unsupported schemes.
#
# Hiddify does not read text subscriptions line by line. ray2sing first builds one
# regex from every known prefix and splits the whole body from one prefix to the
# *next*. Consequence: a line that starts with no known prefix is not its own line,
# it sticks to the *previous* chunk and, because the previous chunk is a URL, lands
# inside its fragment (the node name).
#
# A/B with the official core reproduced the failure on live data: when an ssr://
# run was present, the tag of the correct node right before it became:
#   "US 🇺🇸 | @Raydikalx | D50052\nssr://MTIw…#CN 🇨🇳 … § 0"
# i.e. the name of one healthy node was contaminated with several whole ssr lines.
# The output still exited 0, so this is a *silent* defect.
#
# Why ssr://: the prefix set in ray2sing is exactly the union of configTypes,
# endpointParsers, xrayConfigTypes, plus {"#", "//"}, and ssr:// is in none of
# them because sing-box removed ShadowsocksR in 1.6.0.
#
# The crucial fix: `#` itself is a known prefix, and expandDecodedConfig::add()
# throws away any chunk that starts with `#` or `//`. So one `#` line immediately
# before any run of unknown lines turns the whole run into a disposable chunk. No
# tag gets contaminated, no healthy node is lost, and those unknown nodes were
# unusable for Hiddify already.
#
# Zero regression for other clients was proven from source: v2rayNG, v2rayN and
# mihomo all read line by line, so an extra `#` line is inert. The shield text
# therefore deliberately contains no `://` of its own.
#
# Live measurement: only one scheme outside ray2sing's prefix set appears anywhere
# in the published output, ssr://, with 28 lines in all, 24 in heavy, 4 in light
# and 28 in protocols/shadowsocksr.txt. The rule is still written generically from
# the prefix set, not as a black-list of ssr, so a new future scheme is covered
# automatically.
RAY2SING_PREFIXES = frozenset({
    "vmess://", "vless://", "trojan://", "svmess://", "svless://", "strojan://",
    "ss://", "tuic://", "hysteria://", "hysteria2://", "hy2://", "ssh://",
    "naive://", "ssconf://", "direct://", "socks://", "phttp://", "phttps://",
    "http://", "https://", "xvmess://", "xvless://", "xtrojan://", "xdirect://",
    "mieru://", "mierus://", "psiphon://", "dnstt://",
    "wg://", "wireguard://", "warp://", "awg://", "[Interface]",
})

#: One reusable shield line. Deliberately no `://`, so no client mistakes it for a
#: URL, and readable enough that someone opening the file understands why it exists.
SHIELD_LINE = "# --- below: schemes sing-box cannot parse (skipped by Hiddify) ---"

#: Same set as a tuple because str.startswith(tuple) runs in C and matters on
#: 10k-line corpora.
_RAY2SING_PREFIX_TUPLE = tuple(sorted(RAY2SING_PREFIXES))


def is_ray2sing_prefixed(line: str) -> bool:
    """Whether this line starts with a prefix ray2sing knows."""
    return line.startswith(_RAY2SING_PREFIX_TUPLE)


def _is_shield(line: str) -> bool:
    """Whether this line is itself a disposable ray2sing chunk, # or //."""
    return line.startswith("#") or line.startswith("//")


def shield_unsupported_runs(lines: List[str]) -> List[str]:
    """Insert one `#` line before each run of lines outside ray2sing's prefixes.

    Idempotent: if the previous line is already `#` or `//`, whether a header or an
    earlier shield, no fresh shield is added. Running it again on its own output
    leaves the output unchanged.
    """
    out: List[str] = []
    prev_is_shield = False
    for line in lines:
        if not line.strip():
            # Blank lines are trimmed into the preceding ray2sing chunk and are
            # inert; they need no shield and do not break a run.
            out.append(line)
            continue
        if _is_shield(line):
            prev_is_shield = True
        elif is_ray2sing_prefixed(line):
            prev_is_shield = False
        elif not prev_is_shield:
            out.append(SHIELD_LINE)
            prev_is_shield = True
        out.append(line)
    return out


def encode_base64_subscription(lines: List[str], header: str = "") -> str:
    """Config list -> the standard base64 subscription payload.

    The shield is applied *inside* this function so the base64 version cannot
    diverge from the text version. Because it is idempotent, callers can safely
    have applied shield_unsupported_runs already.

    `header` is prepended *before* encoding, not after. Measured reason: Hiddify's
    parseHeadersFromContent first base64-decodes, so the header must live *inside*
    the payload to be seen. A header outside the base64 is both invisible and can
    break the payload for clients that decode the whole response in one shot.
    """
    joined = "\n".join(shield_unsupported_runs(lines))
    return base64.b64encode((header + joined).encode("utf-8")).decode("ascii")

# Output guard against raw control bytes.
#
# _repair_control_chars() closes the defect in *input*. This guard repeats the same
# guarantee on *output*: if a third path, header, label or generated text ever
# creates a control byte, publication fails loudly instead of shipping it silently.
#
# Fail-closed is deliberate. In this repo, an aggregate failure means the publish
# step never runs and the last healthy output stays on main. The worst outcome is
# stale data plus one very visible red run, not bad data going live. Correctness
# beats freshness here.
#
# Why every C0 byte except LF is forbidden, with zero false positives by
# measurement:
#   1. live scan of the full published output: TAB=0, CR=0, DEL=0 everywhere. The
#      only legal control byte in normal output was LF.
#   2. static scan: the only \t/\r in the writer modules live inside a *rejecting*
#      set `_FRONT_HOST_BAD_CHARS`, not in writable text. Headers contain only `#`,
#      text and LF.
#   3. serializer semantics: json.dumps and yaml.dump escape every C0 byte. Live
#      check on \x16, \t and \r: all three became textual escapes. So clash.yaml and
#      singbox.json structurally cannot contain raw control bytes. Base64 also only
#      outputs ASCII.
#
# Result: in normal operation this guard never fires. It is an assertion, not a
# filter.
class ControlByteInOutput(ValueError):
    """Output contains a forbidden raw control byte, publication must stop."""


#: Every C0 byte except `\n`, plus DEL. TAB and CR are included on purpose:
#: measurement showed they never occur, and their presence would mean CRLF or an
#: unintended header leak.
_FORBIDDEN_OUTPUT_CHAR_RE = re.compile(r"[\x00-\x09\x0b-\x1f\x7f]")


def assert_no_control_bytes(path: str, content: str) -> None:
    """Raise when `content` contains a forbidden control byte.

    The error message is intentionally actionable: path, byte, line and column, plus
    a short repr() excerpt so the log itself is not polluted.
    """
    match = _FORBIDDEN_OUTPUT_CHAR_RE.search(content)
    if match is None:
        return
    offset = match.start()
    line_no = content.count("\n", 0, offset) + 1
    line_start = content.rfind("\n", 0, offset) + 1
    column = offset - line_start + 1
    total = len(_FORBIDDEN_OUTPUT_CHAR_RE.findall(content))
    excerpt = content[max(line_start, offset - 40):offset + 40]
    raise ControlByteInOutput(
        f"refusing to write {path!r}: forbidden control byte "
        f"0x{ord(match.group(0)):02X} at line {line_no}, column {column} "
        f"(byte offset {offset}); {total} forbidden byte(s) in total; "
        f"excerpt={excerpt!r}"
    )
