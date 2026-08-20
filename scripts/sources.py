# -*- coding: utf-8 -*-
"""Free config subscription sources, grouped by expected quality.

Tiers, best first:
    LIGHT  pre-tested or curated feeds. Small, high connect rate.
    HEAVY  bulk aggregators. Large and diverse, lower connect rate.
    ALL    LIGHT + HEAVY, de-duplicated, original order preserved.

Maintenance rules
    * Verify a URL with a real HTTP request before adding it.
    * Live per-source status is published to ``health.json``.
    * Retirement is automatic, not manual: ``state.py`` tracks *unique* yield
      per source. Raw config count and HTTP 200 both hide mirror feeds, e.g.
      Eternity.txt is a strict subset of sub_merge.txt from the same upstream.
    * Counts are derived from the lists below, never written by hand.
"""
from __future__ import annotations

from typing import List

#: Curated / self-tested feeds.
LIGHT_SOURCES: List[str] = [
    # Speed-tested aggregate, highest quality available on GitHub.
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    # Structurally validated fetcher.
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    # MahsaNet: only sub_1 is live, sub_2..4 answer 200 with an empty body.
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_1.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
    # Mid-size hand-picked lists.
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
]

#: High-volume aggregators. Expect heavy overlap between them.
HEAVY_SOURCES: List[str] = [
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_base64_Sub.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://github.com/ShatakVPN/ConfigForge-V2Ray/raw/refs/heads/main/configs/vless.txt",
    "https://github.com/VOID-Anonymity/V.O.I.D-VPN_Bypass/raw/refs/heads/main/url_work.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no7.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no8.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no9.txt",
    "https://raw.githubusercontent.com/ShadowException/VPN/refs/heads/main/configs/VPN-cat",
    # Replacements for the dead MahsaNetConfigTopic/xray_final.txt (HTTP 404).
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
]

#: Tier label -> URL list. Single place to add a tier.
SOURCE_TIERS = {
    "light": LIGHT_SOURCES,
    "heavy": HEAVY_SOURCES,
}


def all_sources() -> List[str]:
    """LIGHT + HEAVY without duplicate URLs, first-seen order preserved."""
    return list(dict.fromkeys(LIGHT_SOURCES + HEAVY_SOURCES))


def tier_of(url: str) -> str:
    """Tier a URL belongs to, or ``"unknown"`` if it is not registered here."""
    for tier, urls in SOURCE_TIERS.items():
        if url in urls:
            return tier
    return "unknown"


#: Derived, so docs and tests can never disagree with the lists.
LIGHT_COUNT: int = len(LIGHT_SOURCES)
HEAVY_COUNT: int = len(HEAVY_SOURCES)
SOURCE_COUNT: int = len(all_sources())
