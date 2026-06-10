from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

_cve_cache: list[dict] | None = None

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _load_cve() -> list[dict]:
    global _cve_cache
    if _cve_cache is not None:
        return _cve_cache
    data_file = Path(__file__).resolve().parents[2] / "data" / "cve_high.json"
    _cve_cache = json.loads(data_file.read_text(encoding="utf-8"))
    return _cve_cache


def search_cve_local(keywords: list[str], top: int = 5) -> list[dict]:
    """Search local CVE cache by keyword matching."""
    results = []
    for cve in _load_cve():
        text = " ".join([
            cve.get("product", ""), cve.get("vendor", ""),
            cve.get("description", ""), cve.get("exploit_type", ""),
        ]).lower()
        score = sum(1 for kw in keywords if kw.lower() in text)
        if score > 0:
            results.append((score, cve))
    results.sort(key=lambda x: (-x[0], -x[1]["cvss"]))
    return [item[1] for item in results[:top]]


async def search_cve_nvd(keyword: str, limit: int = 5) -> list[dict]:
    """Fetch recent CVEs from NVD API 2.0 (free, no key required)."""
    results: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                NVD_API,
                params={
                    "keywordSearch": keyword,
                    "resultsPerPage": min(limit, 20),
                },
                headers={"User-Agent": "SOC-DragonGuardian/1.0"},
            )
            resp.raise_for_status()
            data = resp.json()

            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")

                metrics = cve.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                cvss = cvss_v31 or cvss_v30
                base_score = cvss.get("baseScore", 0)
                severity = cvss.get("baseSeverity", "MEDIUM").lower()

                descriptions = cve.get("descriptions", [])
                desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                results.append({
                    "id": cve_id,
                    "cvss": base_score,
                    "severity": severity,
                    "product": keyword.title(),
                    "vendor": "",
                    "versions": [],
                    "description": desc_en[:300],
                    "exploit_type": "",
                    "attack_vector": "",
                    "patch": "",
                    "mitre": [],
                    "source": "nvd",
                })

        results.sort(key=lambda x: -x["cvss"])
        return results[:limit]
    except Exception:
        logger.debug("NVD API unavailable, falling back to local cache")
        return []


async def search_cve(keywords: list[str], top: int = 5) -> list[dict]:
    """Search CVEs: local cache + live NVD API. Dedup by CVE ID.

    In demo mode, only local cache is used (fast <1ms, 52 high-risk CVEs).
    NVD live API is only queried in wazuh mode for real-time CVE enrichment.
    """
    from app.services.config import settings

    local = search_cve_local(keywords, top)
    seen = {c["id"] for c in local}

    # Demo 模式跳过 NVD 实时查询（本地缓存已有 52 条高危 CVE，足够展示）
    if settings.app_mode == "demo":
        local.sort(key=lambda x: -x["cvss"])
        return local[:top]

    # Wazuh 模式：补充 NVD 实时查询
    primary_kw = keywords[0] if keywords else ""
    if primary_kw:
        nvd_results = await search_cve_nvd(primary_kw, limit=3)
        for c in nvd_results:
            if c["id"] not in seen and c["cvss"] >= 5.0:
                local.append(c)
                seen.add(c["id"])

    local.sort(key=lambda x: -x["cvss"])
    return local[:top]


async def search_cve_by_asset(
    hostname: str, log_text: str, service_hints: list[str] | None = None,
) -> list[dict]:
    """Search CVEs relevant to an asset, extracting keywords from logs and service hints."""
    keywords = list(service_hints or [])

    combo = (log_text + " " + hostname).lower()
    product_signatures: dict[str, list[str]] = {
        "openssh": ["ssh", "sshd", "openssh"],
        "apache": ["apache", "httpd", "apache2"],
        "nginx": ["nginx"],
        "mysql": ["mysql", "mariadb"],
        "postgresql": ["postgres", "postgresql", "pgsql"],
        "redis": ["redis"],
        "docker": ["docker", "runc", "containerd"],
        "kubernetes": ["k8s", "kubernetes", "kube"],
        "tomcat": ["tomcat", "catalina"],
        "jenkins": ["jenkins"],
        "php": ["php", "php-fpm"],
        "exchange": ["exchange", "owa", "ecp"],
        "windows": ["win", "windows", "smb", "rdp", "netlogon"],
        "linux": ["linux", "kernel", "ubuntu", "centos", "debian"],
        "sudo": ["sudo"],
        "chrome": ["chrome", "chromium"],
        "confluence": ["confluence", "atlassian"],
        "citrix": ["citrix", "netscaler", "adc"],
        "vmware": ["vmware", "vcenter", "vsphere"],
        "fortinet": ["fortinet", "fortios", "fortigate"],
        "paloalto": ["palo alto", "pan-os", "globalprotect"],
        "cisco": ["cisco", "asa", "ftd"],
        "curl": ["curl", "libcurl"],
    }

    for product, sigs in product_signatures.items():
        if any(sig in combo for sig in sigs):
            keywords.append(product)

    return await search_cve(keywords[:12])
