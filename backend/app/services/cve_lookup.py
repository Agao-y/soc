from __future__ import annotations

import json
from pathlib import Path

_cve_cache: list[dict] | None = None


def _load_cve() -> list[dict]:
    global _cve_cache
    if _cve_cache is not None:
        return _cve_cache
    data_file = Path(__file__).resolve().parents[2] / "data" / "cve_high.json"
    _cve_cache = json.loads(data_file.read_text(encoding="utf-8"))
    return _cve_cache


def search_cve(keywords: list[str], top: int = 5) -> list[dict]:
    """Search CVEs by keyword matching against product, vendor, description, and exploit_type."""
    results = []
    for cve in _load_cve():
        text = " ".join([
            cve.get("product", ""),
            cve.get("vendor", ""),
            cve.get("description", ""),
            cve.get("exploit_type", ""),
        ]).lower()
        score = sum(1 for kw in keywords if kw.lower() in text)
        if score > 0:
            results.append((score, cve))
    results.sort(key=lambda x: (-x[0], -x[1]["cvss"]))
    return [item[1] for item in results[:top]]


def search_cve_by_asset(hostname: str, log_text: str, service_hints: list[str] | None = None) -> list[dict]:
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

    return search_cve(keywords[:12])
