"""
SOC 攻击数据模拟器 — 向 Wazuh Indexer 注入多样化攻击告警

用法:
  python simulate_attacks.py          # 注入 500 条随机告警
  python simulate_attacks.py --count 200   # 注入 200 条
  python simulate_attacks.py --clear       # 清空注入的模拟数据
  python simulate_attacks.py --watch       # 持续注入 (每30秒一批)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv()

INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USERNAME", "")
INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASSWORD", "")
INDEXER_VERIFY = os.getenv("WAZUH_INDEXER_VERIFY_SSL", "true").lower() == "true"
ALERT_INDEX = os.getenv("WAZUH_ALERT_INDEX", "wazuh-alerts*")
SIM_TAG = "soc-simulation"

# ---- 攻击场景库 ----

SEVERITY_POOL = ["low", "medium", "high", "critical"]
SEVERITY_WEIGHTS = [15, 35, 35, 15]  # 加权分布

SCENARIOS = [
    {
        "type": "brute-force",
        "title_templates": [
            "SSH brute force attack detected from {src_ip}",
            "Multiple failed login attempts on {asset}",
            "RDP brute force from {src_ip} targeting {asset}",
            "FTP login brute force from {src_ip}",
            "WordPress admin brute force from {src_ip}",
        ],
        "rule_ids": [5710, 5712, 5716, 5718, 5760],
        "rule_groups": ["authentication_failed", "syslog", "sshd"],
        "mitre_tactics": ["Credential Access", "Brute Force"],
        "attack_stage": "Initial Access",
        "severity_bias": ["medium", "high"],
        "log_templates": [
            "Failed password for root from {src_ip} port {src_port} ssh2",
            "Failed password for admin from {src_ip} port {src_port} ssh2",
            "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={src_ip}",
            "Failed password for invalid user {username} from {src_ip} port {src_port}",
            "PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost={src_ip}",
        ],
    },
    {
        "type": "port-scan",
        "title_templates": [
            "Port scan detected from {src_ip}",
            "Nmap SYN scan from {src_ip}",
            "Horizontal port scan across {asset}",
            "Aggressive port scan targeting ports 1-1024 from {src_ip}",
        ],
        "rule_ids": [5600, 5601, 5602, 5603],
        "rule_groups": ["recon", "syslog", "firewall"],
        "mitre_tactics": ["Discovery", "Reconnaissance"],
        "attack_stage": "Reconnaissance",
        "severity_bias": ["low", "medium"],
        "log_templates": [
            "Connection attempts to multiple ports from {src_ip}",
            "nmap scan report for {asset} [{src_ip}]",
            "masscan detected: {src_ip} scanning common ports",
        ],
    },
    {
        "type": "c2",
        "title_templates": [
            "C2 beacon detected from {asset} to {dst_ip}",
            "Suspicious outbound connection to known C2 server {dst_ip}",
            "DNS tunneling to {dst_domain}",
            "HTTPS beacon pattern detected to {dst_ip}",
        ],
        "rule_ids": [5530, 5531, 5532, 5535],
        "rule_groups": ["attack", "c2", "trojan"],
        "mitre_tactics": ["Command and Control", "Defense Evasion"],
        "attack_stage": "Command and Control",
        "severity_bias": ["high", "critical"],
        "log_templates": [
            "Suspicious outbound connection: {asset} -> {dst_ip}:443 (beacon interval 60s)",
            "DNS query for {dst_domain} — known C2 domain (threat intel match)",
            "TLS handshake to {dst_ip} with self-signed certificate",
        ],
    },
    {
        "type": "ransomware",
        "title_templates": [
            "Ransomware encryption activity on {asset}",
            "Mass file modification detected on {asset}",
            "Suspicious process encrypting files on {asset}",
        ],
        "rule_ids": [5540, 5541, 5543],
        "rule_groups": ["attack", "ransomware", "malware"],
        "mitre_tactics": ["Impact", "Execution"],
        "attack_stage": "Execution",
        "severity_bias": ["critical"],
        "log_templates": [
            "Process {process} (PID {pid}) modified 500+ files in /data",
            "File extension changed to .encrypted on {asset}",
            "Ransom note detected: /home/user/README_DECRYPT.txt",
        ],
        "processes": ["encryptor.exe", "locker.bin", "svchost_inject.exe", "cryptmalware.exe"],
    },
    {
        "type": "exfiltration",
        "title_templates": [
            "Data exfiltration from {asset} to external IP {dst_ip}",
            "Large data transfer to {src_country} from {asset}",
            "Suspicious FTP upload from {asset}",
        ],
        "rule_ids": [5510, 5511, 5512],
        "rule_groups": ["attack", "exfiltration", "network"],
        "mitre_tactics": ["Exfiltration"],
        "attack_stage": "Exfiltration",
        "severity_bias": ["high", "critical"],
        "log_templates": [
            "Outbound transfer of 2.3GB to {dst_ip} on port 443",
            "FTP STOR /data/dump.sql from {asset} to external {dst_ip}",
        ],
    },
    {
        "type": "miner",
        "title_templates": [
            "Crypto miner detected on {asset}",
            "Mining pool connection from {asset}",
        ],
        "rule_ids": [5520, 5521],
        "rule_groups": ["attack", "miner", "malware"],
        "mitre_tactics": ["Execution", "Impact"],
        "attack_stage": "Execution",
        "severity_bias": ["medium", "high"],
        "log_templates": [
            "Process xmrig connected to pool.minexmr.com:4444",
            "High CPU usage detected from hidden process cryptonight",
        ],
    },
    {
        "type": "web-attack",
        "title_templates": [
            "SQL injection attempt from {src_ip}",
            "XSS attack from {src_ip} targeting {asset}",
            "Directory traversal from {src_ip}",
            "Webshell upload attempt on {asset}",
        ],
        "rule_ids": [31100, 31101, 31102, 31168],
        "rule_groups": ["web", "attack", "sql_injection"],
        "mitre_tactics": ["Initial Access", "Execution"],
        "attack_stage": "Initial Access",
        "severity_bias": ["high"],
        "log_templates": [
            'GET /search?id=1\' UNION SELECT username,password FROM users-- HTTP/1.1',
            'POST /upload.php HTTP/1.1 — PHP webshell payload detected',
            'GET /../../etc/passwd HTTP/1.1 from {src_ip}',
        ],
    },
]

# 全球攻击源IP库
ATTACK_IPS = [
    ("185.220.101.{}", "俄罗斯", "莫斯科", "RU"),
    ("45.155.205.{}", "乌克兰", "基辅", "UA"),
    ("103.224.182.{}", "印度尼西亚", "雅加达", "ID"),
    ("185.176.27.{}", "荷兰", "阿姆斯特丹", "NL"),
    ("194.26.29.{}", "德国", "法兰克福", "DE"),
    ("45.61.136.{}", "美国", "洛杉矶", "US"),
    ("91.240.118.{}", "英国", "伦敦", "GB"),
    ("103.149.162.{}", "越南", "河内", "VN"),
    ("185.156.73.{}", "法国", "巴黎", "FR"),
    ("45.14.224.{}", "巴西", "圣保罗", "BR"),
    ("116.31.116.{}", "中国", "深圳", "CN"),
    ("103.35.64.{}", "韩国", "首尔", "KR"),
    ("94.102.61.{}", "罗马尼亚", "布加勒斯特", "RO"),
    ("185.191.32.{}", "尼日利亚", "拉各斯", "NG"),
    ("5.188.62.{}", "伊朗", "德黑兰", "IR"),
]

ASSETS = [
    ("web-prod-01", "10.0.1.11", "prod"),
    ("web-prod-02", "10.0.1.12", "prod"),
    ("db-master-01", "10.0.2.21", "prod"),
    ("db-slave-01", "10.0.2.22", "prod"),
    ("app-server-01", "10.0.3.31", "prod"),
    ("app-server-02", "10.0.3.32", "prod"),
    ("dev-workstation", "10.0.99.10", "dev"),
    ("test-server", "10.0.98.5", "test"),
]

DST_DOMAINS = [
    "evil-c2.xyz", "bad-actors.net", "c2-beacon.top", "malware-update.cc",
    "steal-data.info", "ransom-c2.onion", "crypt-pool.ru",
]


def random_ip(pool_entry: tuple) -> str:
    base, country, city, code = pool_entry
    return base.format(random.randint(2, 250))


def generate_alert(scenario: dict, base_time: datetime) -> dict:
    """生成一条 Wazuh 格式的模拟告警"""
    src_pool = random.choice(ATTACK_IPS)
    src_ip = random_ip(src_pool)
    asset = random.choice(ASSETS)
    sev = random.choice(scenario["severity_bias"])
    rule_id = random.choice(scenario["rule_ids"])

    # 时间抖动
    jitter = timedelta(
        hours=random.randint(-24, 0),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )
    ts = (base_time + jitter).isoformat()

    title_tmpl = random.choice(scenario["title_templates"])
    title = title_tmpl.format(
        src_ip=src_ip, asset=asset[0], dst_ip=asset[1],
        dst_domain=random.choice(DST_DOMAINS),
        src_country=src_pool[1],
    )

    log_tmpl = random.choice(scenario.get("log_templates", [title]))
    log = log_tmpl.format(
        src_ip=src_ip, asset=asset[0], dst_ip=asset[1],
        src_port=random.randint(1024, 65535),
        dst_domain=random.choice(DST_DOMAINS),
        username=random.choice(["root", "admin", "test", "deploy"]),
        process=random.choice(scenario.get("processes", ["unknown.exe"])),
        pid=random.randint(1000, 99999),
    )

    dst_ip = asset[1]
    if scenario["type"] in ("c2", "exfiltration"):
        dst_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))

    return {
        "@timestamp": ts,
        "agent": {
            "id": f"{random.randint(1, 999):03d}",
            "name": asset[0],
            "ip": asset[1],
        },
        "rule": {
            "id": rule_id,
            "level": _severity_to_level(sev),
            "description": title,
            "groups": scenario["rule_groups"],
            "mitre": {"tactic": scenario["mitre_tactics"]},
        },
        "data": {
            "srcip": src_ip,
            "srcport": str(random.randint(1024, 65535)),
            "dstip": dst_ip if scenario["type"] in ("c2", "exfiltration") else asset[1],
            "dstport": str(random.choice([22, 80, 443, 3389, 8080, 3306])),
            "protocol": random.choice(["TCP", "UDP"]),
        },
        "location": random.choice([
            "/var/log/auth.log", "/var/log/syslog",
            "/var/log/apache2/access.log", "Windows Event Log",
        ]),
        "full_log": log,
        "decoder": {"name": "json-decoder", "parent": "wazuh"},
        "predecoder": {"hostname": asset[0], "srcip": src_ip},
        "simulation": True,
        "sim_tag": SIM_TAG,
        "sim_scenario": scenario["type"],
    }


def _severity_to_level(sev: str) -> int:
    return {"low": 4, "medium": 8, "high": 12, "critical": 15}[sev]


def generate_alerts(count: int = 500) -> list[dict]:
    now = datetime.now(timezone.utc)
    alerts = []
    for _ in range(count):
        # 按权重选场景
        scenario = random.choices(
            SCENARIOS,
            weights=[20, 15, 12, 8, 10, 8, 10],
            k=1,
        )[0]
        alerts.append(generate_alert(scenario, now))
    # 按时间倒序排序
    alerts.sort(key=lambda a: a["@timestamp"], reverse=True)
    return alerts


def inject_alerts(alerts: list[dict], dry_run: bool = False) -> int:
    """批量索引告警到 Wazuh Indexer"""
    if dry_run:
        for a in alerts[:10]:
            rule = a["rule"]
            print(f"  [{rule['level']}] {rule['description'][:80]}")
            print(f"    src={a['data']['srcip']} -> dst={a['data']['dstip']}")
            print(f"    type={a['sim_scenario']}  ts={a['@timestamp']}")
        print(f"  ... 共 {len(alerts)} 条 (dry-run)")
        return len(alerts)

    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    auth = httpx.BasicAuth(INDEXER_USER, INDEXER_PASS)
    client = httpx.Client(verify=ctx, timeout=30, auth=auth, trust_env=False)
    injected = 0
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index_name = f"wazuh-alerts-4.x-{today}"

    for alert in alerts:
        doc_id = str(uuid.uuid4())
        try:
            resp = client.put(
                f"{INDEXER_URL}/{index_name}/_doc/{doc_id}",
                json=alert,
            )
            if resp.status_code in (200, 201):
                injected += 1
            else:
                print(f"  WARN: {resp.status_code} {resp.text[:200]}")
        except Exception as e:
            print(f"  ERR: {e}")

    client.close()
    return injected


def clear_simulated() -> int:
    """删除所有模拟告警"""
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    auth = httpx.BasicAuth(INDEXER_USER, INDEXER_PASS)
    client = httpx.Client(verify=ctx, timeout=30, auth=auth, trust_env=False)

    payload = {
        "query": {"term": {"sim_tag": SIM_TAG}},
    }
    try:
        resp = client.post(
            f"{INDEXER_URL}/{ALERT_INDEX}/_delete_by_query",
            json=payload,
        )
        data = resp.json()
        deleted = data.get("deleted", 0)
        print(f"已删除 {deleted} 条模拟告警")
        return deleted
    except Exception as e:
        print(f"ERR: {e}")
        return 0
    finally:
        client.close()


def watch_mode(interval: int = 30, batch: int = 20):
    """持续注入模式 — 模拟实时攻击流"""
    print(f"持续攻击模拟: 每 {interval}s 注入 {batch} 条告警 (Ctrl+C 停止)")
    try:
        while True:
            alerts = generate_alerts(batch)
            n = inject_alerts(alerts)
            now = datetime.now().strftime("%H:%M:%S")
            print(f"  [{now}] 注入 {n} 条")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n模拟停止")


def main():
    parser = argparse.ArgumentParser(description="SOC 攻击数据模拟器")
    parser.add_argument("--count", type=int, default=500, help="注入数量 (默认500)")
    parser.add_argument("--clear", action="store_true", help="清空全部模拟数据")
    parser.add_argument("--watch", action="store_true", help="持续注入模式")
    parser.add_argument("--dry-run", action="store_true", help="仅预览，不写入")
    args = parser.parse_args()

    if not INDEXER_URL or not INDEXER_USER or not INDEXER_PASS:
        print("错误: 请在 .env 中设置 WAZUH_INDEXER_URL / WAZUH_INDEXER_USERNAME / WAZUH_INDEXER_PASSWORD")
        sys.exit(1)

    print(f"Indexer: {INDEXER_URL}")
    print(f"Index:   {ALERT_INDEX}")
    print()

    if args.clear:
        clear_simulated()
        return

    if args.watch:
        watch_mode()
        return

    print(f"生成 {args.count} 条模拟攻击告警...")
    alerts = generate_alerts(args.count)

    # 统计
    sev_dist = {}
    type_dist = {}
    for a in alerts:
        sev = _severity_to_level.__wrapped__(a) if hasattr(_severity_to_level, '__wrapped__') else _map_level_to_sev(a["rule"]["level"])
        sev_dist[sev] = sev_dist.get(sev, 0) + 1
        typ = a["sim_scenario"]
        type_dist[typ] = type_dist.get(typ, 0) + 1

    # 需要用反函数统计严重级别
    sev_dist2 = {}
    for a in alerts:
        level = a["rule"]["level"]
        if level >= 13: s = "critical"
        elif level >= 10: s = "high"
        elif level >= 6: s = "medium"
        else: s = "low"
        sev_dist2[s] = sev_dist2.get(s, 0) + 1

    print(f"严重级别: {sev_dist2}")
    print(f"攻击类型: {type_dist}")
    print()

    if args.dry_run:
        inject_alerts(alerts, dry_run=True)
    else:
        n = inject_alerts(alerts)
        print(f"成功注入 {n}/{len(alerts)} 条到 {INDEXER_URL}")
        print("刷新 Dashboard 即可看到新告警")


def _map_level_to_sev(level: int) -> str:
    if level >= 13: return "critical"
    if level >= 10: return "high"
    if level >= 6: return "medium"
    return "low"


if __name__ == "__main__":
    main()
