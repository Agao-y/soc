"""
竞赛演示数据生成器 — 生成丰富的告警数据到 data/alerts.json
完全独立，不依赖 Docker / Wazuh / 外部 API
"""

import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

NOW = datetime.now(timezone.utc)

# ============================================================
# 攻击源 IP 库 (国家/城市/坐标)
# ============================================================
ATTACKERS = [
    {"ip": "185.220.101.{}", "country": "俄罗斯", "city": "莫斯科", "lat": 55.7558, "lon": 37.6173, "region": "欧洲"},
    {"ip": "45.155.205.{}", "country": "乌克兰", "city": "基辅", "lat": 50.4501, "lon": 30.5234, "region": "欧洲"},
    {"ip": "103.224.182.{}", "country": "印度尼西亚", "city": "雅加达", "lat": -6.2088, "lon": 106.8456, "region": "东南亚"},
    {"ip": "185.176.27.{}", "country": "荷兰", "city": "阿姆斯特丹", "lat": 52.3676, "lon": 4.9041, "region": "欧洲"},
    {"ip": "194.26.29.{}", "country": "德国", "city": "法兰克福", "lat": 50.1109, "lon": 8.6821, "region": "欧洲"},
    {"ip": "45.61.136.{}", "country": "美国", "city": "洛杉矶", "lat": 34.0522, "lon": -118.2437, "region": "北美"},
    {"ip": "91.240.118.{}", "country": "英国", "city": "伦敦", "lat": 51.5074, "lon": -0.1278, "region": "欧洲"},
    {"ip": "103.149.162.{}", "country": "越南", "city": "河内", "lat": 21.0278, "lon": 105.8342, "region": "东南亚"},
    {"ip": "185.156.73.{}", "country": "法国", "city": "巴黎", "lat": 48.8566, "lon": 2.3522, "region": "欧洲"},
    {"ip": "45.14.224.{}", "country": "巴西", "city": "圣保罗", "lat": -23.5505, "lon": -46.6333, "region": "南美"},
    {"ip": "116.31.116.{}", "country": "中国", "city": "深圳", "lat": 22.5431, "lon": 114.0579, "region": "东亚"},
    {"ip": "103.35.64.{}", "country": "韩国", "city": "首尔", "lat": 37.5665, "lon": 126.9780, "region": "东亚"},
    {"ip": "94.102.61.{}", "country": "罗马尼亚", "city": "布加勒斯特", "lat": 44.4268, "lon": 26.1025, "region": "欧洲"},
    {"ip": "185.191.32.{}", "country": "尼日利亚", "city": "拉各斯", "lat": 6.5244, "lon": 3.3792, "region": "非洲"},
    {"ip": "5.188.62.{}", "country": "伊朗", "city": "德黑兰", "lat": 35.6892, "lon": 51.3890, "region": "中东"},
    {"ip": "41.77.239.{}", "country": "埃及", "city": "开罗", "lat": 30.0444, "lon": 31.2357, "region": "非洲"},
    {"ip": "177.54.20.{}", "country": "阿根廷", "city": "布宜诺斯艾利斯", "lat": -34.6037, "lon": -58.3816, "region": "南美"},
    {"ip": "14.192.18.{}", "country": "印度", "city": "孟买", "lat": 19.0760, "lon": 72.8777, "region": "南亚"},
    {"ip": "202.183.112.{}", "country": "澳大利亚", "city": "悉尼", "lat": -33.8688, "lon": 151.2093, "region": "大洋洲"},
    {"ip": "77.247.110.{}", "country": "土耳其", "city": "伊斯坦布尔", "lat": 41.0082, "lon": 28.9784, "region": "中东"},
]

# ============================================================
# 内部资产库
# ============================================================
ASSETS = [
    {"hostname": "web-prod-01", "ip": "10.0.1.11", "env": "prod", "owner": "ops-team"},
    {"hostname": "web-prod-02", "ip": "10.0.1.12", "env": "prod", "owner": "ops-team"},
    {"hostname": "db-master-01", "ip": "10.0.2.21", "env": "prod", "owner": "dba-team"},
    {"hostname": "db-slave-01", "ip": "10.0.2.22", "env": "prod", "owner": "dba-team"},
    {"hostname": "app-server-01", "ip": "10.0.3.31", "env": "prod", "owner": "app-team"},
    {"hostname": "app-server-02", "ip": "10.0.3.32", "env": "prod", "owner": "app-team"},
    {"hostname": "dev-workstation", "ip": "10.0.99.10", "env": "dev", "owner": "dev-team"},
    {"hostname": "test-server", "ip": "10.0.98.5", "env": "test", "owner": "qa-team"},
]

# ============================================================
# 攻击场景定义
# ============================================================
SCENARIOS = {
    "brute-force": {
        "weight": 25,
        "severity": ["medium", "high"],
        "rule_ids": [5710, 5712, 5716, 5718, 5760],
        "rule_levels": [8, 10, 12],
        "mitre_tactics": ["Credential Access", "Brute Force"],
        "attack_stage": "Initial Access",
        "titles": [
            "SSH 暴力破解攻击: {src_ip} → {asset}",
            "RDP 登录爆破: {src_ip} 对 {asset} 尝试 {count} 次",
            "FTP 凭证爆破攻击从 {src_ip}",
            "WordPress 后台暴力破解 {src_ip}",
            "多源SSH爆破: {src_ip} 针对 {asset}",
            "数据库登录爆破: {src_ip} → {asset}:3306",
        ],
        "logs": [
            "Failed password for root from {src_ip} port {src_port} ssh2",
            "Failed password for admin from {src_ip} port {src_port} ssh2",
            "authentication failure; logname= uid=0 rhost={src_ip}",
            "Failed password for invalid user {username} from {src_ip} port {src_port}",
            "PAM 2 more authentication failures; rhost={src_ip}",
            "RDP login failed: user=administrator src={src_ip} attempts={count}",
        ],
    },
    "port-scan": {
        "weight": 20,
        "severity": ["low", "medium"],
        "rule_ids": [5600, 5601, 5602, 5603],
        "rule_levels": [4, 5, 7],
        "mitre_tactics": ["Discovery", "Reconnaissance"],
        "attack_stage": "Reconnaissance",
        "titles": [
            "端口扫描检测: {src_ip} 扫描 {asset}",
            "Nmap SYN 扫描来自 {src_ip}",
            "大规模端口扫描: {src_ip} 扫描 {count} 端口",
            "隐蔽扫描检测: {src_ip} → {asset}",
        ],
        "logs": [
            "Connection attempts to multiple ports from {src_ip}: {ports}",
            "nmap scan report for {asset} [{src_ip}]",
            "masscan detected: {src_ip} scanning common ports (1-1024)",
            "Port scan detected: {src_ip} → {asset} [{count} ports in 30s]",
        ],
    },
    "c2": {
        "weight": 15,
        "severity": ["high", "critical"],
        "rule_ids": [5530, 5531, 5532, 5535],
        "rule_levels": [12, 13, 15],
        "mitre_tactics": ["Command and Control", "Defense Evasion"],
        "attack_stage": "Command and Control",
        "titles": [
            "C2 信标检测: {asset} → {dst_ip}",
            "DNS 隧道检测: {asset} → {dst_domain}",
            "HTTPS 心跳信标到疑似C2服务器 {dst_ip}",
            "可疑加密外连: {asset} → {dst_ip}:443 (C2指纹匹配)",
        ],
        "logs": [
            "Suspicious outbound connection: {asset} → {dst_ip}:443 (beacon interval 60s)",
            "DNS query for {dst_domain} — known C2 domain (TI match)",
            "TLS beacon to {dst_ip} with JA3 hash a1b2c3d4e5 (C2 pattern)",
            "Recurring HTTPS POST to {dst_ip}/gate.php every 120s",
        ],
    },
    "ransomware": {
        "weight": 10,
        "severity": ["critical"],
        "rule_ids": [5540, 5541, 5543],
        "rule_levels": [14, 15],
        "mitre_tactics": ["Impact", "Execution"],
        "attack_stage": "Execution",
        "titles": [
            "勒索软件加密行为: {asset} 上 {count} 文件被修改",
            "可疑加密进程检测: {process} 在 {asset}",
            "勒索信检测: {asset} 发现 README_DECRYPT.txt",
        ],
        "logs": [
            "Process {process} (PID {pid}) modified {count} files in 60s on {asset}",
            "File extension changed to .encrypted on multiple directories",
            "Ransom note detected: /home/user/README_DECRYPT.txt on {asset}",
        ],
        "processes": ["encryptor.exe", "locker.bin", "svchost_inject.exe", "wannacry.exe"],
    },
    "exfiltration": {
        "weight": 12,
        "severity": ["high", "critical"],
        "rule_ids": [5510, 5511, 5512],
        "rule_levels": [10, 12, 14],
        "mitre_tactics": ["Exfiltration"],
        "attack_stage": "Exfiltration",
        "titles": [
            "数据渗出检测: {asset} → {dst_ip} ({size}MB)",
            "可疑FTP外传: {asset} 上传数据到 {dst_ip}",
            "DNS数据渗出: {asset} → {dst_domain}",
        ],
        "logs": [
            "Outbound transfer of {size}MB to {dst_ip} on port 443 from {asset}",
            "FTP STOR /data/dump_{date}.sql from {asset} to {dst_ip}",
            "Large DNS TXT queries from {asset} to {dst_domain} (avg {size} bytes)",
        ],
    },
    "miner": {
        "weight": 8,
        "severity": ["medium", "high"],
        "rule_ids": [5520, 5521],
        "rule_levels": [8, 10],
        "mitre_tactics": ["Execution", "Impact"],
        "attack_stage": "Execution",
        "titles": [
            "挖矿木马检测: {asset} 连接到矿池",
            "隐蔽挖矿进程: {process} 在 {asset} 高CPU占用",
        ],
        "logs": [
            "Process {process} connected to {dst_domain}:4444 (mining pool)",
            "High CPU ({cpu}%) detected on {asset} from hidden process {process}",
        ],
        "processes": ["xmrig.exe", "minergate-cli", "cpuminer.exe", "nicehash.exe"],
    },
    "web-attack": {
        "weight": 10,
        "severity": ["high", "critical"],
        "rule_ids": [31100, 31101, 31102, 31168],
        "rule_levels": [10, 12, 14],
        "mitre_tactics": ["Initial Access", "Execution"],
        "attack_stage": "Initial Access",
        "titles": [
            "SQL注入攻击: {src_ip} → {asset}",
            "XSS跨站脚本: {src_ip} 针对 {asset}",
            "目录遍历攻击: {src_ip} 尝试读取 {asset} 系统文件",
            "Webshell上传: {src_ip} → {asset}",
        ],
        "logs": [
            "GET /search?id=1' UNION SELECT username,password FROM users-- from {src_ip}",
            "POST /upload.php HTTP/1.1 — PHP webshell payload detected {src_ip}",
            "GET /../../../etc/passwd HTTP/1.1 from {src_ip}",
            "POST /admin/login HTTP/1.1 — SQLi payload in username field from {src_ip}",
        ],
    },
}

DST_DOMAINS = [
    "evil-c2.xyz", "bad-actors.net", "c2-beacon.top",
    "steal-data.info", "crypt-pool.ru", "malware-update.cc",
]
USERNAMES = ["root", "admin", "test", "deploy", "webmaster", "oracle"]
PORTS_COMMON = [22, 80, 443, 3306, 3389, 8080, 8443, 6379, 27017]


def random_ip(attacker: dict) -> str:
    return attacker["ip"].format(random.randint(2, 250))


def random_dst_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def generate():
    alerts = []
    scenario_list = list(SCENARIOS.items())

    for _ in range(200):
        # 加权选择场景
        sc_names = [s[0] for s in scenario_list]
        sc_weights = [s[1]["weight"] for s in scenario_list]
        sc_name = random.choices(sc_names, weights=sc_weights, k=1)[0]
        sc = SCENARIOS[sc_name]

        attacker = random.choice(ATTACKERS)
        asset = random.choice(ASSETS)
        src_ip = random_ip(attacker)
        dst_ip = asset["ip"] if sc_name not in ("c2", "exfiltration") else random_dst_ip()
        sev = random.choice(sc["severity"])
        rule_level = random.choice(sc["rule_levels"])
        rule_id = random.choice(sc["rule_ids"])

        # 时间 (过去 72 小时内)
        hours_ago = random.randint(0, 72)
        minutes_ago = random.randint(0, 59)
        ts = NOW - timedelta(hours=hours_ago, minutes=minutes_ago)

        count = random.randint(3, 500)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(PORTS_COMMON)
        size_mb = round(random.uniform(0.5, 50), 1)
        cpu_pct = random.randint(70, 99)
        process = random.choice(sc.get("processes", ["unknown.exe"]))
        pid = random.randint(1000, 99999)
        ports_str = ",".join(str(random.choice(PORTS_COMMON)) for _ in range(random.randint(3, 10)))
        date_str = ts.strftime("%Y%m%d")
        username = random.choice(USERNAMES)
        dst_domain = random.choice(DST_DOMAINS)

        title_tmpl = random.choice(sc["titles"])
        title = title_tmpl.format(
            src_ip=src_ip, asset=asset["hostname"], dst_ip=dst_ip,
            count=count, size=size_mb, process=process,
            dst_domain=dst_domain, cpu=cpu_pct,
        )

        log_tmpl = random.choice(sc["logs"])
        log = log_tmpl.format(
            src_ip=src_ip, asset=asset["hostname"], dst_ip=dst_ip,
            src_port=src_port, count=count, size=size_mb,
            process=process, pid=pid, cpu=cpu_pct,
            username=username, ports=ports_str, date=date_str,
            dst_domain=dst_domain,
        )

        alert = {
            "id": str(uuid.uuid4()),
            "title": title,
            "source": "wazuh",
            "severity": sev,
            "status": random.choice(["new"] * 7 + ["investigating"]),
            "timestamp": ts.isoformat(),
            "rule_name": title,
            "description": title,
            "log_excerpt": log[:500],
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_geo": {
                "region": attacker["region"],
                "country": attacker["country"],
                "city": attacker["city"],
                "latitude": attacker["lat"],
                "longitude": attacker["lon"],
            },
            "event_type": sc_name,
            "request_content": log,
            "packet_details": {
                "protocol": random.choice(["TCP", "UDP"]),
                "request_method": "GET" if sc_name == "web-attack" else "unknown",
                "request_uri": "/" if sc_name != "web-attack" else random.choice([
                    "/search?id=1' UNION SELECT", "/admin/login",
                    "/upload.php", "/../../../etc/passwd",
                ]),
                "source_port": src_port,
                "destination_port": dst_port,
                "packet_size": random.randint(64, 1500),
                "tcp_flags": random.choice(["SYN", "ACK", "PSH ACK", "RST"]),
                "payload_preview": log[:300],
            },
            "threat_type": sc_name,
            "attack_stage": sc["attack_stage"],
            "related_rule_ids": [str(rule_id)],
            "hardening_suggestions": [
                "结合原始日志补充规则调优，并核验主机与账号侧安全基线",
                "更新IDS/IPS规则库，封禁恶意源IP",
            ],
            "similar_incidents": {
                "total": random.randint(5, 200),
                "last_7_days": random.randint(1, 30),
                "closed_rate": round(random.uniform(0.3, 0.9), 2),
            },
            "ticket": {
                "status": random.choice(["pending", "processing"]),
                "assignee": random.choice(["admin", "analyst01", "system"]),
                "updated_at": ts.isoformat(),
                "response_minutes": random.randint(0, 480),
            },
            "mitre_tactics": sc["mitre_tactics"],
            "asset": {
                "hostname": asset["hostname"],
                "ip": asset["ip"],
                "owner": asset["owner"],
                "environment": asset["env"],
            },
            "related_entities": [
                v for v in [src_ip, dst_ip, asset["hostname"]]
                if v and v not in ("0.0.0.0", "unknown-host")
            ],
            "timeline": [
                {"timestamp": (ts - timedelta(minutes=random.randint(1, 120))).isoformat(),
                 "message": f"初步检测到异常行为: {attacker['country']} IP {src_ip}"},
                {"timestamp": (ts - timedelta(minutes=random.randint(1, 60))).isoformat(),
                 "message": f"关联分析确认攻击模式: {sc_name}"},
                {"timestamp": ts.isoformat(),
                 "message": log[:200]},
            ],
        }
        alerts.append(alert)

    # 按时间降序
    alerts.sort(key=lambda a: a["timestamp"], reverse=True)
    return alerts


def main():
    out_path = Path(__file__).resolve().parent / "data" / "alerts.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print("生成 200 条竞赛演示告警数据...")
    alerts = generate()

    # 统计
    from collections import Counter
    sevs = Counter(a["severity"] for a in alerts)
    types = Counter(a["threat_type"] for a in alerts)
    stages = Counter(a["attack_stage"] for a in alerts)

    print(f"严重级别: {dict(sevs)}")
    print(f"攻击类型: {dict(types)}")
    print(f"攻击阶段: {dict(stages)}")

    out_path.write_text(
        json.dumps(alerts, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\n已写入 {len(alerts)} 条 → {out_path}")
    print("现在用 APP_MODE=demo 启动后端即可使用")


if __name__ == "__main__":
    main()
