"""预热分析缓存：预计算所有告警的LLM分析结果，后续页面秒开。"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.services.alert_repository import AlertRepository
from app.services.llm_client import LLMClient
from app.services.threat_analyzer import ThreatAnalyzer


async def main():
    repo = AlertRepository()
    llm = LLMClient()
    analyzer = ThreatAnalyzer(repo, llm)

    alerts = repo.list_alerts()
    total = len(alerts)
    cached = 0
    skipped = 0

    print(f"预热分析缓存 ({total}条告警)...")
    for i, alert in enumerate(alerts):
        cached_entry = repo.get_cached_analysis(alert.id)
        if cached_entry:
            skipped += 1
            continue

        try:
            result = await analyzer.analyze_alert(alert.id)
            if result:
                cached += 1
                print(f"  [{i+1}/{total}] {alert.id[:12]} - score={result.assessment.overall_score} ✓")
        except Exception as e:
            print(f"  [{i+1}/{total}] {alert.id[:12]} - ERROR: {e}")

    repo.save_cache_now()
    print(f"\n完成: 新增 {cached}, 跳过(已缓存) {skipped}, 总计 {total}")


if __name__ == "__main__":
    asyncio.run(main())
