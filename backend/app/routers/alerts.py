from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import get_current_user
from app.models.schemas import AlertDetailResponse, AssessmentExplainability, DashboardResponse, PagedAlertsResponse, SIEMAlert, StatusUpdateRequest
from app.services.alert_repository import AlertRepository
from app.services.config import settings
from app.services.llm_client import LLMClient
from app.services.threat_analyzer import ThreatAnalyzer


router = APIRouter(tags=["alerts"])
repository = AlertRepository()
analyzer = ThreatAnalyzer(repository=repository, llm_client=LLMClient())


@router.get("/alerts", response_model=PagedAlertsResponse)
async def list_alerts(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
) -> PagedAlertsResponse:
    items, total = await repository.list_alerts_paged(page, size)
    total_pages = max(1, (total + size - 1) // size)
    return PagedAlertsResponse(items=items, total=total, page=page, size=size, total_pages=total_pages)


@router.get("/alerts/{alert_id}", response_model=AlertDetailResponse)
async def get_alert_detail(alert_id: str, current_user: dict = Depends(get_current_user)) -> AlertDetailResponse:
    result = await analyzer.analyze_alert(alert_id)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@router.get("/alerts/{alert_id}/explainability", response_model=AssessmentExplainability)
async def get_alert_explainability(alert_id: str, current_user: dict = Depends(get_current_user)) -> AssessmentExplainability:
    result = await analyzer.explain_alert_async(alert_id)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@router.patch("/alerts/{alert_id}/status", response_model=SIEMAlert)
async def update_alert_status(alert_id: str, body: StatusUpdateRequest, current_user: dict = Depends(get_current_user)) -> SIEMAlert:
    alert = await repository.update_alert_status(alert_id, body.status)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard(current_user: dict = Depends(get_current_user)) -> DashboardResponse:
    return await analyzer.build_dashboard_async()


@router.get("/health/wazuh")
async def wazuh_health(current_user: dict = Depends(get_current_user)) -> dict:
    if settings.app_mode != "wazuh":
        return {
            "indexer": {"ok": False, "note": "不在 Wazuh 模式"},
            "manager": {"ok": False, "note": "不在 Wazuh 模式"},
            "overall": "demo_mode",
        }

    idx_health = await repository.wazuh_indexer_health()
    mgr_health = await repository.wazuh_manager_health()

    idx_ok = idx_health.get("ok", False)
    mgr_ok = mgr_health.get("ok", False)

    idx_breaker = repository.indexer_breaker
    mgr_breaker = repository.manager_breaker

    result = {
        "indexer": {
            "ok": idx_ok,
            "url": settings.wazuh_indexer_url,
            "cluster_status": idx_health.get("status", "unknown"),
            "circuit_breaker": idx_breaker.state.value,
        },
        "manager": {
            "ok": mgr_ok,
            "url": settings.wazuh_manager_url,
            "version": mgr_health.get("version", "unknown"),
            "circuit_breaker": mgr_breaker.state.value,
        },
    }

    if idx_ok and mgr_ok:
        result["overall"] = "healthy"
    elif idx_ok or mgr_ok:
        result["overall"] = "degraded"
    else:
        result["overall"] = "unhealthy"

    return result


@router.get("/agents")
async def list_agents(current_user: dict = Depends(get_current_user)) -> list[dict]:
    return await repository.list_wazuh_agents()


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str, current_user: dict = Depends(get_current_user)) -> dict:
    agent = await repository.get_wazuh_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent
