from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.models.schemas import AlertDetailResponse, AssessmentExplainability, DashboardResponse, SIEMAlert
from app.services.alert_repository import AlertRepository
from app.services.llm_client import LLMClient
from app.services.threat_analyzer import ThreatAnalyzer


router = APIRouter(tags=["alerts"])
repository = AlertRepository()
analyzer = ThreatAnalyzer(repository=repository, llm_client=LLMClient())


@router.get("/alerts", response_model=list[SIEMAlert])
def list_alerts() -> list[SIEMAlert]:
    return repository.list_alerts()


@router.get("/alerts/{alert_id}", response_model=AlertDetailResponse)
async def get_alert_detail(alert_id: str) -> AlertDetailResponse:
    result = await analyzer.analyze_alert(alert_id)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@router.get("/alerts/{alert_id}/explainability", response_model=AssessmentExplainability)
def get_alert_explainability(alert_id: str) -> AssessmentExplainability:
    result = analyzer.explain_alert(alert_id)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@router.get("/dashboard", response_model=DashboardResponse)
def get_dashboard() -> DashboardResponse:
    return analyzer.build_dashboard()
