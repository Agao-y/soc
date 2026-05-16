from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers.alerts import router as alerts_router


app = FastAPI(
    title="LLM-SIEM Threat Detection Platform",
    version="0.1.0",
    description="智能 SIEM 告警分析、威胁研判与处置建议平台",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts_router, prefix="/api")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
