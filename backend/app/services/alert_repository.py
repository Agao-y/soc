from __future__ import annotations

import json
from pathlib import Path

from app.models.schemas import SIEMAlert


class AlertRepository:
    def __init__(self) -> None:
        root = Path(__file__).resolve().parents[2]
        self._data_file = root / "data" / "alerts.json"

    def list_alerts(self) -> list[SIEMAlert]:
        payload = json.loads(self._data_file.read_text(encoding="utf-8"))
        return [SIEMAlert.model_validate(item) for item in payload]

    def get_alert(self, alert_id: str) -> SIEMAlert | None:
        for alert in self.list_alerts():
            if alert.id == alert_id:
                return alert
        return None
