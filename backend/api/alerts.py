from fastapi import APIRouter, HTTPException, Query

from ..database import get_alert, list_alerts


router = APIRouter()


@router.get("/api/alerts")
def recent_alerts(
    limit: int = Query(default=100, ge=1, le=1000),
):
    alerts = list_alerts(limit)
    return {"success": True, "alerts": alerts, "count": len(alerts)}


@router.get("/api/alerts/{alert_id}")
def alert_by_id(alert_id: str):
    alert = get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"success": True, "alert": alert}