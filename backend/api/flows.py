from fastapi import APIRouter, Query

from ..database import list_flows


router = APIRouter()


@router.get("/api/flows")
def recent_flows(
    limit: int = Query(default=100, ge=1, le=1000),
):
    flows = list_flows(limit)
    return {"success": True, "flows": flows, "count": len(flows)}