from fastapi import APIRouter

from ..database import statistics


router = APIRouter()


@router.get("/api/statistics")
def backend_statistics():
    return {"success": True, **statistics(), "backend_status": "running"}


@router.get("/api/status")
def backend_status():
    return {
        "success": True,
        "status": "running",
        "backend": "healthy",
        "detector": "ready",
    }