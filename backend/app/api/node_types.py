from fastapi import APIRouter
from app.nodes.registry import list_node_types

router = APIRouter(prefix="/api", tags=["node-types"])

@router.get("/node-types")
def get_node_types():
    """Return palette metadata for React Flow frontend."""
    return {"nodes": list_node_types()}
