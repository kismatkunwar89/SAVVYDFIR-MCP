from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.models.state import InvestigationState

app = FastAPI(title="SAVVYDFIR-MCP Graph Bridge API")

# Allow the Vue.js frontend to talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/graph")
async def get_zep_graph():
    """
    This endpoint reads the atomic JSON state saved by the FastMCP tool 
    (from the other process) and serves it directly to the Vue frontend.
    """
    state = InvestigationState.load_from_disk()
    
    # We transform the pure Findings into standard Nodes and Edges for Vue
    nodes = []
    edges = []
    
    # Add the central "Hypothesis" node
    nodes.append({"id": "investigation", "label": "Active Investigation", "group": "root"})
    
    for idx, f in enumerate(state.findings):
        # 1. Artifact Source Node (e.g., $MFT)
        nodes.append({"id": f.artifact_source, "label": f.artifact_source, "group": "artifact"})
        edges.append({"from": "investigation", "to": f.artifact_source})
        
        # 2. Finding Node (e.g., svchost.exe PID 4420)
        finding_id = f.finding_id
        nodes.append({"id": finding_id, "label": f.finding_type, "title": f.description, "group": "finding"})
        edges.append({"from": f.artifact_source, "to": finding_id})
        
    return {"nodes": nodes, "edges": edges}
