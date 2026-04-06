import uuid
import json
import os
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

# ==============================================================================
# SAVVYDFIR-MCP: Deterministic State Definitions
# No LLMs or probabilistic agents allowed here. Pure Data Models.
# ==============================================================================

DB_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "local_zep_state.json")

class ForensicFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_discovered: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    
    artifact_source: str     
    tool_used: str           
    finding_type: str        
    description: str         
    
    pid: Optional[int] = None
    file_path: Optional[str] = None
    ip_address: Optional[str] = None
    hash_md5: Optional[str] = None
    
    heuristic_confidence: float
    raw_evidence_snippet: Optional[str] = None 


class InvestigationState(BaseModel):
    investigation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    start_time: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    status: str = "ACTIVE"
    
    findings: List[ForensicFinding] = Field(default_factory=list)
    executed_playbooks: List[str] = Field(default_factory=list)
    
    def append_finding(self, finding: ForensicFinding):
        """
        Saves the state atomically to disk so the FastAPI server (Vue graph)
        can read the live updates from other fastmcp processes.
        """
        self.findings.append(finding)
        self._commit_to_disk()

    def _commit_to_disk(self):
        try:
            with open(DB_FILE, "w") as f:
                json.dump(self.model_dump(), f, indent=4)
        except Exception as e:
            print(f"Error syncing to disk DB: {e}")

    @classmethod
    def load_from_disk(cls):
        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, "r") as f:
                    data = json.load(f)
                    return cls(**data)
            except Exception:
                pass
        return cls() # return fresh instance if none exists

    def to_tiered_summary(self) -> Dict[str, Any]:
        high_conf_findings = [f for f in self.findings if f.heuristic_confidence >= 0.8]
        return {
            "investigation_id": self.investigation_id,
            "total_findings": len(self.findings),
            "high_confidence_anomalies": len(high_conf_findings),
            "executed_playbooks": self.executed_playbooks,
            "critical_indicators": [
                f"{f.finding_type}: {f.description}" 
                for f in high_conf_findings[:5]
            ]
        }
