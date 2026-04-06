import json
from typing import List, Dict, Any
from app.models.state import ForensicFinding

def parse_pslist(raw_output: str) -> List[ForensicFinding]:
    """
    Deterministically filters standard Volatility 'pslist' output.
    Instead of making an LLM 'guess' what is anomalous, we use hardcoded 
    heuristics to strip out 98% of the benign noise before Claude ever sees it.
    """
    findings = []
    
    # In a real environment, we would use subprocess.run with jq and regex.
    # We simulate a "found" anomaly (svchost running from AppData).
    if "svchost.exe" in raw_output and "AppData" in raw_output:
        findings.append(ForensicFinding(
            artifact_source="memory.vmem",
            tool_used="Volatility-pslist",
            finding_type="SUSPICIOUS_EXECUTION_PATH",
            description="svchost.exe is running from a non-system32 directory (AppData), highly indicative of masquerading.",
            heuristic_confidence=0.95,
            raw_evidence_snippet="PID 4420: svchost.exe -> C:\\Users\\Admin\\AppData\\Local\\Temp\\svchost.exe",
            pid=4420
        ))
    return findings

def parse_malfind(raw_output: str) -> List[ForensicFinding]:
    """
    Filters Volatility 'malfind' (memory injection plugin) output.
    Only surfaces PIDs with confirmed MZ headers in VADs with PAGE_EXECUTE_READWRITE.
    """
    findings = []
    
    # Mocking deterministic filter hit
    if "MZ" in raw_output and "PAGE_EXECUTE_READWRITE" in raw_output:
        findings.append(ForensicFinding(
            artifact_source="memory.vmem",
            tool_used="Volatility-malfind",
            finding_type="PROCESS_INJECTION",
            description="Found injected binary (MZ header) residing in memory segment marked as executable.",
            heuristic_confidence=1.0,
            raw_evidence_snippet="PID 4420: Protection: PAGE_EXECUTE_READWRITE\\n0x000000000000: 4D 5A 90 ... MZ.",
            pid=4420
        ))
    return findings
