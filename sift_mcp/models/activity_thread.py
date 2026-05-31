"""activity_thread.py - Cyber Kill Chain phase mapping for blindspot detection.

W1.7 (CR13 Option X): Activity Thread tracks which Cyber Kill Chain phases
have evidence (findings mapped to phase). Empty phase = blindspot per Diamond
Model Axiom 4: every malicious activity must traverse a succession of phases.

The Activity Thread is rendered as a Mermaid diagram in the final report,
filled phases shown in green, empty (blindspot) phases shown in red. This is
direct hackathon judging-criterion-#5 deliverable (Audit Trail Quality -
'can judges trace any finding back to specific tool execution that produced
it', extended to 'and see what's MISSING').

References:
- Notebook #43 (Proactive Threat Hunting): Diamond Model + Activity Thread
- Lockheed Martin Cyber Kill Chain (canonical phase list)
- MITRE ATT&CK tactics align ~1:1 with kill-chain phases
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Cyber Kill Chain phases (Lockheed Martin canonical, MITRE-compatible)
# ---------------------------------------------------------------------------

class KillChainPhase(str, Enum):
    """Lockheed Martin Cyber Kill Chain canonical phases.

    Each phase ALIGNS with MITRE ATT&CK tactic groupings:
        RECONNAISSANCE      → TA0043 Reconnaissance
        WEAPONIZATION       → (offline, not directly observable)
        DELIVERY            → TA0001 Initial Access
        EXPLOITATION        → TA0002 Execution + TA0004 Privilege Escalation
        INSTALLATION        → TA0003 Persistence + TA0005 Defense Evasion
        COMMAND_AND_CONTROL → TA0011 Command and Control
        ACTIONS_ON_OBJECTIVES → TA0009 Collection + TA0010 Exfiltration + TA0040 Impact
    """
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"  # rarely observable on host
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


# Color hints for Mermaid rendering - green = evidence present, red = blindspot
KILL_CHAIN_COLORS_FILLED = "#16a34a"  # green
KILL_CHAIN_COLORS_EMPTY = "#dc2626"   # red
KILL_CHAIN_COLORS_PARTIAL = "#eab308" # amber (single-source, low corroboration)


# Default mapping: MITRE technique prefix → KillChainPhase
# This is used to auto-classify findings that carry MITRE techniques into
# the right phase. Agnostic - no hardcoded case values.
MITRE_TECHNIQUE_PHASE_MAP: dict[str, KillChainPhase] = {
    # Reconnaissance
    "T1595": KillChainPhase.RECONNAISSANCE,  # Active Scanning
    "T1592": KillChainPhase.RECONNAISSANCE,  # Gather Victim Host Info
    "T1589": KillChainPhase.RECONNAISSANCE,  # Gather Victim Identity Info
    # Initial Access / Delivery
    "T1566": KillChainPhase.DELIVERY,        # Phishing
    "T1190": KillChainPhase.DELIVERY,        # Exploit Public-Facing Application
    "T1078": KillChainPhase.DELIVERY,        # Valid Accounts
    # Execution / Exploitation
    "T1059": KillChainPhase.EXPLOITATION,    # Command and Scripting Interpreter
    "T1106": KillChainPhase.EXPLOITATION,    # Native API
    "T1203": KillChainPhase.EXPLOITATION,    # Exploitation for Client Execution
    "T1204": KillChainPhase.EXPLOITATION,    # User Execution
    # Privilege Escalation (also exploitation phase)
    "T1055": KillChainPhase.EXPLOITATION,    # Process Injection
    "T1068": KillChainPhase.EXPLOITATION,    # Exploitation for Privilege Escalation
    # Persistence / Installation
    "T1547": KillChainPhase.INSTALLATION,    # Boot/Logon Autostart Execution
    "T1543": KillChainPhase.INSTALLATION,    # Create or Modify System Process
    "T1053": KillChainPhase.INSTALLATION,    # Scheduled Task/Job
    "T1136": KillChainPhase.INSTALLATION,    # Create Account
    # Defense Evasion
    "T1070": KillChainPhase.INSTALLATION,    # Indicator Removal (log clearing, timestomp)
    "T1027": KillChainPhase.INSTALLATION,    # Obfuscated Files or Information
    "T1562": KillChainPhase.INSTALLATION,    # Impair Defenses
    # Credential Access (often classified with C2 for stolen creds usage)
    "T1003": KillChainPhase.EXPLOITATION,    # OS Credential Dumping
    "T1110": KillChainPhase.EXPLOITATION,    # Brute Force
    # Discovery
    "T1083": KillChainPhase.EXPLOITATION,    # File and Directory Discovery
    "T1057": KillChainPhase.EXPLOITATION,    # Process Discovery
    "T1018": KillChainPhase.EXPLOITATION,    # Remote System Discovery
    # Lateral Movement (also installation-like in cycle)
    "T1021": KillChainPhase.INSTALLATION,    # Remote Services (SMB, WinRM)
    "T1570": KillChainPhase.INSTALLATION,    # Lateral Tool Transfer
    # Command and Control
    "T1071": KillChainPhase.COMMAND_AND_CONTROL,  # Application Layer Protocol
    "T1090": KillChainPhase.COMMAND_AND_CONTROL,  # Proxy
    "T1573": KillChainPhase.COMMAND_AND_CONTROL,  # Encrypted Channel
    # Collection
    "T1005": KillChainPhase.ACTIONS_ON_OBJECTIVES,  # Data from Local System
    "T1119": KillChainPhase.ACTIONS_ON_OBJECTIVES,  # Automated Collection
    "T1560": KillChainPhase.ACTIONS_ON_OBJECTIVES,  # Archive Collected Data
    # Exfiltration
    "T1041": KillChainPhase.ACTIONS_ON_OBJECTIVES,  # Exfiltration Over C2
    "T1048": KillChainPhase.ACTIONS_ON_OBJECTIVES,  # Exfiltration Over Alternative Protocol
    "T1567": KillChainPhase.ACTIONS_ON_OBJECTIVES,  # Exfiltration Over Web Service
    # Impact
    "T1486": KillChainPhase.ACTIONS_ON_OBJECTIVES,  # Data Encrypted for Impact (ransomware)
    "T1490": KillChainPhase.ACTIONS_ON_OBJECTIVES,  # Inhibit System Recovery (vssadmin delete)
    "T1485": KillChainPhase.ACTIONS_ON_OBJECTIVES,  # Data Destruction
}


def classify_finding_to_phase(mitre_techniques: list[str]) -> Optional[KillChainPhase]:
    """Map a finding's MITRE techniques to its most-likely kill-chain phase.

    Returns the FIRST matching phase based on technique-base lookup
    (T1059.001 → T1059 → EXPLOITATION). Returns None if no technique matches.
    """
    for tech in mitre_techniques or []:
        tech_upper = str(tech).strip().upper()
        # Try exact match first
        if tech_upper in MITRE_TECHNIQUE_PHASE_MAP:
            return MITRE_TECHNIQUE_PHASE_MAP[tech_upper]
        # Try base technique (drop .NNN sub-technique)
        base = tech_upper.split(".", 1)[0]
        if base in MITRE_TECHNIQUE_PHASE_MAP:
            return MITRE_TECHNIQUE_PHASE_MAP[base]
    return None


# ---------------------------------------------------------------------------
# Activity Thread state model
# ---------------------------------------------------------------------------

class ActivityThread(BaseModel):
    """Per-case mapping of Cyber Kill Chain phases → finding IDs.

    Lives in state.json under ``state.activity_thread``. Updated whenever a
    finding is added (via add_finding / submit_finding) - the finding's
    mitre_techniques are classified into a phase, and the finding ID is
    appended to that phase's bucket.

    The report's Activity Thread section reads this state and emits a
    Mermaid graph:
        - Phase node colored green = ≥2 findings (corroborated)
        - Phase node colored amber = 1 finding (single-source observation)
        - Phase node colored red = empty (BLINDSPOT - per Diamond Axiom 4)
    """

    # Per-phase finding ID buckets
    phases: dict[str, list[str]] = Field(
        default_factory=lambda: {phase.value: [] for phase in KillChainPhase},
        description="Mapping of KillChainPhase.value → list of finding_ids classified to that phase.",
    )

    # Per-phase data_gap notes (why a phase is empty when it shouldn't be)
    blindspot_notes: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Mapping of KillChainPhase.value → analyst-authored note explaining "
            "why this phase has no evidence (e.g., 'evidence not extracted', "
            "'logs cleared by attacker', 'phase not relevant to case scope')."
        ),
    )

    @field_validator("phases")
    @classmethod
    def _validate_phase_keys(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        """Phase keys must match KillChainPhase enum values."""
        valid_keys = {phase.value for phase in KillChainPhase}
        for k in v:
            if k not in valid_keys:
                raise ValueError(f"Invalid kill-chain phase key: {k!r}. Valid: {sorted(valid_keys)}")
        return v

    def add_finding(self, finding_id: str, mitre_techniques: list[str]) -> Optional[str]:
        """Classify a finding into its kill-chain phase and append the ID.

        Returns the phase.value the finding was added to, or None if
        no MITRE technique matched (finding remains unclassified and
        won't appear in the Activity Thread for this run).
        """
        phase = classify_finding_to_phase(mitre_techniques)
        if phase is None:
            return None
        bucket = self.phases.setdefault(phase.value, [])
        if finding_id not in bucket:
            bucket.append(finding_id)
        return phase.value

    def empty_phases(self) -> list[str]:
        """Return phase.value for every phase with zero classified findings.

        These are the BLINDSPOTS per Diamond Axiom 4. Excludes
        WEAPONIZATION (rarely observable on host artifacts).
        """
        return [
            phase.value
            for phase in KillChainPhase
            if phase != KillChainPhase.WEAPONIZATION
            and not self.phases.get(phase.value)
        ]

    def filled_phases(self) -> list[str]:
        """Return phase.value for every phase with ≥1 classified finding."""
        return [phase.value for phase in KillChainPhase if self.phases.get(phase.value)]

    def phase_status(self, phase: KillChainPhase) -> str:
        """Return 'filled' (≥2 findings = corroborated), 'partial' (1 finding),
        or 'empty' (0 findings - blindspot)."""
        n = len(self.phases.get(phase.value, []))
        if n >= 2:
            return "filled"
        if n == 1:
            return "partial"
        return "empty"

    def coverage_summary(self) -> dict[str, int]:
        """One-line snapshot for reporting."""
        return {
            "phases_filled": len([p for p in KillChainPhase if self.phase_status(p) == "filled"]),
            "phases_partial": len([p for p in KillChainPhase if self.phase_status(p) == "partial"]),
            "phases_empty": len([p for p in KillChainPhase
                                  if self.phase_status(p) == "empty"
                                  and p != KillChainPhase.WEAPONIZATION]),
            "total_classified_findings": sum(len(v) for v in self.phases.values()),
        }


__all__ = [
    "ActivityThread",
    "KillChainPhase",
    "classify_finding_to_phase",
    "MITRE_TECHNIQUE_PHASE_MAP",
    "KILL_CHAIN_COLORS_FILLED",
    "KILL_CHAIN_COLORS_EMPTY",
    "KILL_CHAIN_COLORS_PARTIAL",
]
