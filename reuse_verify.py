"""State-loaded reuse verification on real VANKO: each native tool twice;
pass2 must reuse (cache_hit) and not re-parse. Mirrors the real MCP flow where
start_investigation loads state before extraction."""
import os, tempfile, time
from sift_mcp.audit import AuditLogger
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import disk

mp = "/mnt/windows_mount"
case = "VANKO-REUSEV"
tmp = tempfile.mkdtemp()
os.environ["OUTPUT_BASE"] = tmp  # isolate cache so pass1 always extracts fresh
state = CaseStateManager(os.path.join(tmp, "s.json"))
state.create_case(case, manifest={}) if hasattr(state, "create_case") else None
state.load(case)
disk.init_tools(state, AuditLogger(os.path.join(tmp, "a.jsonl")))

def reused(r):
    d = r.get("data") or {}
    return bool(r.get("reused_output") or r.get("cache_hit") or d.get("reused_output")
                or d.get("cache_hit") or r.get("reused") or "reuse" in str(r.get("note","")).lower())

for name in ["extract_recycle_bin", "extract_powershell_history", "extract_scheduled_tasks"]:
    fn = getattr(disk, name)
    t0 = time.time(); r1 = fn(image_path=mp, case_id=case); t1 = time.time()
    r2 = fn(image_path=mp, case_id=case); t2 = time.time()
    print("%-30s p1=%s/%s  p2=%s/%s REUSED=%s  %.2fs->%.2fs" % (
        name, r1.get("status"), r1.get("total_rows"),
        r2.get("status"), r2.get("total_rows"), reused(r2), t1-t0, t2-t1))
