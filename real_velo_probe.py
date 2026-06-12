"""Run real extractors against the REAL Velociraptor ntfs root (partial triage)
to observe no-disk / partial-collection behavior."""
import os, tempfile
os.environ["OUTPUT_BASE"] = tempfile.mkdtemp()
from sift_mcp.audit import AuditLogger
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import disk

st = CaseStateManager(os.path.join(os.environ["OUTPUT_BASE"], "s.json"))
st.load("REAL-VELO")
disk.init_tools(st, AuditLogger(os.path.join(os.environ["OUTPUT_BASE"], "a.jsonl")))

root = "/tmp/hunt_lab_test/victim/uploads/ntfs/%5C%5C.%5CC%3A"
print("=== real extractors vs REAL velociraptor ntfs root (partial triage) ===")
for name in ("extract_recycle_bin", "extract_powershell_history",
             "extract_scheduled_tasks", "extract_registry_run_keys"):
    try:
        r = getattr(disk, name)(image_path=root, case_id="REAL-VELO")
        print("  %-30s status=%-16s rows=%s" % (name, r.get("status"), r.get("total_rows")))
    except Exception as e:
        print("  %-30s EXC=%s: %s" % (name, type(e).__name__, str(e)[:60]))
