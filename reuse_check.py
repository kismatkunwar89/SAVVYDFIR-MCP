"""Real VANKO double-call reuse check: each extractor twice; pass2 must reuse (skip parse)."""
import tempfile, os, time, json
from sift_mcp.audit import AuditLogger
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import disk

mp = "/mnt/windows_mount"
case = "VANKO-REUSECHK"
tmp = tempfile.mkdtemp()
disk.init_tools(CaseStateManager(os.path.join(tmp, "s.json")),
                AuditLogger(os.path.join(tmp, "a.jsonl")))

def reused(r):
    d = r.get("data") or {}
    for k in ("reused_output", "cache_hit", "reused", "durable_reuse"):
        if r.get(k) or d.get(k):
            return True
    return False

tools = ["extract_recycle_bin", "extract_powershell_history", "extract_scheduled_tasks",
         "extract_shellbags", "extract_lnk_files", "extract_jump_lists",
         "extract_browser_history", "extract_registry_fileaccess"]

print("=== reuse keys probe (first tool) ===")
fn0 = getattr(disk, tools[0])
r0 = fn0(image_path=mp, case_id=case)
print("top keys:", sorted(r0.keys()))
print("data keys:", sorted((r0.get("data") or {}).keys()))

print("=== double-call per tool ===")
ok = True
for name in tools:
    fn = getattr(disk, name)
    t0 = time.time(); r1 = fn(image_path=mp, case_id=case); t1 = time.time()
    r2 = fn(image_path=mp, case_id=case); t2 = time.time()
    ru = reused(r2)
    faster = (t2 - t1) < (t1 - t0) * 0.5  # pass2 <50% of pass1 time = likely reuse
    print("%-32s pass1=%s/%s pass2_REUSED=%s faster=%s (%.1fs->%.1fs)" % (
        name, r1.get("status"), r1.get("total_rows"), ru, faster, t1 - t0, t2 - t1))
    if not (ru or faster):
        ok = False
print("RESULT:", "ALL_REUSE_OK" if ok else "SOME_DID_NOT_REUSE")
