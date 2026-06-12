"""Pinpoint why the 3 native tools miss/fail on real VANKO (no state.load needed:
artifact_absent/collection_failed returns before the reuse path)."""
import tempfile, os, subprocess
from sift_mcp.audit import AuditLogger
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import disk

mp = "/mnt/windows_mount"
case = "VANKO-DIAG2"
tmp = tempfile.mkdtemp()
disk.init_tools(CaseStateManager(os.path.join(tmp, "s.json")),
                AuditLogger(os.path.join(tmp, "a.jsonl")))

def sh(c): return subprocess.getoutput(c)

print("VOLUME_ROOTS:", disk._user_activity_volume_roots(mp))
print("--- what is actually on the mount (case-insensitive) ---")
print("psreadline:", sh("find /mnt/windows_mount/Users -ipath '*PowerShell*ConsoleHost_history.txt' 2>/dev/null | head -3"))
print("recyclebin_dir:", sh("ls -d /mnt/windows_mount/[\\$]Recycle.Bin 2>/dev/null"))
print("recyclebin_I:", sh("ls /mnt/windows_mount/[\\$]Recycle.Bin/*/[\\$]I* 2>/dev/null | head -3"))
print("tasks_count:", sh("find /mnt/windows_mount/Windows/System32/Tasks -type f 2>/dev/null | wc -l"))
print("--- exact PSReadline dir casing ---", sh("find /mnt/windows_mount/Users -ipath '*PowerShell*' -iname 'PSReadL*' -type d 2>/dev/null | head -3"))

print("--- tool results ---")
for name in ["extract_powershell_history", "extract_scheduled_tasks", "extract_recycle_bin"]:
    r = getattr(disk, name)(image_path=mp, case_id=case)
    print(name, "status=", r.get("status"), "rows=", r.get("total_rows"),
          "note=", str(r.get("note"))[:160],
          "pf=", str(r.get("parser_failures"))[:160],
          "profiles_checked=", r.get("profiles_checked"))
