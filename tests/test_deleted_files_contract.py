import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sift_mcp.audit import AuditLogger
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import disk


class _FakeFlsResult:
    ok = True
    exit_code = 0
    stderr = ""
    execution_id = "E-777"
    command_line = "fls -rd /evidence/disk.E01"

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


class _FakeSleuthKitRunner:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout

    def fls(self, **kwargs):
        return _FakeFlsResult(self.stdout)


class DeletedFilesContractTests(unittest.TestCase):
    def test_list_deleted_files_summary_persists_full_output_without_full_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            state.load("CASE-DEL")
            audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
            stdout = "\n".join(
                f"r/r * {1000 + idx}-128-1: Windows/Temp/deleted-{idx}.exe"
                for idx in range(1000)
            )
            disk.init_tools(
                state,
                audit,
                sk_runner=_FakeSleuthKitRunner(stdout),
            )

            with mock.patch.dict("os.environ", {"OUTPUT_BASE": tmp_dir}, clear=False):
                result = disk.list_deleted_files(
                    image_path="/evidence/disk.E01",
                    case_id="CASE-DEL",
                    max_entries=25,
                    response_format="summary",
                )

            self.assertEqual(result["status"], "success")
            self.assertEqual(result["records_count"], 1000)
            self.assertNotIn("data", result)
            self.assertEqual(len(result["preview"]), 25)
            self.assertTrue(result["storage_path"])
            persisted = json.loads(Path(result["storage_path"]).read_text(encoding="utf-8"))
            self.assertEqual(persisted["records_count"], 1000)
            self.assertEqual(len(persisted["records"]), 1000)

    def test_list_deleted_files_detailed_returns_bounded_page(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
            state.load("CASE-DEL-PAGE")
            audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
            stdout = "\n".join(
                f"r/r * {2000 + idx}-128-1: Windows/Temp/deleted-{idx}.exe"
                for idx in range(20)
            )
            disk.init_tools(
                state,
                audit,
                sk_runner=_FakeSleuthKitRunner(stdout),
            )

            with mock.patch.dict("os.environ", {"OUTPUT_BASE": tmp_dir}, clear=False):
                result = disk.list_deleted_files(
                    image_path="/evidence/disk.E01",
                    case_id="CASE-DEL-PAGE",
                    response_format="detailed",
                    limit=5,
                    page_offset=10,
                )

            self.assertEqual(result["status"], "success")
            self.assertEqual(result["records_count"], 20)
            self.assertEqual(len(result["data"]), 5)
            self.assertEqual(result["data"][0]["file_path"], "Windows/Temp/deleted-10.exe")


if __name__ == "__main__":
    unittest.main()
