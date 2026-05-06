import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from test_mcp_retrieval import _load_server_for_test
except ModuleNotFoundError:
    from tests.test_mcp_retrieval import _load_server_for_test


class LaneControlToolTests(unittest.TestCase):
    def test_start_investigation_returns_first_required_tool_calls_without_iocs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir))
            manifest = Path(tmp_dir) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "case_id": "CASE-START",
                        "mode": "blind",
                        "disk_images": ["/evidence/disk/image.E01"],
                        "memory_dumps": ["/evidence/memory/mem.raw"],
                        "known_iocs": ["192.0.2.10"],
                    }
                ),
                encoding="utf-8",
            )

            result = server.start_investigation(str(manifest))

            self.assertEqual(result["status"], "ok")
            calls = result["next_required_tools"]
            self.assertEqual(calls[0]["tool"], "environment_preflight")
            self.assertIn(
                {"tool": "mount_image", "arguments": {"image_path": "/evidence/disk/image.E01"}, "reason": "Expose disk evidence before disk artifact collection."},
                calls,
            )
            self.assertIn(
                {"tool": "load_memory", "arguments": {"dump_path": "/evidence/memory/mem.raw"}, "reason": "Load memory evidence before memory artifact collection."},
                calls,
            )
            self.assertIn("do_not_start_artifact_collection_until", result)
            self.assertNotIn("known_iocs", result)

    def test_start_investigation_warns_when_case_state_already_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir))
            server._state_manager.load("CASE-REUSE")
            server._state_manager.add_execution(
                {
                    "case_id": "CASE-REUSE",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "tool_name": "memory.list_processes",
                    "command_line": "list_processes()",
                }
            )
            manifest = Path(tmp_dir) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "case_id": "CASE-REUSE",
                        "mode": "blind",
                        "disk_images": [],
                        "memory_dumps": [],
                    }
                ),
                encoding="utf-8",
            )

            result = server.start_investigation(str(manifest))

            self.assertEqual(result["status"], "ok")
            self.assertTrue(result["existing_case_state_detected"])
            self.assertEqual(result["existing_case_counts"]["executions_count"], 1)
            self.assertIn("case_reuse_warning", result)
            self.assertIn("finding_count_accuracy_note", result)

    def test_environment_preflight_reports_dependency_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir))

            result = server.environment_preflight("CASE-LANE")

            self.assertIn(result["status"], {"ok", "warning"})
            names = {check["name"] for check in result["checks"]}
            self.assertIn("artifact_storage_writable", names)
            self.assertIn("recmd_batch:DFIRBatch.reb", names)

    def test_record_analysis_lane_rejects_unknown_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir))
            server._state_manager.load("CASE-LANE")

            result = server.record_analysis_lane(
                case_id="CASE-LANE",
                lane_id="memory",
                status="COMPLETE",
                assigned_agent="memory-analyst",
                execution_ids=["E-999"],
                finding_ids=["F-999"],
            )

            self.assertEqual(result["status"], "error")
            self.assertIn("E-999", result["missing_execution_ids"])
            self.assertIn("F-999", result["missing_finding_ids"])

    def test_record_analysis_lane_persists_valid_agent_and_gates_clear(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir))
            server._state_manager.load("CASE-LANE")
            server._state_manager.upsert_analysis_lane(
                "memory",
                status="PENDING",
                required=True,
            )
            server._state_manager.add_execution(
                {
                    "case_id": "CASE-LANE",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "tool_name": "memory.list_processes",
                    "command_line": "list_processes()",
                }
            )
            finding_id = server._state_manager.add_finding(
                {
                    "case_id": "CASE-LANE",
                    "finding_type": "other",
                    "artifact_type": "memory",
                    "artifact_path": "/evidence/memory.raw",
                    "tool_name": "memory.list_processes",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "evidence_kind": "observation",
                    "finding_status": "ACTIVE",
                    "confidence": 0.5,
                    "description": "Memory process inventory collected.",
                }
            )

            result = server.record_analysis_lane(
                case_id="CASE-LANE",
                lane_id="memory",
                status="COMPLETE",
                assigned_agent="memory-analyst",
                execution_ids=["E-001"],
                finding_ids=[finding_id],
                summary="Memory lane reviewed.",
            )

            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["lane"]["assigned_agent"], "memory-analyst")
            gates = server.get_investigation_gates("CASE-LANE")
            memory_lane = next(
                lane for lane in gates["analysis_lanes"]
                if lane["lane_id"] == "memory"
            )
            self.assertEqual(memory_lane["assigned_agent"], "memory-analyst")
            self.assertNotIn("memory", gates["missing_specialists"])

    def test_extract_windows_artifacts_writes_only_durable_raw_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir))
            image = Path(tmp_dir) / "image.E01"
            image.write_text("fake image", encoding="utf-8")

            def fake_run(args, capture_output=True, text=False, encoding=None, errors=None, timeout=None):
                class _Result:
                    def __init__(self, returncode=0, stdout=b"", stderr=b"") -> None:
                        self.returncode = returncode
                        self.stdout = stdout
                        self.stderr = stderr

                if args[0] == "fls":
                    stdout = (
                        "r/r 20454-128-3: Windows/System32/winevt/Logs/Security.evtx\n"
                        "r/r 999-128-3: Windows/System32/config/SYSTEM\n"
                        "r/r 1000-128-3: Windows/appcompat/Programs/Amcache.hve\n"
                        "r/r 1001-128-3: Windows/Prefetch/EVIL.EXE-12345678.pf\n"
                        "r/r 0-128-1: $MFT\n"
                    )
                    return _Result(stdout=stdout if text else stdout.encode())
                if args[0] == "icat":
                    return _Result(stdout=b"artifact-bytes")
                raise AssertionError(args)

            with mock.patch.object(server.subprocess, "run", side_effect=fake_run):
                with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                    result = server.extract_windows_artifacts(
                        case_id="CASE-RAW",
                        image_path=str(image),
                        families=["evtx", "registry", "amcache", "prefetch", "mft"],
                    )

            self.assertEqual(result["status"], "success")
            for key in ("evtx_dir", "registry_dir", "amcache_hive", "prefetch_dir", "mft_path"):
                self.assertIsNotNone(result[key])
                self.assertTrue(str(result[key]).startswith(str(Path(tmp_dir) / "CASE-RAW" / "artifacts" / "raw")))
                self.assertIn("/artifacts/raw/", str(result[key]).replace("\\", "/"))
            self.assertFalse(result["data_gaps"])

    def test_generate_report_surfaces_graph_missing_and_gate_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir))
            server._state_manager.load("CASE-GRAPH-GATE")
            server._state_manager.add_execution(
                {
                    "case_id": "CASE-GRAPH-GATE",
                    "execution_id": "E-001",
                    "iteration": 1,
                    "tool_name": "memory.list_processes",
                    "command_line": "list_processes()",
                }
            )
            with mock.patch.object(
                server,
                "sigma_scan",
                return_value={
                    "status": "ok",
                    "total_hits": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "summary_markdown": "No anomalies detected.",
                    "actionable_leads": [],
                    "anti_forensics_warnings": [],
                    "data_gaps": [],
                },
            ):
                with mock.patch.object(
                    server,
                    "coverage_report",
                    return_value={
                        "covered_tactics": [],
                        "uncovered_tactics": [],
                        "coverage_percent": 0.0,
                        "suggested_next_tools": {},
                    },
                ):
                    with mock.patch.dict(os.environ, {"OUTPUT_BASE": tmp_dir}, clear=False):
                        result = server.generate_report("CASE-GRAPH-GATE")

            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["next_required_tool"], "generate_graph")
            self.assertTrue(result["gate_blockers"])


if __name__ == "__main__":
    unittest.main()
