import importlib
import json
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sift_mcp.audit import AuditLogger
from sift_mcp.models.artifacts import EventRecord
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import disk as disk_tools


class _DummyFastMCP:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    def tool(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator


def _load_server_for_test(analysis_dir: Path):
    sys.modules.pop("sift_mcp.server", None)
    fake_fastmcp = types.ModuleType("fastmcp")
    fake_fastmcp.FastMCP = _DummyFastMCP
    original_env = os.environ.get("SAVVYDFIR_ANALYSIS_DIR")
    os.environ["SAVVYDFIR_ANALYSIS_DIR"] = str(analysis_dir)
    try:
        sys.modules["fastmcp"] = fake_fastmcp
        module = importlib.import_module("sift_mcp.server")
        return importlib.reload(module)
    finally:
        if original_env is None:
            os.environ.pop("SAVVYDFIR_ANALYSIS_DIR", None)
        else:
            os.environ["SAVVYDFIR_ANALYSIS_DIR"] = original_env
        sys.modules.pop("fastmcp", None)


class FinalStabilizationServerTests(unittest.TestCase):
    def test_generate_report_summary_mode_is_compact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir) / "analysis")
            server._state_manager.load("CASE-RPT")
            fake_payload = {
                "status": "ok",
                "case_id": "CASE-RPT",
                "summary": {"status": "COMPLETE", "confirmed_count": 0},
                "status_breakdown": {"ACTIVE": 2},
                "evidence_kind_breakdown": {"OBSERVATION": 2},
                "findings_count": 2,
                "unresolved_count": 1,
                "report_path": str(Path(tmp_dir) / "CASE-RPT" / "report.html"),
                "top_confirmed_findings": [],
                "top_active_leads": [
                    {
                        "finding_id": "F-001",
                        "finding_status": "ACTIVE",
                        "confidence": 0.88,
                        "tool_name": "disk.extract_registry_run_keys",
                        "description": "A" * 300,
                    }
                ],
            }
            with patch.object(server, "generate_report_payload", return_value=fake_payload):
                result = server.generate_report("CASE-RPT", response_format="summary")

            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["response_format"], "summary")
            self.assertIn("top_active_leads", result)
            self.assertNotIn("top_findings", result)
            self.assertLessEqual(len(result["top_active_leads"][0]["description"]), 160)

    def test_run_analysis_missing_temp_path_includes_persisted_handle_hint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir) / "analysis")
            result = server.run_analysis(
                "/tmp/savvydfir_evtx_dead/evtx_timeline.csv",
                "df.head()",
            )
            self.assertEqual(result["status"], "error")
            self.assertIn("persisted", result["error"].lower())
            self.assertIn("handle", result["error"].lower())

    def test_canonicalize_response_prefers_persisted_csv_handle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir) / "analysis")
            stable_path = "/cases/CASE/artifacts/evtx/evtx_timeline.csv"
            transient_path = "/tmp/savvydfir_evtx_abc/evtx_timeline.csv"
            canonical = server._canonicalize_response_artifact_paths(
                {
                    "status": "success",
                    "execution_id": "E-001",
                    "csv_path": transient_path,
                    "agent_instruction": f"Analyze {transient_path} for pivots.",
                    "provenance": {
                        "csv_path": stable_path,
                        "artifact_paths": [transient_path],
                    },
                    "handle": {"kind": "csv", "path": transient_path},
                }
            )

            self.assertEqual(canonical["csv_path"], stable_path)
            self.assertEqual(canonical["provenance"]["csv_path"], stable_path)
            self.assertEqual(canonical["handle"]["path"], stable_path)
            self.assertNotIn("/tmp/savvydfir_", canonical["agent_instruction"])

    def test_canonicalize_response_suppresses_transient_handle_when_marked_transient(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir) / "analysis")
            canonical = server._canonicalize_response_artifact_paths(
                {
                    "status": "warning",
                    "execution_id": "E-010",
                    "csv_path": "/tmp/savvydfir_prefetch_abc/prefetch.csv",
                    "handle": {"kind": "csv", "path": "/tmp/savvydfir_prefetch_abc/prefetch.csv"},
                    "artifact_persistence": {
                        "status": "transient",
                        "persisted_path": None,
                        "reason": "copy failed",
                    },
                }
            )

            self.assertIsNone(canonical.get("csv_path"))
            self.assertIsNone(canonical.get("handle"))

    def test_sigma_hunt_directory_timeout_falls_back_and_filters_hits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir) / "analysis")
            server._state_manager.load("CASE-SIGMA")

            evtx_dir = Path(tmp_dir) / "logs"
            evtx_dir.mkdir(parents=True, exist_ok=True)
            (evtx_dir / "Security.evtx").write_text("placeholder", encoding="utf-8")

            hits = [
                {
                    "name": "Credential Dump Attempt",
                    "level": "high",
                    "tags": ["attack.t1003"],
                    "event_id": 4688,
                    "system_time": "2026-04-17T00:00:00Z",
                },
                {
                    "name": "PowerShell Execution",
                    "level": "high",
                    "tags": ["attack.t1059.001"],
                    "event_id": 4104,
                    "system_time": "2026-04-17T00:10:00Z",
                },
                {
                    "name": "Informational Noise",
                    "level": "low",
                    "tags": ["attack.t1003"],
                    "event_id": 4688,
                    "system_time": "2026-04-17T00:20:00Z",
                },
            ]

            def _fake_subprocess_run(cmd, capture_output, text, timeout):
                if "--version" in cmd:
                    return server.subprocess.CompletedProcess(cmd, 0, "chainsaw 1.0", "")
                output_path = Path(cmd[cmd.index("--output") + 1])
                target = Path(cmd[2])
                if target.is_dir():
                    raise server.subprocess.TimeoutExpired(cmd, timeout)
                output_path.write_text(json.dumps(hits), encoding="utf-8")
                return server.subprocess.CompletedProcess(cmd, 0, "", "")

            with patch.object(server.subprocess, "run", side_effect=_fake_subprocess_run):
                result = server.sigma_hunt(
                    str(evtx_dir),
                    case_id="CASE-SIGMA",
                    severity="high",
                    techniques="T1003",
                    response_format="summary",
                    max_entries=10,
                )

            self.assertEqual(result["status"], "success")
            self.assertTrue(result["fallback_applied"])
            self.assertEqual(result["fallback_reason"], "directory_timeout")
            self.assertIn(str(evtx_dir / "Security.evtx"), result["fallback_targets"])
            self.assertEqual(result["hits_total"], 1)
            self.assertEqual(result["response_format"], "summary")
            self.assertNotIn("hits", result)
            self.assertEqual(result["preview"][0]["rule_name"], "Credential Dump Attempt")
            self.assertTrue(Path(result["output_path"]).exists())
            self.assertEqual(result["handle"]["query_tool"], "query_sigma_results")

    def test_query_sigma_results_filters_and_pages_without_creating_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir) / "analysis")
            sigma_path = Path(tmp_dir) / "chainsaw.json"
            sigma_path.write_text(
                json.dumps(
                    [
                        {"name": "Credential Dump Attempt", "level": "high", "tags": ["attack.t1003"]},
                        {"name": "PowerShell Execution", "level": "high", "tags": ["attack.t1059.001"]},
                        {"name": "Noise", "level": "low", "tags": ["attack.t1003"]},
                    ]
                ),
                encoding="utf-8",
            )

            summary = server.query_sigma_results(
                str(sigma_path),
                severity="high",
                techniques="T1003",
                limit=1,
                offset=0,
                response_format="summary",
            )
            detailed = server.query_sigma_results(
                str(sigma_path),
                severity="high",
                limit=2,
                offset=0,
                response_format="detailed",
            )

            self.assertEqual(summary["status"], "ok")
            self.assertEqual(summary["filtered_hits_total"], 1)
            self.assertEqual(summary["returned_count"], 1)
            self.assertNotIn("hits", summary)
            self.assertEqual(summary["handle"]["query_tool"], "query_sigma_results")
            self.assertEqual(detailed["returned_count"], 2)
            self.assertEqual(len(detailed["hits"]), 2)


class FinalStabilizationDiskTests(unittest.TestCase):
    def test_summarize_evtx_warns_when_csv_handle_is_not_durable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            audit_path = Path(tmp_dir) / "audit.jsonl"
            output_base = Path(tmp_dir) / "cases"
            state_manager = CaseStateManager(str(state_path))
            state_manager.load("CASE-EVTX")
            audit_logger = AuditLogger(str(audit_path))

            class _FakeRunner:
                def run_evtxecmd(self, *, evtx_dir, csv_dir, csv_filename, start_date, end_date, event_ids, tool_name):
                    csv_path = Path(csv_dir) / csv_filename
                    csv_path.write_text(
                        "EventId,Channel,Provider,TimeCreated,Level,Computer,UserId,Message\n"
                        "4688,Security,Microsoft-Windows-Security-Auditing,2026-04-17T00:00:00+00:00,Information,WKSTN01,S-1-5-18,Process created\n",
                        encoding="utf-8",
                    )
                    return SimpleNamespace(
                        ok=True,
                        exit_code=0,
                        stderr="",
                        execution_id="E-001",
                        command_line="EvtxECmd --csv",
                    )

            disk_tools.init_tools(
                state_manager=state_manager,
                audit_logger=audit_logger,
                ez_runner=_FakeRunner(),
                sk_runner=SimpleNamespace(),
            )

            image_root = Path(tmp_dir) / "mnt" / "disk"
            evtx_dir = image_root / "Windows" / "System32" / "winevt" / "Logs"
            evtx_dir.mkdir(parents=True, exist_ok=True)

            fake_record = EventRecord(
                event_id=4688,
                channel="Security",
                provider="Microsoft-Windows-Security-Auditing",
                timestamp=datetime.now(timezone.utc),
                level="Information",
                computer="WKSTN01",
                user_sid="S-1-5-18",
                message_summary="Process creation event.",
                extra_fields={"NewProcessName": r"C:\Windows\System32\cmd.exe"},
            )

            with patch.dict(os.environ, {"OUTPUT_BASE": str(output_base)}), \
                 patch.object(disk_tools, "_persist_csv", side_effect=lambda path, tool: path), \
                 patch.object(disk_tools, "_build_evtx_records", return_value=([fake_record], [])), \
                 patch.object(disk_tools, "promote_corroborated_findings", return_value=None):
                result = disk_tools.summarize_evtx(
                    image_path=str(image_root),
                    evtx_dir=str(evtx_dir),
                    channel="Security",
                    response_format="summary",
                )

            self.assertEqual(result["status"], "warning")
            self.assertIn("could not be persisted", result["warning"].lower())
            self.assertFalse(result.get("csv_path"))
            self.assertFalse(result.get("provenance", {}).get("csv_path"))
            self.assertIsNone(result.get("handle"))
            self.assertEqual(result["artifact_persistence"]["status"], "transient")

    def test_get_amcache_summary_mode_returns_durable_handle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            audit_path = Path(tmp_dir) / "audit.jsonl"
            output_base = Path(tmp_dir) / "cases"
            state_manager = CaseStateManager(str(state_path))
            state_manager.load("CASE-AMCACHE")
            audit_logger = AuditLogger(str(audit_path))

            class _FakeRunner:
                def run_amcacheparser(self, *, hive_path, csv_dir, csv_filename, tool_name):
                    csv_path = Path(csv_dir) / "amcache_UnassociatedFileEntries.csv"
                    csv_path.write_text(
                        "FullPath,SHA1,FileSize,Publisher\n"
                        "C:\\Users\\Bob\\AppData\\evil.exe,0123456789abcdef0123456789abcdef01234567,1234,Acme\n",
                        encoding="utf-8",
                    )
                    return SimpleNamespace(
                        ok=True,
                        exit_code=0,
                        stderr="",
                        execution_id="E-002",
                        command_line="AmcacheParser --csv",
                    )

            disk_tools.init_tools(
                state_manager=state_manager,
                audit_logger=audit_logger,
                ez_runner=_FakeRunner(),
                sk_runner=SimpleNamespace(),
            )

            image_root = Path(tmp_dir) / "mnt" / "disk"
            hive_path = image_root / "Windows" / "appcompat" / "Programs" / "Amcache.hve"
            hive_path.parent.mkdir(parents=True, exist_ok=True)
            hive_path.write_text("placeholder", encoding="utf-8")

            with patch.dict(os.environ, {"OUTPUT_BASE": str(output_base)}):
                result = disk_tools.get_amcache(
                    image_path=str(image_root),
                    hive_path=str(hive_path),
                    response_format="summary",
                )

            self.assertEqual(result["status"], "success")
            self.assertEqual(result["response_format"], "summary")
            self.assertEqual(result["artifact_persistence"]["status"], "durable")
            self.assertTrue(result["handle"]["path"].startswith(str(output_base)))
            self.assertNotIn("data", result)

    def test_extract_registry_run_keys_returns_suppressed_handle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "state.json"
            audit_path = Path(tmp_dir) / "audit.jsonl"
            output_base = Path(tmp_dir) / "cases"
            state_manager = CaseStateManager(str(state_path))
            state_manager.load("CASE-REG")
            audit_logger = AuditLogger(str(audit_path))

            class _FakeRunner:
                def run_recmd(self, *, hive_dir, csv_dir, csv_filename, batch_file, sync_batch, tool_name):
                    csv_path = Path(csv_dir) / csv_filename
                    csv_path.write_text(
                        "KeyPath,ValueName,ValueData,HiveType\n"
                        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run,Good,C:\\Windows\\System32\\calc.exe,SOFTWARE\n"
                        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run,UserDrop,C:\\Users\\Bob\\AppData\\evil.exe,SOFTWARE\n",
                        encoding="utf-8",
                    )
                    return SimpleNamespace(
                        ok=True,
                        exit_code=0,
                        stderr="",
                        execution_id="E-003",
                        command_line="RECmd --csv",
                    )

            disk_tools.init_tools(
                state_manager=state_manager,
                audit_logger=audit_logger,
                ez_runner=_FakeRunner(),
                sk_runner=SimpleNamespace(),
            )

            image_root = Path(tmp_dir) / "mnt" / "disk"
            hive_dir = image_root / "Windows" / "System32" / "config"
            hive_dir.mkdir(parents=True, exist_ok=True)

            with patch.dict(os.environ, {"OUTPUT_BASE": str(output_base)}):
                result = disk_tools.extract_registry_run_keys(
                    image_path=str(image_root),
                    hive_dir=str(hive_dir),
                    response_format="summary",
                    batch_mode=False,
                )

            self.assertEqual(result["status"], "success")
            self.assertEqual(result["artifact_persistence"]["status"], "durable")
            self.assertGreater(result["suppressed_row_count"], 0)
            self.assertTrue(result["suppressed_csv_path"].startswith(str(output_base)))
            self.assertEqual(result["suppressed_handle"]["path"], result["suppressed_csv_path"])


if __name__ == "__main__":
    unittest.main()
