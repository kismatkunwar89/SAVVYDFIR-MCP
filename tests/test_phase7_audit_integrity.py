"""Phase 7 audit sealing, linkage, and provenance regression tests."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

from sift_mcp.audit import AuditLogger


def _import_server(tmp_dir: str):
    previous_analysis_dir = os.environ.get("SAVVYDFIR_ANALYSIS_DIR")
    previous_fastmcp = sys.modules.get("fastmcp")
    os.environ["SAVVYDFIR_ANALYSIS_DIR"] = tmp_dir

    if "fastmcp" not in sys.modules:
        class _FakeFastMCP:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def tool(self, *args, **kwargs):
                def _decorator(func):
                    return func

                return _decorator

            def resource(self, *args, **kwargs):
                def _decorator(func):
                    return func

                return _decorator

        sys.modules["fastmcp"] = types.SimpleNamespace(FastMCP=_FakeFastMCP)

    if "sift_mcp.server" in sys.modules:
        server = importlib.reload(sys.modules["sift_mcp.server"])
    else:
        server = importlib.import_module("sift_mcp.server")

    return server, previous_analysis_dir, previous_fastmcp


def _restore_server_env(previous_analysis_dir, previous_fastmcp) -> None:
    if previous_analysis_dir is None:
        os.environ.pop("SAVVYDFIR_ANALYSIS_DIR", None)
    else:
        os.environ["SAVVYDFIR_ANALYSIS_DIR"] = previous_analysis_dir

    if previous_fastmcp is None:
        sys.modules.pop("fastmcp", None)
    else:
        sys.modules["fastmcp"] = previous_fastmcp


def _base_finding(
    *,
    case_id: str,
    execution_id: str,
    tool_name: str,
    artifact_path: str,
    description: str,
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "finding_type": "other",
        "artifact_type": "disk",
        "artifact_path": artifact_path,
        "tool_name": tool_name,
        "execution_id": execution_id,
        "iteration": 1,
        "evidence_kind": "observation",
        "finding_status": "ACTIVE",
        "confidence": 0.9,
        "description": description,
        "supporting_indicators": [artifact_path],
    }


class Phase7AuditIntegrityTests(unittest.TestCase):
    def test_audit_logger_seals_new_entries_and_starts_new_segment_after_legacy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit_path = Path(tmp_dir) / "audit.jsonl"
            legacy_entry = {
                "timestamp": "2026-04-17T00:00:00.000Z",
                "execution_id": "E-001",
                "event_type": "completed",
                "tool": "legacy.tool",
                "finding_ids_generated": [],
            }
            audit_path.write_text(json.dumps(legacy_entry) + "\n", encoding="utf-8")

            audit = AuditLogger(str(audit_path))
            execution_id = audit.next_execution_id()
            started = audit.log_execution(
                execution_id=execution_id,
                tool_name="memory.scan_network",
                parameters={"dump_path": "/evidence/mem.raw"},
                command_line="vol.py windows.netscan.NetScan",
            )
            completed = audit.log_result(
                execution_id=execution_id,
                exit_code=0,
                duration=1.25,
                outputs_summary="network scan complete",
                finding_ids=[],
                tool_name="memory.scan_network",
                command_line="vol.py windows.netscan.NetScan",
                parameters={"dump_path": "/evidence/mem.raw"},
            )
            linked = audit.log_link(
                execution_id=execution_id,
                tool_name="memory.scan_network",
                finding_ids=["F-001"],
                artifact_refs=["/cases/out.csv"],
                artifact_hashes=[],
                raw_evidence_refs=[{"path": "/cases/out.csv", "role": "derived"}],
            )

            lines = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertNotIn("entry_hash", lines[0])
            self.assertEqual(started["schema_version"], 2)
            self.assertIsNone(started["prev_entry_hash"])
            self.assertEqual(completed["prev_entry_hash"], started["entry_hash"])
            self.assertEqual(linked["prev_entry_hash"], completed["entry_hash"])

    def test_server_finalizer_links_execution_and_updates_finding_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server, previous_analysis_dir, previous_fastmcp = _import_server(tmp_dir)
            try:
                case_id = "CASE-P7-LINK"
                server._state_manager.load(case_id)
                artifact = Path(tmp_dir) / "prefetch.csv"
                artifact.write_text("path,last_run\n", encoding="utf-8")

                started = server._audit_logger.log_execution(
                    execution_id="E-001",
                    tool_name="disk.extract_prefetch",
                    parameters={"image_path": "/evidence/disk.E01"},
                    command_line="pecmd --csv /cases/prefetch.csv",
                )
                completed = server._audit_logger.log_result(
                    execution_id="E-001",
                    exit_code=0,
                    duration=1.0,
                    outputs_summary="prefetch parsed",
                    finding_ids=[],
                    tool_name="disk.extract_prefetch",
                    command_line="pecmd --csv /cases/prefetch.csv",
                    parameters={"image_path": "/evidence/disk.E01"},
                )
                server._record_execution_parity(
                    execution_id="E-001",
                    tool_name="disk.extract_prefetch",
                    command_line="pecmd --csv /cases/prefetch.csv",
                    parameters={"image_path": "/evidence/disk.E01"},
                    duration_seconds=1.0,
                    exit_code=0,
                    outputs_summary="prefetch parsed",
                    started_entry=started,
                    completed_entry=completed,
                )

                finding_id = server._state_manager.add_finding(
                    _base_finding(
                        case_id=case_id,
                        execution_id="E-001",
                        tool_name="disk.extract_prefetch",
                        artifact_path=str(artifact),
                        description="Prefetch confirms execution of a suspicious binary.",
                    )
                )

                finalized = server._finalize_tool_response(
                    "disk.extract_prefetch",
                    {
                        "status": "success",
                        "execution_id": "E-001",
                        "findings_created": [finding_id],
                        "csv_path": str(artifact),
                        "raw_command": "pecmd --csv /cases/prefetch.csv",
                    },
                )

                execution = server._state_manager.get_execution("E-001")
                assert execution is not None
                self.assertTrue(execution["audit_linked_entry_hash"])
                self.assertEqual(execution["finding_ids_generated"], [finding_id])
                self.assertTrue(execution["artifact_hashes"])
                self.assertEqual(finalized["artifact_hashes"][0]["role"], "output")

                finding = server._state_manager.get_finding(finding_id)
                assert finding is not None
                self.assertTrue(finding["raw_evidence_refs"])
                self.assertIn(str(artifact.resolve()), {ref["path"] for ref in finding["raw_evidence_refs"]})

                provenance = server.get_provenance(finding_id)
                # W1.7 (CR-revised 2026-05-23): _finalize_tool_response now
                # also injects a context_bundle audit row for the 11 non-contract
                # tools that previously got nothing. Filter to the durable
                # execution-lifecycle events so this test stays stable against
                # heuristic injection presence/absence.
                lifecycle_events = [
                    e["event_type"] for e in provenance["execution_chain"]
                    if e["event_type"] in {"started", "completed", "linked"}
                ]
                self.assertEqual(lifecycle_events, ["started", "completed", "linked"])
                self.assertFalse(provenance["legacy_unsealed"])
            finally:
                _restore_server_env(previous_analysis_dir, previous_fastmcp)

    def test_get_provenance_marks_legacy_findings_unsealed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server, previous_analysis_dir, previous_fastmcp = _import_server(tmp_dir)
            try:
                case_id = "CASE-P7-LEGACY"
                server._state_manager.load(case_id)
                finding_id = server._state_manager.add_finding(
                    _base_finding(
                        case_id=case_id,
                        execution_id="E-000",
                        tool_name="legacy.migrated",
                        artifact_path="/evidence/legacy.raw",
                        description="Legacy finding without a sealed audit chain.",
                    )
                )

                provenance = server.get_provenance(finding_id)
                self.assertEqual(provenance["execution_chain"], [])
                self.assertTrue(provenance["legacy_unsealed"])
            finally:
                _restore_server_env(previous_analysis_dir, previous_fastmcp)

    def test_primary_input_hash_is_reused_from_verify_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server, previous_analysis_dir, previous_fastmcp = _import_server(tmp_dir)
            try:
                case_id = "CASE-P7-HASH"
                server._state_manager.load(case_id)
                image_path = Path(tmp_dir) / "disk.raw"
                image_path.write_bytes(b"disk-image")
                image_sha = hashlib.sha256(image_path.read_bytes()).hexdigest()

                started_1 = server._audit_logger.log_execution(
                    execution_id="E-001",
                    tool_name="evidence.verify_integrity",
                    parameters={"image_path": str(image_path)},
                    command_line="sha256sum disk.raw",
                )
                completed_1 = server._audit_logger.log_result(
                    execution_id="E-001",
                    exit_code=0,
                    duration=0.1,
                    outputs_summary="integrity verified",
                    finding_ids=[],
                    tool_name="evidence.verify_integrity",
                    command_line="sha256sum disk.raw",
                    parameters={"image_path": str(image_path)},
                )
                server._record_execution_parity(
                    execution_id="E-001",
                    tool_name="evidence.verify_integrity",
                    command_line="sha256sum disk.raw",
                    parameters={"image_path": str(image_path)},
                    duration_seconds=0.1,
                    exit_code=0,
                    outputs_summary="integrity verified",
                    started_entry=started_1,
                    completed_entry=completed_1,
                )
                verify_finding_id = server._state_manager.add_finding(
                    _base_finding(
                        case_id=case_id,
                        execution_id="E-001",
                        tool_name="evidence.verify_integrity",
                        artifact_path=str(image_path),
                        description="Image integrity verified with SHA-256.",
                    )
                )
                server._finalize_tool_response(
                    "evidence.verify_integrity",
                    {
                        "status": "success",
                        "execution_id": "E-001",
                        "findings_created": [verify_finding_id],
                        "data": [
                            {
                                "image_path": str(image_path),
                                "computed_hash": image_sha,
                                "algorithm": "sha256",
                            }
                        ],
                        "raw_command": "sha256sum disk.raw",
                    },
                )

                derived_output = Path(tmp_dir) / "timeline.csv"
                derived_output.write_text("ts,desc\n", encoding="utf-8")

                started_2 = server._audit_logger.log_execution(
                    execution_id="E-002",
                    tool_name="disk.extract_mft_timeline",
                    parameters={"image_path": str(image_path)},
                    command_line="mftecmd --csv timeline.csv",
                )
                completed_2 = server._audit_logger.log_result(
                    execution_id="E-002",
                    exit_code=0,
                    duration=0.2,
                    outputs_summary="mft parsed",
                    finding_ids=[],
                    tool_name="disk.extract_mft_timeline",
                    command_line="mftecmd --csv timeline.csv",
                    parameters={"image_path": str(image_path)},
                )
                server._record_execution_parity(
                    execution_id="E-002",
                    tool_name="disk.extract_mft_timeline",
                    command_line="mftecmd --csv timeline.csv",
                    parameters={"image_path": str(image_path)},
                    duration_seconds=0.2,
                    exit_code=0,
                    outputs_summary="mft parsed",
                    started_entry=started_2,
                    completed_entry=completed_2,
                )
                finding_id = server._state_manager.add_finding(
                    _base_finding(
                        case_id=case_id,
                        execution_id="E-002",
                        tool_name="disk.extract_mft_timeline",
                        artifact_path=str(derived_output),
                        description="MFT timeline highlights suspicious file activity.",
                    )
                )
                server._finalize_tool_response(
                    "disk.extract_mft_timeline",
                    {
                        "status": "success",
                        "execution_id": "E-002",
                        "findings_created": [finding_id],
                        "provenance": {
                            "source_path": str(image_path),
                            "csv_path": str(derived_output),
                        },
                        "raw_command": "mftecmd --csv timeline.csv",
                    },
                )

                execution = server._state_manager.get_execution("E-002")
                assert execution is not None
                self.assertTrue(
                    any(
                        item["path"] == str(image_path.resolve())
                        and item["source"] == "verify_integrity"
                        for item in execution["artifact_hashes"]
                    )
                )
                self.assertFalse(
                    any(
                        ref["path"] == str(image_path.resolve())
                        and ref.get("hash_status") == "unhashed_primary_input"
                        for ref in execution["raw_evidence_refs"]
                    )
                )
            finally:
                _restore_server_env(previous_analysis_dir, previous_fastmcp)


if __name__ == "__main__":
    unittest.main()
