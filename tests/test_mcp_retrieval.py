import importlib
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path


class _DummyFastMCP:
    def __init__(self, *args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs

    def tool(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator

    def resource(self, *args, **kwargs):
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


def _finding_payload(index: int, **overrides):
    payload = {
        "case_id": "CASE-MCP",
        "finding_type": "persistence" if index % 2 else "other",
        "artifact_type": "disk" if index % 2 else "memory",
        "artifact_path": fr"C:\Temp\artifact_{index}.exe",
        "tool_name": "disk.extract_registry_run_keys" if index % 2 else "memory.scan_processes",
        "execution_id": f"E-{index + 1:03d}",
        "iteration": 1,
        "evidence_kind": "observation",
        "finding_status": "ACTIVE" if index % 3 else "CONFIRMED",
        "confidence": 0.55 + (index / 1000.0),
        "description": f"Finding {index} provides enough descriptive detail for validation.",
        "mitre_tactic": "TA0003" if index % 2 else "TA0005",
        "mitre_technique": "T1547.001" if index % 2 else "T1055",
    }
    payload.update(overrides)
    return payload


class McpRetrievalTests(unittest.TestCase):
    def test_get_finding_returns_one_record_and_not_found_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir) / "analysis")
            server._state_manager.load("CASE-MCP")
            finding_id = server._state_manager.add_finding(_finding_payload(1))

            found = server.get_finding("CASE-MCP", finding_id)
            missing = server.get_finding("CASE-MCP", "F-999")

            self.assertEqual(found["status"], "ok")
            self.assertTrue(found["found"])
            self.assertEqual(found["finding"]["finding_id"], finding_id)

            self.assertEqual(missing["status"], "error")
            self.assertFalse(missing["found"])
            self.assertIn("not found", missing["error"].lower())

    def test_get_findings_filters_and_paginates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir) / "analysis")
            server._state_manager.load("CASE-MCP")
            for index in range(6):
                server._state_manager.add_finding(
                    _finding_payload(
                        index,
                        finding_type="observation",
                        artifact_type="disk",
                        evidence_kind="observation",
                        tool_name="test.synthetic",
                        finding_status="ACTIVE" if index < 5 else "CONFIRMED",
                        mitre_tactic="TA0003" if index < 5 else "TA0006",
                        confidence=0.70 + (index / 100.0),
                    )
                )

            result = server.get_findings(
                "CASE-MCP",
                finding_type="observation",
                artifact_type="disk",
                evidence_kind="observation",
                finding_status="ACTIVE",
                mitre_tactic="TA0003",
                min_confidence=0.72,
                limit=2,
                offset=1,
            )

            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["total_findings"], 3)
            self.assertEqual(result["limit"], 2)
            self.assertEqual(result["offset"], 1)
            self.assertEqual(result["returned_count"], 2)
            self.assertEqual(result["response_format"], "summary")
            self.assertTrue(all(f["mitre_tactic"] == "TA0003" for f in result["findings"]))
            self.assertTrue(all(float(f["confidence"]) >= 0.72 for f in result["findings"]))
            self.assertTrue(all("artifact_path" not in f for f in result["findings"]))

    def test_get_findings_detailed_mode_preserves_raw_hit_only_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir) / "analysis")
            server._state_manager.load("CASE-MCP")
            finding = _finding_payload(
                0,
                finding_type="threat_detection",
                raw_hit={"rule": "sigma_test", "level": "high"},
            )

            original = server._state_manager.get_findings

            def _fake_get_findings(**kwargs):
                self.assertEqual(kwargs.get("finding_type"), "threat_detection")
                return [dict(finding)]

            server._state_manager.get_findings = _fake_get_findings  # type: ignore[assignment]
            try:
                trimmed = server.get_findings(
                    "CASE-MCP",
                    finding_type="threat_detection",
                    response_format="detailed",
                )
                expanded = server.get_findings(
                    "CASE-MCP",
                    finding_type="threat_detection",
                    response_format="detailed",
                    include_raw_hit=True,
                )
            finally:
                server._state_manager.get_findings = original  # type: ignore[assignment]

            self.assertEqual(trimmed["status"], "ok")
            self.assertNotIn("raw_hit", trimmed["findings"][0])
            self.assertEqual(expanded["findings"][0]["raw_hit"]["rule"], "sigma_test")

    def test_get_findings_enforces_limit_cap_and_offset_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            server = _load_server_for_test(Path(tmp_dir) / "analysis")
            server._state_manager.load("CASE-MCP")
            for index in range(205):
                server._state_manager.add_finding(_finding_payload(index))

            capped = server.get_findings("CASE-MCP", limit=500)
            invalid_offset = server.get_findings("CASE-MCP", offset=-1)

            self.assertEqual(capped["status"], "ok")
            self.assertEqual(capped["limit"], 200)
            self.assertEqual(capped["returned_count"], 200)
            self.assertEqual(capped["total_findings"], 205)

            self.assertEqual(invalid_offset["status"], "error")
            self.assertIn("offset", invalid_offset["error"].lower())


if __name__ == "__main__":
    unittest.main()
