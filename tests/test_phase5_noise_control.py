"""Phase 5 noise-control tests for memory tool grouping and suppression.

Validates that scan_network and detect_injection group repeated signals
by stable entities and expose suppression_summary / grouping_context in
their contract responses.
"""

import json
import tempfile
import unittest
from pathlib import Path

from sift_mcp.audit import AuditLogger
from sift_mcp.runners.base import SafeRunner
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import memory


class FakeNetscanRunner(SafeRunner):
    """Mock runner that returns multiple ESTABLISHED connections to the same host."""

    def __init__(self, *, audit_logger, case_id, state_manager, netscan_rows=None, malfind_rows=None):
        super().__init__(
            audit_logger=audit_logger,
            case_id=case_id,
            tool_name="memory.fake",
            state_manager=state_manager,
        )
        self._netscan_rows = netscan_rows
        self._malfind_rows = malfind_rows

    def netscan(self, *, dump_path, tool_name=None, **kwargs):
        rows = self._netscan_rows or [
            # 3 connections from PID 1234 to 10.0.0.50 on registered ports (1024-49151)
            {
                "PID": 1234,
                "Owner": "malware.exe",
                "Proto": "TCPv4",
                "LocalAddr": "192.168.1.10",
                "LocalPort": 51001,
                "ForeignAddr": "10.0.0.50",
                "ForeignPort": 8443,
                "State": "ESTABLISHED",
                "Offset(P)": "0xAAAA0001",
            },
            {
                "PID": 1234,
                "Owner": "malware.exe",
                "Proto": "TCPv4",
                "LocalAddr": "192.168.1.10",
                "LocalPort": 51002,
                "ForeignAddr": "10.0.0.50",
                "ForeignPort": 9443,
                "State": "ESTABLISHED",
                "Offset(P)": "0xAAAA0002",
            },
            {
                "PID": 1234,
                "Owner": "malware.exe",
                "Proto": "TCPv4",
                "LocalAddr": "192.168.1.10",
                "LocalPort": 51003,
                "ForeignAddr": "10.0.0.50",
                "ForeignPort": 8080,
                "State": "ESTABLISHED",
                "Offset(P)": "0xAAAA0003",
            },
            # 1 connection from PID 5678 to a different host
            {
                "PID": 5678,
                "Owner": "browser.exe",
                "Proto": "TCPv4",
                "LocalAddr": "192.168.1.10",
                "LocalPort": 52001,
                "ForeignAddr": "203.0.113.5",
                "ForeignPort": 80,
                "State": "ESTABLISHED",
                "Offset(P)": "0xBBBB0001",
            },
            # 1 LISTENING connection (should NOT create a finding)
            {
                "PID": 4,
                "Owner": "System",
                "Proto": "TCPv4",
                "LocalAddr": "0.0.0.0",
                "LocalPort": 445,
                "ForeignAddr": "0.0.0.0",
                "ForeignPort": 0,
                "State": "LISTENING",
                "Offset(P)": "0xCCCC0001",
            },
        ]
        return self.run(
            ["printf", json.dumps(rows)],
            parameters={"dump_path": dump_path},
            tool_name=tool_name,
        )

    def malfind(self, *, dump_path, pid=None, tool_name=None, **kwargs):
        rows = self._malfind_rows or [
            # 3 regions in PID 4242 (svchost.exe): 1 MZ + 2 shellcode
            {
                "PID": 4242,
                "Process": "svchost.exe",
                "Start VPN": "0x1000",
                "End VPN": "0x2000",
                "Protection": "PAGE_EXECUTE_READWRITE",
                "Hexdump": "4d 5a 90 00",
                "Disassembly": "push ebp; mov ebp, esp",
            },
            {
                "PID": 4242,
                "Process": "svchost.exe",
                "Start VPN": "0x3000",
                "End VPN": "0x4000",
                "Protection": "PAGE_EXECUTE_READ",
                "Hexdump": "cc cc cc cc",
                "Disassembly": "int3; nop",
            },
            {
                "PID": 4242,
                "Process": "svchost.exe",
                "Start VPN": "0x5000",
                "End VPN": "0x6000",
                "Protection": "PAGE_EXECUTE_READWRITE",
                "Hexdump": "fc e8 82 00",
                "Disassembly": "cld; call $+0x82",
            },
            # 1 region in PID 9999 (explorer.exe)
            {
                "PID": 9999,
                "Process": "explorer.exe",
                "Start VPN": "0x7000",
                "End VPN": "0x8000",
                "Protection": "PAGE_EXECUTE_READWRITE",
                "Hexdump": "4d 5a 50 45",
                "Disassembly": "push ebp; call rax",
            },
        ]
        return self.run(
            ["printf", json.dumps(rows)],
            parameters={"dump_path": dump_path, "pid": pid},
            tool_name=tool_name,
        )

    def classify_error(self, result):
        return None


class Phase5NoiseControlTests(unittest.TestCase):
    def _make_env(self, tmp_dir, case_id):
        audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
        state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
        state.load(case_id)
        return audit, state

    # ------------------------------------------------------------------
    # scan_network grouping
    # ------------------------------------------------------------------

    def test_scan_network_groups_by_pid_ip_port_class(self):
        """3 connections from same PID to same IP on registered ports → 1 finding."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit, state = self._make_env(tmp_dir, "CASE-NET-GROUP")
            runner = FakeNetscanRunner(
                audit_logger=audit, case_id="CASE-NET-GROUP", state_manager=state,
            )
            memory.init_tools(state, audit, runner=runner)

            dump_path = str(Path(tmp_dir) / "memory.raw")
            Path(dump_path).write_text("placeholder", encoding="utf-8")

            result = memory.scan_network(dump_path=dump_path)

            self.assertEqual(result["status"], "success")
            # 5 raw rows total, 4 ESTABLISHED, 3 external
            self.assertEqual(result["connection_count"], 5)
            self.assertEqual(result["established_count"], 4)

            # Should have 2 grouped findings (one per pid+ip+port_class group)
            self.assertEqual(len(result["findings_created"]), 2)

            # suppression_summary present
            self.assertIn("suppression_summary", result)
            summary = result["suppression_summary"]
            self.assertEqual(summary["findings_emitted"], 2)
            self.assertGreater(summary["total_raw_signals"], summary["findings_emitted"])

            # grouping_context present
            self.assertIn("grouping_context", result)
            ctx = result["grouping_context"]
            self.assertEqual(ctx["strategy"], "pid_remoteip_portclass")
            self.assertEqual(ctx["groups_formed"], 2)
            self.assertEqual(result["domain_metadata"]["tool_domain"], "memory")
            self.assertIn("network", result["domain_metadata"]["artifact_families"])

    def test_scan_network_grouped_finding_has_group_key_and_support_count(self):
        """Grouped findings carry group_key and support_count in state."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit, state = self._make_env(tmp_dir, "CASE-NET-GROUP2")
            runner = FakeNetscanRunner(
                audit_logger=audit, case_id="CASE-NET-GROUP2", state_manager=state,
            )
            memory.init_tools(state, audit, runner=runner)

            dump_path = str(Path(tmp_dir) / "memory.raw")
            Path(dump_path).write_text("placeholder", encoding="utf-8")

            result = memory.scan_network(dump_path=dump_path)
            findings = state.get_findings(artifact_type="memory")

            # The PID 1234 group should have support_count=3
            pid_1234_findings = [
                f for f in findings
                if f.get("group_key", "").startswith("netscan:1234:")
            ]
            self.assertEqual(len(pid_1234_findings), 1)
            self.assertEqual(pid_1234_findings[0]["support_count"], 3)
            self.assertIn("netscan:1234:10.0.0.50:", pid_1234_findings[0]["group_key"])
            self.assertEqual(pid_1234_findings[0]["promotion_reason"], "established_external")

    def test_scan_network_rerun_is_idempotent(self):
        """Running scan_network twice produces the same findings (dedup via group_key)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit, state = self._make_env(tmp_dir, "CASE-NET-IDEMP")
            runner = FakeNetscanRunner(
                audit_logger=audit, case_id="CASE-NET-IDEMP", state_manager=state,
            )
            memory.init_tools(state, audit, runner=runner)

            dump_path = str(Path(tmp_dir) / "memory.raw")
            Path(dump_path).write_text("placeholder", encoding="utf-8")

            first = memory.scan_network(dump_path=dump_path)
            second = memory.scan_network(dump_path=dump_path)

            self.assertEqual(
                sorted(first["findings_created"]),
                sorted(second["findings_created"]),
            )
            self.assertEqual(len(state.get_findings()), 2)

    def test_scan_network_no_findings_for_listening_or_loopback(self):
        """Listening and loopback connections do not produce findings."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit, state = self._make_env(tmp_dir, "CASE-NET-LISTEN")
            rows = [
                {
                    "PID": 4,
                    "Owner": "System",
                    "Proto": "TCPv4",
                    "LocalAddr": "0.0.0.0",
                    "LocalPort": 445,
                    "ForeignAddr": "0.0.0.0",
                    "ForeignPort": 0,
                    "State": "LISTENING",
                    "Offset(P)": "0xDDDD0001",
                },
                {
                    "PID": 100,
                    "Owner": "loopback.exe",
                    "Proto": "TCPv4",
                    "LocalAddr": "127.0.0.1",
                    "LocalPort": 8080,
                    "ForeignAddr": "127.0.0.1",
                    "ForeignPort": 9090,
                    "State": "ESTABLISHED",
                    "Offset(P)": "0xEEEE0001",
                },
            ]
            runner = FakeNetscanRunner(
                audit_logger=audit, case_id="CASE-NET-LISTEN",
                state_manager=state, netscan_rows=rows,
            )
            memory.init_tools(state, audit, runner=runner)

            dump_path = str(Path(tmp_dir) / "memory.raw")
            Path(dump_path).write_text("placeholder", encoding="utf-8")

            result = memory.scan_network(dump_path=dump_path)
            self.assertEqual(result["findings_created"], [])
            self.assertEqual(result["suppression_summary"]["findings_emitted"], 0)

    # ------------------------------------------------------------------
    # detect_injection grouping
    # ------------------------------------------------------------------

    def test_detect_injection_groups_by_pid(self):
        """3 VAD regions in PID 4242 + 1 in PID 9999 → 2 findings (not 4)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit, state = self._make_env(tmp_dir, "CASE-INJ-GROUP")
            runner = FakeNetscanRunner(
                audit_logger=audit, case_id="CASE-INJ-GROUP", state_manager=state,
            )
            memory.init_tools(state, audit, runner=runner)

            dump_path = str(Path(tmp_dir) / "memory.raw")
            Path(dump_path).write_text("placeholder", encoding="utf-8")

            result = memory.detect_injection(dump_path=dump_path)

            self.assertEqual(result["status"], "success")
            self.assertEqual(result["injection_count"], 4)  # 4 raw regions
            self.assertEqual(len(result["findings_created"]), 2)  # 2 PID groups

            self.assertIn("suppression_summary", result)
            summary = result["suppression_summary"]
            self.assertEqual(summary["findings_emitted"], 2)
            self.assertEqual(summary["total_raw_signals"], 4)
            self.assertEqual(summary["signals_suppressed"], 2)  # 4 - 2

    def test_detect_injection_grouped_finding_carries_metadata(self):
        """Grouped injection finding has group_key, support_count, and mz info."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit, state = self._make_env(tmp_dir, "CASE-INJ-META")
            runner = FakeNetscanRunner(
                audit_logger=audit, case_id="CASE-INJ-META", state_manager=state,
            )
            memory.init_tools(state, audit, runner=runner)

            dump_path = str(Path(tmp_dir) / "memory.raw")
            Path(dump_path).write_text("placeholder", encoding="utf-8")

            result = memory.detect_injection(dump_path=dump_path)
            findings = state.get_findings(artifact_type="memory")

            # PID 4242 group
            pid_4242 = [f for f in findings if "4242" in (f.get("group_key") or "")]
            self.assertEqual(len(pid_4242), 1)
            f = pid_4242[0]
            self.assertEqual(f["support_count"], 3)
            self.assertEqual(f["group_key"], "malfind:4242:svchost.exe")
            self.assertEqual(f["promotion_reason"], "mz_header_present")
            self.assertEqual(f["mitre_technique"], "T1055.001")
            self.assertIn("mz_regions=1", f["supporting_indicators"])
            self.assertIn("total_regions=3", f["supporting_indicators"])

            # PID 9999 group
            pid_9999 = [f for f in findings if "9999" in (f.get("group_key") or "")]
            self.assertEqual(len(pid_9999), 1)
            self.assertEqual(pid_9999[0]["support_count"], 1)
            self.assertEqual(pid_9999[0]["promotion_reason"], "mz_header_present")

    def test_detect_injection_rerun_is_idempotent(self):
        """Running detect_injection twice deduplicates via group_key content_key."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit, state = self._make_env(tmp_dir, "CASE-INJ-IDEMP")
            runner = FakeNetscanRunner(
                audit_logger=audit, case_id="CASE-INJ-IDEMP", state_manager=state,
            )
            memory.init_tools(state, audit, runner=runner)

            dump_path = str(Path(tmp_dir) / "memory.raw")
            Path(dump_path).write_text("placeholder", encoding="utf-8")

            first = memory.detect_injection(dump_path=dump_path)
            second = memory.detect_injection(dump_path=dump_path)

            self.assertEqual(
                sorted(first["findings_created"]),
                sorted(second["findings_created"]),
            )
            self.assertEqual(len(state.get_findings()), 2)

    def test_detect_injection_contract_still_has_requires_agent(self):
        """Phase 5 grouping preserves the @memory-analyst dispatch metadata."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit, state = self._make_env(tmp_dir, "CASE-INJ-AGENT")
            runner = FakeNetscanRunner(
                audit_logger=audit, case_id="CASE-INJ-AGENT", state_manager=state,
            )
            memory.init_tools(state, audit, runner=runner)

            dump_path = str(Path(tmp_dir) / "memory.raw")
            Path(dump_path).write_text("placeholder", encoding="utf-8")

            result = memory.detect_injection(dump_path=dump_path)
            self.assertEqual(result["requires_agent"], "@memory-analyst")
            self.assertIn("grouping_context", result)
            self.assertEqual(result["domain_metadata"]["tool_domain"], "memory")

    # ------------------------------------------------------------------
    # No regression in existing contract behavior
    # ------------------------------------------------------------------

    def test_detect_injection_still_sanitizes_disassembly(self):
        """Phase 5 grouping still fences disassembly_preview in contract output."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit, state = self._make_env(tmp_dir, "CASE-INJ-SANITIZE")
            runner = FakeNetscanRunner(
                audit_logger=audit, case_id="CASE-INJ-SANITIZE", state_manager=state,
            )
            memory.init_tools(state, audit, runner=runner)

            dump_path = str(Path(tmp_dir) / "memory.raw")
            Path(dump_path).write_text("placeholder", encoding="utf-8")

            result = memory.detect_injection(dump_path=dump_path)
            for record in result["data"]:
                if record.get("disassembly_preview"):
                    self.assertTrue(
                        record["disassembly_preview"].startswith("<EVIDENCE_CONTENT>"),
                        "Disassembly should be fenced",
                    )


if __name__ == "__main__":
    unittest.main()
