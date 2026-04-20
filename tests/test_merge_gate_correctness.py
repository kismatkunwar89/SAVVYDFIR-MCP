import csv
import tempfile
import unittest
from pathlib import Path

from sift_mcp.audit import AuditLogger
from sift_mcp.models.finding import EvidenceKind, Finding, FindingStatus
from sift_mcp.state import CaseStateManager
from sift_mcp.tools import correlation


def _write_rows(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


class MergeGateCorrectnessTests(unittest.TestCase):
    def _make_case(self, tmp_dir: str, case_id: str) -> tuple[AuditLogger, CaseStateManager]:
        audit = AuditLogger(str(Path(tmp_dir) / "audit.jsonl"))
        state = CaseStateManager(str(Path(tmp_dir) / "state.json"))
        state.load(case_id)
        correlation.init_tools(audit, state)
        return audit, state

    def _add_execution(
        self,
        state: CaseStateManager,
        *,
        execution_id: str,
        tool_name: str,
        raw_evidence_refs: list[dict[str, str]],
    ) -> None:
        state.add_execution(
            {
                "execution_id": execution_id,
                "tool_name": tool_name,
                "command_line": tool_name,
                "parameters": {},
                "raw_evidence_refs": raw_evidence_refs,
            }
        )

    def _add_disk_finding(
        self,
        state: CaseStateManager,
        case_id: str,
        *,
        finding_type: str,
        description: str,
        supporting_indicators: list[str],
        tool_name: str,
        artifact_path: str = "/mnt/disk",
    ) -> str:
        finding = Finding(
            case_id=case_id,
            finding_type=finding_type,
            artifact_type="disk",
            artifact_path=artifact_path,
            tool_name=tool_name,
            execution_id="E-900",
            iteration=1,
            evidence_kind=EvidenceKind.OBSERVATION,
            finding_status=FindingStatus.ACTIVE,
            confidence=0.9,
            description=description,
            supporting_indicators=supporting_indicators,
        )
        return state.add_finding(finding.model_dump(mode="json"))

    def test_get_executions_filters_by_tool_name_in_insertion_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, state = self._make_case(tmp_dir, "CASE-EXECUTIONS")
            self._add_execution(
                state,
                execution_id="E-001",
                tool_name="disk.extract_mft_timeline",
                raw_evidence_refs=[],
            )
            self._add_execution(
                state,
                execution_id="E-002",
                tool_name="disk.get_amcache",
                raw_evidence_refs=[],
            )
            self._add_execution(
                state,
                execution_id="E-003",
                tool_name="disk.extract_mft_timeline",
                raw_evidence_refs=[],
            )

            executions = state.get_executions(tool_name="disk.extract_mft_timeline")

            self.assertEqual(
                [execution["execution_id"] for execution in executions],
                ["E-001", "E-003"],
            )

    def test_compare_disk_and_memory_ignores_transient_refs_and_uses_previous_durable_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, state = self._make_case(tmp_dir, "CASE-TRANSIENT-IGNORE")
            durable_csv = Path(tmp_dir) / "artifacts" / "mft.csv"
            _write_rows(durable_csv, [{"FileName": "/mnt/disk/Windows/subject_srv.exe"}])
            self._add_execution(
                state,
                execution_id="E-001",
                tool_name="disk.extract_mft_timeline",
                raw_evidence_refs=[{"path": str(durable_csv), "role": "derived"}],
            )
            self._add_execution(
                state,
                execution_id="E-002",
                tool_name="disk.extract_mft_timeline",
                raw_evidence_refs=[{"path": "/tmp/savvydfir_mft_latest/mft_timeline.csv", "role": "derived"}],
            )
            self._add_disk_finding(
                state,
                "CASE-TRANSIENT-IGNORE",
                finding_type="persistence",
                description="Run key points to subject_srv.exe",
                supporting_indicators=[r"value_data:C:\Windows\subject_srv.exe"],
                tool_name="disk.extract_registry_run_keys",
            )

            result = correlation.compare_disk_and_memory("CASE-TRANSIENT-IGNORE")

            discrepancy_types = {entry["discrepancy_type"] for entry in result["discrepancies"]}
            self.assertNotIn("persistence_missing_binary", discrepancy_types)

    def test_compare_disk_and_memory_prefers_latest_durable_execution_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, state = self._make_case(tmp_dir, "CASE-LATEST-DURABLE")
            old_csv = Path(tmp_dir) / "artifacts" / "mft-old.csv"
            new_csv = Path(tmp_dir) / "artifacts" / "mft-new.csv"
            _write_rows(old_csv, [{"FileName": "/mnt/disk/Windows/subject_srv.exe"}])
            _write_rows(new_csv, [{"FileName": "/mnt/disk/Windows/other.exe"}])
            self._add_execution(
                state,
                execution_id="E-001",
                tool_name="disk.extract_mft_timeline",
                raw_evidence_refs=[{"path": str(old_csv), "role": "derived"}],
            )
            self._add_execution(
                state,
                execution_id="E-002",
                tool_name="disk.extract_mft_timeline",
                raw_evidence_refs=[{"path": str(new_csv), "role": "handle"}],
            )
            self._add_disk_finding(
                state,
                "CASE-LATEST-DURABLE",
                finding_type="persistence",
                description="Run key points to subject_srv.exe",
                supporting_indicators=[r"value_data:C:\Windows\subject_srv.exe"],
                tool_name="disk.extract_registry_run_keys",
            )

            result = correlation.compare_disk_and_memory("CASE-LATEST-DURABLE")

            discrepancies = [
                entry
                for entry in result["discrepancies"]
                if entry["discrepancy_type"] == "persistence_missing_binary"
            ]
            self.assertEqual(len(discrepancies), 1)

    def test_compare_disk_and_memory_matches_case_mount_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, state = self._make_case(tmp_dir, "CASE-MOUNT-PATHS")
            durable_csv = Path(tmp_dir) / "artifacts" / "mft.csv"
            _write_rows(
                durable_csv,
                [{"FileName": "/cases/CASE-MOUNT-PATHS/evidence/mnt/C/Windows/subject_srv.exe"}],
            )
            self._add_execution(
                state,
                execution_id="E-001",
                tool_name="disk.extract_mft_timeline",
                raw_evidence_refs=[{"path": str(durable_csv), "role": "derived"}],
            )
            self._add_disk_finding(
                state,
                "CASE-MOUNT-PATHS",
                finding_type="persistence",
                description="Run key points to subject_srv.exe",
                supporting_indicators=[r"value_data:C:\Windows\subject_srv.exe"],
                tool_name="disk.extract_registry_run_keys",
            )

            result = correlation.compare_disk_and_memory("CASE-MOUNT-PATHS")

            discrepancy_types = {entry["discrepancy_type"] for entry in result["discrepancies"]}
            self.assertNotIn("persistence_missing_binary", discrepancy_types)

    def test_compare_disk_and_memory_handles_quoted_registry_command_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, state = self._make_case(tmp_dir, "CASE-QUOTED-PATH")
            durable_csv = Path(tmp_dir) / "artifacts" / "amcache.csv"
            _write_rows(durable_csv, [{"FullPath": "/mnt/disk/Windows/System32/cmd.exe"}])
            self._add_execution(
                state,
                execution_id="E-001",
                tool_name="disk.get_amcache",
                raw_evidence_refs=[{"path": str(durable_csv), "role": "handle"}],
            )
            self._add_disk_finding(
                state,
                "CASE-QUOTED-PATH",
                finding_type="persistence",
                description="Run key launches cmd.exe with arguments",
                supporting_indicators=[r'value_data:"C:\Windows\System32\cmd.exe" /c evil.bat'],
                tool_name="disk.extract_registry_run_keys",
            )

            result = correlation.compare_disk_and_memory("CASE-QUOTED-PATH")

            discrepancy_types = {entry["discrepancy_type"] for entry in result["discrepancies"]}
            self.assertNotIn("persistence_missing_binary", discrepancy_types)

    def test_compare_disk_and_memory_falls_back_to_finding_text_when_no_durable_artifacts_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            _, state = self._make_case(tmp_dir, "CASE-FINDING-FALLBACK")
            self._add_disk_finding(
                state,
                "CASE-FINDING-FALLBACK",
                finding_type="prefetch",
                description="Prefetch confirms execution of subject_srv.exe",
                supporting_indicators=[r"C:\Windows\subject_srv.exe"],
                tool_name="disk.extract_prefetch",
            )
            self._add_disk_finding(
                state,
                "CASE-FINDING-FALLBACK",
                finding_type="persistence",
                description="Run key points to subject_srv.exe",
                supporting_indicators=[r"value_data:C:\Windows\subject_srv.exe"],
                tool_name="disk.extract_registry_run_keys",
            )

            result = correlation.compare_disk_and_memory("CASE-FINDING-FALLBACK")

            self.assertEqual(result["status"], "ok")
            discrepancy_types = {entry["discrepancy_type"] for entry in result["discrepancies"]}
            self.assertNotIn("persistence_missing_binary", discrepancy_types)
