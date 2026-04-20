"""Phase 6 tests for authoritative tool-domain catalog metadata."""

from __future__ import annotations

import ast
import importlib
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

from sift_mcp.tool_catalog import (
    ALLOWED_ARTIFACT_FAMILIES,
    ALLOWED_RESULT_KINDS,
    ALLOWED_TOOL_DOMAINS,
    TOOL_CATALOG,
    iter_catalog_entries,
    validate_tool_catalog,
)


_SERVER_PATH = Path(__file__).resolve().parents[1] / "sift_mcp" / "server.py"


def _server_mcp_tool_names() -> list[str]:
    module = ast.parse(_SERVER_PATH.read_text(encoding="utf-8"))
    tool_names: list[str] = []
    for node in module.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and getattr(getattr(decorator, "func", None), "attr", None) == "tool":
                tool_names.append(node.name)
                break
    return tool_names


class Phase6ToolCatalogTests(unittest.TestCase):
    def test_catalog_covers_every_server_exposed_tool(self) -> None:
        issues = validate_tool_catalog(_server_mcp_tool_names())
        self.assertEqual(issues, [])

    def test_catalog_entries_use_allowed_domain_metadata(self) -> None:
        seen_tool_names: set[str] = set()
        for entry in iter_catalog_entries():
            self.assertNotIn(entry.tool_name, seen_tool_names)
            seen_tool_names.add(entry.tool_name)
            self.assertIn(entry.tool_domain, ALLOWED_TOOL_DOMAINS)
            self.assertIn(entry.result_kind, ALLOWED_RESULT_KINDS)
            self.assertTrue(entry.artifact_families)
            for artifact_family in entry.artifact_families:
                self.assertIn(artifact_family, ALLOWED_ARTIFACT_FAMILIES)

        self.assertEqual(len(TOOL_CATALOG), len(_server_mcp_tool_names()))

    def test_describe_tool_catalog_groups_and_filters(self) -> None:
        previous_analysis_dir = os.environ.get("SAVVYDFIR_ANALYSIS_DIR")
        previous_fastmcp = sys.modules.get("fastmcp")
        with tempfile.TemporaryDirectory() as tmp_dir:
            os.environ["SAVVYDFIR_ANALYSIS_DIR"] = tmp_dir
            if "fastmcp" not in sys.modules:
                class _FakeFastMCP:
                    def __init__(self, *args, **kwargs) -> None:
                        pass

                    def tool(self, *args, **kwargs):
                        def _decorator(func):
                            return func

                        return _decorator

                sys.modules["fastmcp"] = types.SimpleNamespace(FastMCP=_FakeFastMCP)
            if "sift_mcp.server" in sys.modules:
                server = importlib.reload(sys.modules["sift_mcp.server"])
            else:
                server = importlib.import_module("sift_mcp.server")

            all_result = server.describe_tool_catalog()
            self.assertEqual(all_result["status"], "ok")
            self.assertIn("disk", all_result["catalog"])
            self.assertIn("memory", all_result["catalog"])
            self.assertGreaterEqual(all_result["tool_count"], len(TOOL_CATALOG))

            memory_only = server.describe_tool_catalog(domain="memory")
            self.assertEqual(memory_only["status"], "ok")
            self.assertEqual(set(memory_only["catalog"].keys()), {"memory"})
            self.assertEqual(
                memory_only["tool_count"],
                len([entry for entry in TOOL_CATALOG.values() if entry.tool_domain == "memory"]),
            )
            self.assertTrue(
                all(item["tool_domain"] == "memory" for item in memory_only["catalog"]["memory"])
            )

        if previous_analysis_dir is None:
            os.environ.pop("SAVVYDFIR_ANALYSIS_DIR", None)
        else:
            os.environ["SAVVYDFIR_ANALYSIS_DIR"] = previous_analysis_dir
        if previous_fastmcp is None:
            sys.modules.pop("fastmcp", None)
        else:
            sys.modules["fastmcp"] = previous_fastmcp


if __name__ == "__main__":
    unittest.main()
