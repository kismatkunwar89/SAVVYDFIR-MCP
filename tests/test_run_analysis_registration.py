"""Regression guard for the run_analysis MCP registration (P0 #6, review 2026-06-03).

The bug: ``@mcp.tool()`` was accidentally placed on the private helper
``_instrument_run_analysis`` instead of the public ``run_analysis`` tool. Direct
Python calls (``server.run_analysis(...)``) kept working — that's why the test
suite stayed green — but MCP clients lost ``mcp__savvydfir__run_analysis`` and the
private instrument helper got exposed instead. The agent then ran Pandas via Bash,
producing NO audit row and false analysis-debt.

Two layers of defense:
  1. AST guard (always runs, no fastmcp needed): the decorator must sit on
     ``run_analysis`` and must NOT sit on ``_instrument_run_analysis``.
  2. Live registration guard (runs where fastmcp is importable, e.g. the VM):
     ``run_analysis`` is in the registered tool set; ``_instrument_run_analysis``
     is not.
"""

import ast
import unittest
from pathlib import Path

SERVER_PY = Path(__file__).resolve().parent.parent / "sift_mcp" / "server.py"


def _is_mcp_tool_decorator(dec: ast.expr) -> bool:
    """True for ``@mcp.tool`` / ``@mcp.tool(...)``."""
    target = dec.func if isinstance(dec, ast.Call) else dec
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "tool"
        and isinstance(target.value, ast.Name)
        and target.value.id == "mcp"
    )


def _decorated_with_mcp_tool(tree: ast.Module, func_name: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return any(_is_mcp_tool_decorator(d) for d in node.decorator_list)
    raise AssertionError(f"function {func_name!r} not found in server.py")


class RunAnalysisDecoratorAstTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = ast.parse(SERVER_PY.read_text(encoding="utf-8"))

    def test_run_analysis_is_decorated(self) -> None:
        self.assertTrue(
            _decorated_with_mcp_tool(self.tree, "run_analysis"),
            "run_analysis MUST carry @mcp.tool() — MCP clients need "
            "mcp__savvydfir__run_analysis for PART B audit join",
        )

    def test_instrument_helper_is_not_decorated(self) -> None:
        self.assertFalse(
            _decorated_with_mcp_tool(self.tree, "_instrument_run_analysis"),
            "_instrument_run_analysis is a private helper and MUST NOT be an MCP tool",
        )


class RunAnalysisLiveRegistrationTests(unittest.TestCase):
    """Runs only where fastmcp + deps are importable (the VM)."""

    def setUp(self) -> None:
        try:
            from sift_mcp import server  # noqa: F401
        except Exception as exc:  # pragma: no cover - env-dependent
            self.skipTest(f"sift_mcp.server not importable in this env: {exc}")
        self.server = server

    def _registered_tool_names(self) -> set:
        mcp = self.server.mcp
        # FastMCP 2.x exposes a sync tool manager; tolerate API drift.
        mgr = getattr(mcp, "_tool_manager", None)
        tools = getattr(mgr, "_tools", None) if mgr is not None else None
        if isinstance(tools, dict):
            return set(tools.keys())
        get_tools = getattr(mcp, "get_tools", None)
        if get_tools is not None:
            import asyncio

            result = asyncio.run(get_tools())
            if isinstance(result, dict):
                return set(result.keys())
            return {getattr(t, "name", str(t)) for t in result}
        self.skipTest("cannot introspect FastMCP tool registry in this version")

    def test_run_analysis_registered(self) -> None:
        self.assertIn("run_analysis", self._registered_tool_names())

    def test_instrument_helper_not_registered(self) -> None:
        self.assertNotIn("_instrument_run_analysis", self._registered_tool_names())


if __name__ == "__main__":
    unittest.main()
