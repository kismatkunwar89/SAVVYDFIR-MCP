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


def _exists(tree: ast.Module, func_name: str) -> bool:
    return any(
        isinstance(n, ast.FunctionDef) and n.name == func_name for n in ast.walk(tree)
    )


class RunAnalysisDecoratorAstTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = ast.parse(SERVER_PY.read_text(encoding="utf-8"))

    def test_run_analysis_is_decorated(self) -> None:
        self.assertTrue(
            _decorated_with_mcp_tool(self.tree, "run_analysis"),
            "run_analysis MUST carry @mcp.tool() — MCP clients need "
            "mcp__savvydfir__run_analysis for PART B audit join",
        )

    def test_private_analysis_helpers_not_decorated(self) -> None:
        # F1 (2026-06-04): the in-process path was replaced by a memory-capped
        # subprocess worker. These private helpers must NEVER become MCP tools.
        for helper in (
            "_run_analysis_isolated",
            "_audit_analysis_started",
            "_audit_analysis_completed",
            "_instrument_run_analysis",  # legacy name; only checked if still present
        ):
            if _exists(self.tree, helper):
                self.assertFalse(
                    _decorated_with_mcp_tool(self.tree, helper),
                    f"{helper} is a private helper and MUST NOT be an MCP tool",
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
        import asyncio
        import inspect

        mcp = self.server.mcp
        # FastMCP 2.x: list_tools() is the registry accessor (may be async).
        lister = getattr(mcp, "list_tools", None) or getattr(mcp, "get_tools", None)
        if lister is None:
            self.skipTest("cannot introspect FastMCP tool registry in this version")
        result = lister()
        if inspect.isawaitable(result):
            result = asyncio.run(result)
        if isinstance(result, dict):
            return set(result.keys())
        return {getattr(t, "name", str(t)) for t in result}

    def test_run_analysis_registered(self) -> None:
        self.assertIn("run_analysis", self._registered_tool_names())

    def test_instrument_helper_not_registered(self) -> None:
        self.assertNotIn("_instrument_run_analysis", self._registered_tool_names())


if __name__ == "__main__":
    unittest.main()
