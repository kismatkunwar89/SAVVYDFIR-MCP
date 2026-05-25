# Contributing to SAVVYDFIR-MCP

Thanks for your interest. This project is an MCP server for DFIR investigations on
SIFT Workstation. We welcome bug reports, tool additions, detector improvements,
and dataset contributions.

## Reporting issues

Open a GitHub issue with:
- Your SIFT Workstation version (`/etc/os-release` + `dotnet --version`)
- Your Claude Code version (`claude --version`)
- The investigation `case_id`, the failing tool name, and the relevant excerpt
  from `analysis/audit.jsonl`
- If the issue affects findings: the `finding_id` and what went wrong

Do **not** include real evidence file contents, hashes from active investigations,
or any PII. Use redacted/synthesized examples.

## Pull requests

1. Fork + branch from `master`. Branch naming: `feat/<short-name>`, `fix/<short-name>`.
2. Run the full test suite: `python3 -m pytest tests/ -v`
3. Keep framework code case-agnostic — no hardcoded IPs, usernames, filenames,
   hashes, MITRE techniques, or case identifiers in `sift_mcp/`, `scripts/`,
   `CLAUDE.md`, or `.claude/agents/*.md`. Detector pattern code is the only
   exception (e.g. `T1070.006` in the timestomping detector).
4. Add a regression test for any code-path you touch.
5. Update `tool_catalog.py` if you add an MCP tool; the catalog parity test
   (`tests/test_phase6_tool_catalog.py`) will fail otherwise.
6. Sign your commits; one-line subject + descriptive body.

## Code style

- Python: PEP 8 + type hints on public functions.
- Markdown: GitHub-flavored, line-wrap at sentence boundaries (not column 80).
- No emojis in source code or framework docs unless requested.
- Tool docstrings: include a copy-paste example with `<ANGLE_BRACKET>` placeholders
  (never literal case-specific values).

## Adding a new MCP tool

1. Implement the underlying logic under `sift_mcp/tools/<namespace>.py`.
2. Add `@mcp.tool()` wrapper in `sift_mcp/server.py` with full docstring +
   audit logging pattern (see `compare_disk_and_memory` for the canonical shape).
3. Register the tool in `sift_mcp/tool_catalog.py`.
4. If the tool returns a large result set, use the `build_contract_response`
   envelope and cap inline payload by severity/level — never by arbitrary count.
5. Add unit + integration tests under `tests/`.
6. If the tool feeds the heuristic-injection layer, add the artifact mapping
   in `_HEURISTIC_ARTIFACT_FOR_TOOL` and ensure the response carries
   `applicable_heuristics`.

## Adding a new heuristic / specialist agent

1. Add `.claude/agents/<name>-analyst.md` with the canonical sections
   (Forensic Ground Rules, What to Hunt, Critical Heuristics, etc.).
2. Wire the artifact key into `scripts/extract_heuristic_slice.py`.
3. Add the artifact mapping in `sift_mcp/tools/_contracts.py`
   (`_HEURISTIC_ARTIFACT_FOR_TOOL`) so the Tier-1 injection picks it up.
4. Keep the agent SOP case-agnostic — no hardcoded examples from past
   investigations.

## License

By contributing, you agree your contributions will be licensed under the
same MIT license that covers the project (see `LICENSE`).
