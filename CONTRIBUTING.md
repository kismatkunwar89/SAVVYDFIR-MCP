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
3. Keep framework code case-agnostic - no hardcoded IPs, usernames, filenames,
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
   envelope and cap inline payload by severity/level - never by arbitrary count.
5. Add unit + integration tests under `tests/`.
6. If the tool feeds the heuristic-injection layer, add the artifact mapping
   in `_HEURISTIC_ARTIFACT_FOR_TOOL` and ensure the response carries
   `applicable_heuristics`.

   **Exception - FK-only tools.** Not every tool feeds the heuristic-injection
   layer. Tools whose forensic guidance is delivered purely via the
   `_forensic_envelope` (in-house `forensic-knowledge` YAMLs) - e.g.
   the user-activity extractors `extract_shellbags`, `extract_lnk_files`,
   `extract_jump_lists`, `extract_browser_history`,
   `extract_registry_fileaccess` - intentionally do NOT carry an
   `applicable_heuristics` slice and have NO `*-analyst.md` knowledge base. For
   these, add the tool->artifact mapping in `server.py:_FK_MAP` and vendor a
   `does_not_prove` + `corroborate_with` YAML under
   `data/forensic-knowledge/artifacts/<platform>/`. Do NOT add them to
   `_HEURISTIC_ARTIFACT_FOR_TOOL`.

## Adding a new heuristic / specialist agent

1. Add `.claude/agents/<name>-analyst.md` with the canonical sections
   (Forensic Ground Rules, What to Hunt, Critical Heuristics, etc.).
2. Wire the artifact key into `scripts/extract_heuristic_slice.py`.
3. Add the artifact mapping in `sift_mcp/tools/_contracts.py`
   (`_HEURISTIC_ARTIFACT_FOR_TOOL`) so the Tier-1 injection picks it up.
4. Keep the agent SOP case-agnostic - no hardcoded examples from past
   investigations.

## Adding or editing forensic-knowledge YAML

The `data/forensic-knowledge/artifacts/` YAMLs supply the runtime forensic envelope
(`forensic_caveat` / `corroborate_with` / `discipline_reminder`) injected into mapped tool
responses. Two namespaces are in use:

- `windows/` - real Windows **OS artifacts** (MFT, Prefetch, Amcache, registry, SRUM, …).
- `analysis_outputs/` - **analysis-tool outputs** not tied to one analyzed OS (e.g. Sigma/Hayabusa
  EVTX alerts, Volatility memory). `linux/` and `macos/` are reserved in the loader search list for
  future real Linux/macOS OS artifacts.

Loading is **registry-driven, not directory auto-discovery**: a brand-new artifact needs an entry in
`server.py:_FK_MAP` (tool -> artifact name) **in addition to** the YAML file; editing an
**already-mapped** YAML needs no code. Either way the server loads YAML at startup, so **restart the
MCP server** to pick up changes. Keep YAML case-agnostic (no case-specific IPs, names, or hashes) and
follow the field shape of an existing file such as
`data/forensic-knowledge/artifacts/windows/mft.yaml`.

Only **8** artifacts carry an inline `applicable_heuristics` slice (mft, evtx, prefetch, amcache,
registry, srum, sigma, memory - see `scripts/extract_heuristic_slice.py:ARTIFACT_FILE_MAP`). FK YAML
guidance is independent of that slice; an artifact can have an FK YAML without a `*-analyst.md` KB.

## Contributing evaluation cases

Accuracy is measured by `python3 scripts/eval/gt_match_scorer.py <ground_truth>.yaml <report.json>`,
which scores a committed `report.json` / `state.json` against a hand-authored answer key on
distinctive anchors - **no live evidence image required**; it is deterministic and CI-friendly. To
add a case:

1. Author the answer key at `scripts/eval/ground_truth/<CASE>.yaml` (cite the source document; state
   limitations; do **not** commit licensed/courseware text that cannot be redistributed).
2. Commit a finalized `report.json` fixture, and optionally a baseline snapshot under
   `scripts/eval/baselines/`.
3. The scorer must run clean - do **not** stuff distinctive tokens into findings to inflate recall.

## Extending detection routing

- ATT&CK routing lives in `sift_mcp/routing/attack_routing.yaml`
  (`technique_id -> {name, tactics, required_artifacts, corroboration_sources}`); guarded by
  `tests/test_attack_routing.py` - every `required_artifacts` entry must be a valid MCP tool name.
- Chainsaw/Sigma rule mapping lives in `rules/chainsaw-sigma-mapping.yml` (vendored from
  WithSecureLabs/chainsaw, GPL-3.0); guarded by `tests/test_sigma_mapping_regression.py`. Run that
  test after any mapping edit - a silent mapping no-op previously caused 0 rules to match.

## License

By contributing, you agree your contributions will be licensed under the
same MIT license that covers the project (see `LICENSE`).
