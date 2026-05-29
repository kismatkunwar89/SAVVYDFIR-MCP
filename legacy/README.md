## legacy/

Files here are deprecated and **MUST NOT** be deployed by `install.sh` or used as a live config source.

### `settings.json.deprecated-2026-05-29`
Old HOME-level Claude Code settings, written for an earlier Claude Code schema.
- Uses `"jq *"` (lowercase) which the new schema rejects.
- Has hook entries without the required `hooks: [...]` wrapper.

Replaced by the project-local `.claude/settings.json` at the repo root. Always launch
`claude` from inside the SAVVYDFIR-MCP directory so the project-local config takes effect.
