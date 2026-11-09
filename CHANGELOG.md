# Changelog

## 0.3.0 — 2026-11-09

### Added — `paths` check group (MCP075–MCP077)

Models CVE-2026-103572, the first MCP-adjacent **config-write** vulnerability
with a public write-up. An agent host in Copilot for Visual Studio / SSMS
guarded writes to its own `.mcp.json` by comparing the literal path it was
about to write; the agent proposed `.mcp.json.`, the guard saw a different
string, and Windows stripped the trailing dot at write time — resolving to the
real config. The agent could then rewrite the file that decides which MCP
servers it may run.

The trailing dot is one instance of a general defect: a string comparison
standing in for a filesystem identity comparison. This release flags the whole
family, because a denylist built that way inherits every one of them:

- **MCP075** (high) — an argument reaches a protected host config
  (`.mcp.json`, `claude_desktop_config.json`, `settings.json`, …) or credential
  directory (`.ssh`, `.aws`, `.gnupg`, `.kube`, …) through a non-canonical
  spelling: trailing dot or space, case variant, `%2e` percent escape,
  NTFS `::$DATA` stream, or an 8.3 short name.
- **MCP076** (medium) — an argument names a protected config or credential path
  directly, or walks to one with `..`. Capability, not a bypass, so it does not
  read as a critical finding.
- **MCP077** (low) — an argument is not in canonical form at all.

The check inspects `args` under both `mcpServers` (every desktop host config
shape) and `servers` (array or map). It is part of the default check set, and
can be run alone with `--checks paths`.

**Deliberately offline.** Resolving a symlink requires touching the filesystem;
an auditor that does so is doing the thing it warns about. The rule reports what
is decidable from the string and says so in the finding text.

### Verified

- 119 tests pass. The 10 new path tests **fail against the unfixed
  implementation** (9 of them; the tenth is the "ordinary path stays clean"
  control, which correctly passes on both). Checked by stashing the
  implementation and re-running.
- `examples/clean-manifest.json` stays clean under the new rule — a rule that
  fires on our own fixture is a rule with a false positive.
- The README CLI example was executed and its output pasted from the run, not
  written by hand.

## 0.2.0 — 2026-11-05

- MCP074: validate MCP Server Cards (SEP-2127).
- MCP070–MCP073: spec conformance group (protocol revision, removed methods,
  deprecated capabilities, deprecated transports).
- Dual-dialect bridge: MCP071 drops to info when `server/discover` is also
  implemented.

## 0.1.0

- Initial release: identity, secrets, transport, resources, tools, prompts,
  annotations checks. SARIF output. Zero runtime dependencies.
