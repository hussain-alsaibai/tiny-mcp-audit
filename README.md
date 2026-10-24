# tiny-mcp-audit

> **Static security audit for MCP server manifests.**  
> Catch risky declarations before a client ever connects. No network access, no sandbox, no dependencies.

[![Python](https://img.shields.io/pypi/pyversions/tiny-mcp-audit.svg)](https://pypi.org/project/tiny-mcp-audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-82%20passed-brightgreen.svg)](#)

## Why?

Public MCP servers are multiplying faster than anyone can review them. A
recent census of **15,465 indexed public MCP servers** found expired domains,
unsigned manifests, and no systematic vetting layer anywhere in the stack.

The manifest is the only artifact an agent reads *before* deciding to trust a
server. That makes it the cheapest and highest-leverage place to catch problems
- and nobody is checking it.

```bash
# you point an agent at a server...
agent connect --mcp-config ./server.json

# ...and this is what actually got reviewed before you ran it
mcp-audit ./server.json
```

## Install

```bash
pip install tiny-mcp-audit
```

Zero runtime dependencies. Pure Python 3.9+.

## Quick start

```python
from tiny_mcp_audit import audit_file

report = audit_file("server.json")

print(report.summary())
for f in report.sorted_findings():
    print(f)
    if f.remediation:
        print("   fix:", f.remediation)

assert not report.has_blocking   # CI gate
```

## CLI

```bash
mcp-audit manifest.json                       # human-readable text
mcp-audit manifest.json --format json         # machine-readable
mcp-audit manifest.json --format sarif        # GitHub code scanning
mcp-audit *.json --fail-on critical           # only block on the worst
mcp-audit manifest.json --checks tools,secrets # run a subset
mcp-audit manifest.json --checks protocol       # spec conformance only
```

Exit codes: `0` clean - `1` findings at or above `--fail-on` (default `high`) - `2` usage error - `3` unreadable manifest.

## What it checks

| Code | Severity | Check |
|------|----------|-------|
| MCP001 | medium | `serverInfo` missing or malformed |
| MCP002 | medium/high | version missing, or floating (`latest`, `master`, `edge`) |
| MCP003 | low | empty server description |
| MCP004 | low | no capabilities declared |
| MCP010 | **critical** | literal credential committed to the manifest |
| MCP011 | high | sensitive env var forwarded wholesale |
| MCP020 | high | plaintext `http://` endpoint |
| MCP021 | high | plaintext `ws://` transport |
| MCP030 | high | resource exposes host filesystem |
| MCP031 | **critical** | resource targets `~/.ssh`, `~/.aws`, `/etc/shadow`, `/proc/self/environ` |
| MCP032 | low | non-standard resource URI scheme |
| MCP040 | medium | duplicate tool name |
| MCP041 | high | command-exec / exfil-shaped tool name |
| MCP042 | medium | tool description missing or too short |
| MCP043 | high | tool declares no input schema |
| MCP044 | medium | tool accepts no inputs |
| MCP050 | high | prompt template contains instruction-override language |
| MCP051 | low | prompt has no description |
| MCP060 | low | tool missing `readOnlyHint` / `destructiveHint` |
| MCP061 | low | `readOnlyHint` present but not boolean |
| MCP070 | high | protocol version missing, malformed, or older than the current revision |
| MCP071 | high | server still exposes a method the current revision removed |
| MCP072 | medium | server advertises a deprecated capability (roots / sampling / logging) |
| MCP073 | medium | server advertises a deprecated transport (HTTP+SSE) |

### Protocol conformance (`protocol`)

The `protocol` check group verifies a manifest against the **current MCP
specification revision** (`2026-07-28`). The 2026-07-28 revision removed the
`initialize` handshake entirely, made MCP stateless, and made `server/discover`
mandatory. Servers still speaking the old dialect are invisible to modern
clients — they negotiate a revision nobody offers.

| Check | What it catches |
|---|---|
| MCP070 | No `protocolVersion`, a non-date version like `1.0`, or a revision older than current |
| MCP071 | `initialize`, `ping`, `logging/setLevel`, `resources/subscribe` and other removed methods still advertised |
| MCP072 | `roots`, `sampling`, `logging` capabilities advertised |
| MCP073 | The deprecated HTTP+SSE transport |

```bash
# Diagnose a server that modern clients cannot reach
mcp-audit server.json --checks protocol
```

The revision is looked up in `protocolVersion`, `protocol_version`,
`specVersion`, `discover.protocolVersions`, and
`_meta.io.modelcontextprotocol/protocolVersion`, so it works against both a
raw manifest and a captured `server/discover` response.

## Design notes

**Secrets are never echoed.** When MCP010 fires, the finding carries only the
matched *shape* (`"pattern": "GitHub token"`, plus the byte offset). The
credential itself never enters the report, so logs and CI annotations are safe
to publish.

**Placeholder-aware.** `sk-your-key-here`, `ghp_xxx...`, `${'$'}{VAR}`, `REDACTED`, and
friends are recognised as documentation tokens and not reported. Docs and test
fixtures stay green.

**Segment-aware tool matching.** `runCommand` becomes `["run", "command"],
`shell.exec` becomes `["shell", "exec"]`. So `runCommand` is flagged but
`execute_report` is not.

**Undocumented risky tools escalate.** A tool named `delete_all` with no
description gets one severity level worse: an agent cannot reason about blast
radius it was never told about.

**Never raises.** Bad JSON, a list where an object was expected, a missing
file - all produce a report with `audited=False` and an error, never a traceback.

## Severity, score, grade

```python
report.grade          # A..F
report.score          # 0-100, weighted by severity
report.max_severity   # worst finding, or None
report.has_blocking   # True at HIGH or worse
report.count(Severity.CRITICAL)
```

## Use in CI

```yaml
- name: Audit MCP manifests
  run: |
    mcp-audit ./manifests/*.json --fail-on high --format sarif > mcp-audit.sarif
```

## Programmatic use

```python
from tiny_mcp_audit import audit_manifest, audit_many, Severity

report = audit_manifest(manifest, checks=["secrets", "tools"])
if report.count(Severity.CRITICAL):
    notify_security(report.to_json())

results = audit_many(["a.json", "b.json"])
risky = {p: r for p, r in results.items() if r.has_blocking}
```

## Try it

```bash
mcp-audit examples/clean-manifest.json   # grade A, exit 0
mcp-audit examples/risky-manifest.json   # many findings, exit 1
```

## Relationship to the tiny-* family

Pairs with [tiny-validator](https://github.com/hussain-alsaibai/tiny-validator)
- validate the *shape* of a tool input, then audit the *whole manifest* for
risk. Both are zero-dependency single-file libraries.

## License

MIT
