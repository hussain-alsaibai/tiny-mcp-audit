"""tiny_mcp_audit — zero-dependency static security audit for MCP manifests.

Why this exists
---------------
Public MCP servers have multiplied far faster than review capacity. A recent
census of 15,465 indexed public servers found expired domains, unsigned
manifests, and no systematic vetting layer. A manifest is the only artifact an
agent reads *before* deciding to trust a server, so it is the cheapest and
highest-leverage place to catch problems.

tiny_mcp_audit statically inspects MCP server manifests (the JSON emitted at
`initialize`, plus common config shapes) and flags risky declarations *before*
a client connects. No network access, no import of server code, no sandbox
required.

Usage::

    from tiny_mcp_audit import audit_manifest

    report = audit_manifest(manifest)
    if report.has_blocking:
        for f in report.sorted_findings():
            print(f)
    print(report.summary())

CLI::

    python -m tiny_mcp_audit manifest.json
    mcp-audit manifest.json --format sarif
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Iterable, Mapping


__version__ = "0.2.0"


# ---------- Severity ----------


class Severity(str, Enum):
    """Finding severity, ordered most to least urgent."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_BY_RANK = {v: k for k, v in _SEVERITY_RANK.items()}


# ---------- Findings ----------


@dataclass
class Finding:
    """A single audit result."""

    code: str
    severity: Severity
    message: str
    location: str = ""
    remediation: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self):
        out = asdict(self)
        out["severity"] = self.severity.value
        return out

    def __str__(self):
        where = " @ " + self.location if self.location else ""
        return "[" + self.severity.value.upper() + "] " + self.code + where + ": " + self.message


# ---------- Heuristic data ----------

# Command-execution and exfiltration-adjacent words in tool names. Matched
# against whole word segments so "exec" matches "shell.exec" and
# "runCommand" but NOT "execute_report".
RISKY_TOOL_NAME_PATTERNS = (
    ("exec", "tool name implies arbitrary command execution", Severity.HIGH),
    ("shell", "tool name implies shell access", Severity.HIGH),
    ("bash", "tool name implies shell access", Severity.HIGH),
    ("eval", "tool name implies dynamic evaluation", Severity.HIGH),
    ("spawn", "tool name implies process spawning", Severity.HIGH),
    ("command", "tool name implies command execution", Severity.MEDIUM),
    ("fetch", "tool name implies outbound network fetch", Severity.MEDIUM),
    ("upload", "tool name implies outbound data transfer", Severity.MEDIUM),
    ("download", "tool name implies outbound network fetch", Severity.LOW),
    ("write", "tool name implies filesystem write", Severity.MEDIUM),
    ("delete", "tool name implies destructive filesystem op", Severity.MEDIUM),
    ("sql", "tool name implies database access", Severity.LOW),
    ("env", "tool name may expose environment secrets", Severity.MEDIUM),
)

# Literal secret shapes. Kept deliberately narrow to limit false positives
# against example and test fixtures.
SECRET_PATTERNS = (
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe live key", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b")),
    ("OpenAI/Anthropic key", re.compile(r"\bsk-(?:ant-)?(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "JSON web token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    ("bearer token assignment", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}")),
)

# Markers that make a secret-looking string harmless in documentation.
SECRET_PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]?|example|placeholder|redacted|x{4,}|dummy|fake"
    r"|<[^>]*>|\$\{|\{\{|\.\.\.|changeme|none|null|insert|test)"
)

# Version strings that mean "whatever is newest" rather than a pinned build.
UNPINNED_VERSION_RE = re.compile(
    r"(?i)^(latest|\*|x|any|master|main|head|stable|edge|nightly|dev|canary)$"
)

DANGEROUS_ENV_VARS = frozenset(
    [
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "SLACK_BOT_TOKEN",
        "SLACK_TOKEN",
        "STRIPE_SECRET_KEY",
        "DATABASE_URL",
        "POSTGRES_PASSWORD",
        "REDIS_PASSWORD",
        "GCP_SERVICE_ACCOUNT_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "NPM_TOKEN",
        "DOCKER_PASSWORD",
        "KUBECONFIG",
        "SSH_PRIVATE_KEY",
    ]
)

FILESYSTEM_URI_SCHEMES = ("file://", "fs://", "local://")
NETWORK_URI_SCHEMES = ("http://", "https://", "ws://", "wss://")
SENSITIVE_PATH_RE = re.compile(
    r"(?i)/\.ssh|/\.aws|/\.env|/\.git/config|/etc/passwd|/etc/shadow|/proc/self/environ"
)
LOOPBACK_RE = re.compile(r"(?i)localhost|127\.0\.0\.1|\[::1\]")

# A well-formed "scheme://" URI with a non-http(s)/file/ws scheme is a
# legitimate custom resource namespace, not a finding.
CUSTOM_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://[^/]")

OVERRIDE_LANGUAGE_RE = re.compile(
    r"(?i)ignore (all |any )?(previous|prior|above) (instructions|prompts)"
    r"|disregard (the )?(system|previous)"
    r"|you are now (a|an|in) [a-z ]{0,30}mode"
)


def _is_placeholder(value):
    """True when a secret-looking string is clearly a doc/example token."""
    return bool(SECRET_PLACEHOLDER_RE.search(value))


# ---------- Manifest shape helpers ----------


def _iter_tools(manifest):
    tools = manifest.get("tools")
    if isinstance(tools, list):
        for t in tools:
            if isinstance(t, Mapping):
                name = t.get("name")
                yield (str(name) if name is not None else "<unnamed>", t)


def _iter_resources(manifest):
    resources = manifest.get("resources")
    if isinstance(resources, list):
        for r in resources:
            if isinstance(r, Mapping):
                uri = r.get("uri") or r.get("url") or ""
                yield (str(uri), r)


def _iter_prompts(manifest):
    prompts = manifest.get("prompts")
    if isinstance(prompts, list):
        for p in prompts:
            if isinstance(p, Mapping):
                name = p.get("name")
                yield (str(name) if name is not None else "<unnamed>", p)


def _walk_strings(obj, path=""):
    """Yield every (dotted_path, string_value) pair in a nested structure."""
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            child = path + "." + str(k) if path else str(k)
            for item in _walk_strings(v, child):
                yield item
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            for item in _walk_strings(v, path + "[" + str(i) + "]"):
                yield item
    elif isinstance(obj, str):
        yield path, obj


def _tool_segments(name):
    """Split a tool name into lowercase word segments.

    "shell.exec" -> ["shell", "exec"], "runCommand" -> ["run", "command"].
    """
    segments = []
    for token in re.split(r"[^A-Za-z0-9]+", name):
        if not token:
            continue
        for piece in re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z]*|[a-z]+|[0-9]+", token):
            segments.append(piece.lower())
    return segments


# ---------- Report ----------


@dataclass
class AuditReport:
    """Aggregated findings for one manifest."""

    findings: list = field(default_factory=list)
    server_name: str = ""
    audited: bool = True
    error: str = ""

    def __bool__(self):
        """True when the manifest produced no findings."""
        return not self.findings

    def __len__(self):
        return len(self.findings)

    def __iter__(self):
        return iter(self.findings)

    @property
    def max_severity(self):
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    @property
    def has_blocking(self):
        """True when a finding is HIGH or worse - the default CI gate."""
        return any(f.severity.rank >= Severity.HIGH.rank for f in self.findings)

    @property
    def score(self):
        """0-100 posture score. Heavier findings cost more."""
        penalty = sum(f.severity.rank * 8 for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self):
        s = self.score
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 40:
            return "D"
        return "F"

    def count(self, severity):
        return sum(1 for f in self.findings if f.severity is severity)

    def find(self, code):
        return [f for f in self.findings if f.code == code]

    @property
    def codes(self):
        return sorted({f.code for f in self.findings})

    def add(self, code, severity, message, location="", remediation="", evidence=None):
        self.findings.append(
            Finding(
                code=code,
                severity=severity,
                message=message,
                location=location,
                remediation=remediation,
                evidence=dict(evidence or {}),
            )
        )

    def sorted_findings(self):
        """Findings ordered by severity desc, then code, for stable output."""
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.code, f.location))

    def summary(self):
        """One-line summary suitable for logs and registry listings."""
        if not self.audited:
            return "audit failed: " + self.error
        if not self.findings:
            return (self.server_name or "manifest") + ": clean (grade A)"
        worst = self.max_severity
        return (
            (self.server_name or "manifest")
            + ": "
            + str(len(self.findings))
            + " finding(s), worst="
            + (worst.value if worst else "none")
            + ", grade="
            + self.grade
        )

    def to_dict(self):
        return {
            "tool": "tiny-mcp-audit",
            "version": __version__,
            "server_name": self.server_name,
            "score": self.score,
            "grade": self.grade,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "error": self.error,
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent)

    def to_sarif(self):
        """SARIF 2.1.0 for GitHub code-scanning and CI annotations."""
        level_for = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        rules = {}
        results = []
        for f in self.sorted_findings():
            if f.code not in rules:
                rules[f.code] = {
                    "id": f.code,
                    "shortDescription": {"text": f.message},
                    "fullDescription": {"text": f.remediation or f.message},
                    "properties": {"severity": f.severity.value},
                }
            results.append(
                {
                    "ruleId": f.code,
                    "level": level_for[f.severity],
                    "message": {"text": f.message},
                }
            )
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "tiny-mcp-audit",
                            "version": __version__,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }


# ---------- Rules ----------


def _check_identity(report, manifest):
    """MCP001-MCP004: server identity and provenance."""
    info = manifest.get("serverInfo") or manifest.get("server")
    if not isinstance(info, Mapping):
        report.add(
            "MCP001",
            Severity.MEDIUM,
            "manifest has no serverInfo block",
            remediation="Declare serverInfo with name and version so clients can pin what they connect to.",
        )
        return

    name = info.get("name")
    if isinstance(name, str):
        report.server_name = name
    else:
        report.add(
            "MCP001",
            Severity.MEDIUM,
            "serverInfo.name is missing or not a string",
            location="serverInfo.name",
            remediation="Set serverInfo.name to a stable identifier.",
        )

    version = info.get("version")
    if not isinstance(version, str) or not version:
        report.add(
            "MCP002",
            Severity.MEDIUM,
            "serverInfo.version is missing - clients cannot pin or track builds",
            location="serverInfo.version",
            remediation="Set an explicit semantic version.",
        )
    elif UNPINNED_VERSION_RE.match(version.strip()):
        report.add(
            "MCP002",
            Severity.HIGH,
            "serverInfo.version is floating (" + repr(version) + ") - supply chain drift risk",
            location="serverInfo.version",
            remediation="Pin an immutable version such as 1.4.2, not 'latest'.",
            evidence={"version": version},
        )

    if not str(info.get("description") or "").strip():
        report.add(
            "MCP003",
            Severity.LOW,
            "serverInfo.description is empty",
            location="serverInfo.description",
            remediation="Describe what the server does; agents use this to pick tools.",
        )

    if not manifest.get("capabilities") and not info.get("capabilities"):
        report.add(
            "MCP004",
            Severity.LOW,
            "manifest declares no capabilities",
            location="capabilities",
            remediation="Declare capabilities so clients know what the server exposes.",
        )


def _check_secrets(report, manifest):
    """MCP010-MCP011: literal credentials committed into a manifest."""
    for path, value in _walk_strings(manifest):
        if _is_placeholder(value):
            continue
        for label, pattern in SECRET_PATTERNS:
            match = pattern.search(value)
            if not match:
                continue
            # Never echo the credential itself, only the matched shape.
            report.add(
                "MCP010",
                Severity.CRITICAL,
                "literal " + label + " present in manifest",
                location=path,
                remediation="Remove the value and reference an env var or secret store instead.",
                evidence={"pattern": label, "offset": match.start()},
            )
            break

    declared = manifest.get("env") or manifest.get("environment")
    if isinstance(declared, Mapping):
        for var in sorted(DANGEROUS_ENV_VARS):
            if var in declared:
                report.add(
                    "MCP011",
                    Severity.HIGH,
                    "manifest forwards sensitive env var " + var,
                    location="env." + var,
                    remediation="Scope down the env allowlist; prefer per-request short-lived tokens.",
                    evidence={"var": var},
                )


def _check_transport(report, manifest):
    """MCP020-MCP021: plaintext transport exposure."""
    # Collect transport URLs first so a URL under transports[] is reported
    # once, as a transport finding, rather than twice (generic + specific).
    transport_urls = set()
    for transport in manifest.get("transports") or []:
        if isinstance(transport, Mapping):
            url = str(transport.get("url") or "")
            if url:
                transport_urls.add(url)

    for transport in manifest.get("transports") or []:
        if not isinstance(transport, Mapping):
            continue
        url = str(transport.get("url") or "")
        kind = str(transport.get("type") or "?")
        if url.lower().startswith("http://") and not LOOPBACK_RE.search(url):
            report.add(
                "MCP020",
                Severity.HIGH,
                "transport " + kind + " uses plaintext http",
                location="transports." + kind,
                remediation="Serve MCP over https or stdio.",
                evidence={"url": url[:120]},
            )

    for path, url in _walk_strings(manifest):
        low = url.lower()
        if low.startswith("http://") and not LOOPBACK_RE.search(url) and url not in transport_urls:
            report.add(
                "MCP020",
                Severity.HIGH,
                "plaintext http:// endpoint in manifest",
                location=path,
                remediation="Use https://, or bind to loopback only.",
                evidence={"url": url[:120]},
            )

    for transport in manifest.get("transports") or []:
        if not isinstance(transport, Mapping):
            continue
        kind = str(transport.get("type") or "").lower()
        url = str(transport.get("url") or "")
        if kind in ("ws", "websocket") and url.lower().startswith("ws://"):
            report.add(
                "MCP021",
                Severity.HIGH,
                "websocket transport " + kind + " uses plaintext ws",
                location="transports." + kind,
                remediation="Use wss://.",
                evidence={"url": url[:120]},
            )


def _check_resources(report, manifest):
    """MCP030-MCP032: resource URIs reaching outside the sandbox."""
    for uri, res in _iter_resources(manifest):
        low = uri.lower()
        if SENSITIVE_PATH_RE.search(low):
            report.add(
                "MCP031",
                Severity.CRITICAL,
                "resource URI targets a sensitive host path: " + uri,
                location="resources." + uri,
                remediation="Remove this resource; it reads credential material.",
                evidence={"uri": uri},
            )
        elif low.startswith(FILESYSTEM_URI_SCHEMES):
            report.add(
                "MCP030",
                Severity.HIGH,
                "resource exposes host filesystem: " + uri,
                location="resources." + uri,
                remediation="Serve files from a scoped directory, not the host root.",
                evidence={"uri": uri, "name": res.get("name")},
            )
        elif (
            not low.startswith(FILESYSTEM_URI_SCHEMES)
            and not low.startswith(NETWORK_URI_SCHEMES)
            and not CUSTOM_SCHEME_RE.match(low)
        ):
            report.add(
                "MCP032",
                Severity.LOW,
                "resource uses an unrecognised URI scheme: " + uri,
                location="resources." + uri,
                remediation="Confirm the scheme is documented and sandbox-aware.",
            )


def _check_tools(report, manifest):
    """MCP040-MCP044: tool surface risk and schema quality."""
    names = set()
    for name, tool in _iter_tools(manifest):
        if name in names:
            report.add(
                "MCP040",
                Severity.MEDIUM,
                "duplicate tool name " + repr(name),
                location="tools." + name,
                remediation="Tool names must be unique; agents resolve tools by name.",
            )
        names.add(name)

        segments = set(_tool_segments(name))
        description = str(tool.get("description") or "")
        described = len(description.strip()) >= 20

        risky = None
        for needle, why, sev in RISKY_TOOL_NAME_PATTERNS:
            if needle in segments:
                risky = (needle, why, sev)
                break

        if risky is not None:
            needle, why, sev = risky
            # A powerful tool with no description is worse: the agent cannot
            # reason about blast radius, so escalate one level.
            if not described and sev.rank < Severity.CRITICAL.rank:
                sev = _BY_RANK[sev.rank + 1]
                why = why + " and it is undocumented"
            report.add(
                "MCP041",
                sev,
                "tool " + repr(name) + " " + why,
                location="tools." + name,
                remediation=(
                    "Document expected inputs and blast radius, and require explicit "
                    "human approval for invocation."
                ),
                evidence={"name": name, "segment": needle},
            )

        if not described:
            report.add(
                "MCP042",
                Severity.MEDIUM,
                "tool " + repr(name) + " has a missing or too-short description",
                location="tools." + name,
                remediation=(
                    "Describe what the tool does, its side effects, and whether it is "
                    "read-only. Agents choose tools from these strings alone."
                ),
                evidence={"name": name},
            )

        input_schema = tool.get("inputSchema") or tool.get("input_schema")
        if input_schema is None:
            report.add(
                "MCP043",
                Severity.HIGH,
                "tool " + repr(name) + " declares no input schema",
                location="tools." + name,
                remediation="Add inputSchema so callers cannot pass arbitrary arguments.",
            )
        elif isinstance(input_schema, Mapping):
            props = input_schema.get("properties")
            if props is None:
                report.add(
                    "MCP043",
                    Severity.MEDIUM,
                    "tool " + repr(name) + " inputSchema has no properties",
                    location="tools." + name + ".inputSchema",
                    remediation="Declare properties explicitly.",
                )
            elif isinstance(props, Mapping) and not props:
                report.add(
                    "MCP044",
                    Severity.MEDIUM,
                    "tool " + repr(name) + " accepts no inputs - confirm this is intended",
                    location="tools." + name + ".inputSchema",
                    remediation="No-op tools are usually a leftover; remove or scope it.",
                )


def _check_prompts(report, manifest):
    """MCP050-MCP051: prompt-injection surface."""
    for name, prompt in _iter_prompts(manifest):
        for path, value in _walk_strings(prompt, "prompts." + name):
            if OVERRIDE_LANGUAGE_RE.search(value):
                report.add(
                    "MCP050",
                    Severity.HIGH,
                    "prompt " + repr(name) + " contains instruction-override language",
                    location=path,
                    remediation="Strip override phrasing from published prompt templates.",
                    evidence={"prompt": name},
                )
        if not str(prompt.get("description") or "").strip():
            report.add(
                "MCP051",
                Severity.LOW,
                "prompt " + repr(name) + " has no description",
                location="prompts." + name,
                remediation="Describe when an agent should select this prompt.",
            )


def _check_annotations(report, manifest):
    """MCP060-MCP061: annotation hygiene across all tools."""
    for name, tool in _iter_tools(manifest):
        ann = tool.get("annotations")
        if not isinstance(ann, Mapping):
            report.add(
                "MCP060",
                Severity.LOW,
                "tool " + repr(name) + " has no annotations (readOnlyHint/destructiveHint)",
                location="tools." + name + ".annotations",
                remediation="Set annotations so hosts can gate risky tools automatically.",
            )
            continue
        if not isinstance(ann.get("readOnlyHint"), bool):
            report.add(
                "MCP061",
                Severity.LOW,
                "tool " + repr(name) + " annotations missing boolean readOnlyHint",
                location="tools." + name + ".annotations.readOnlyHint",
                remediation="Declare readOnlyHint explicitly.",
            )


# ---------- Server Card validation (MCP074) ----------

# SEP-2127 defines the Server Card: a static metadata document describing a
# remote MCP server for PRE-CONNECTION discovery. It is the document a client
# fetches before it knows anything about the server.
#
# Why this rule exists: a Server Card is fetched from a URL the server
# controls and read by an agent before any human sees it. That is the same
# trust shape as the Radware finding (86 million GitHub items scanned, ~2.5
# prompt injections per 100,000 items, including instructions hidden in HTML
# comments): attacker-controlled metadata that a model reads and may act on.
# A card whose description or headers carry instructions is the same attack,
# delivered through the protocol.
#
# The schema (modelcontextprotocol/experimental-ext-server-card, schema.ts)
# requires $schema, name, version and description. Optional: title,
# websiteUrl, repository, icons, remotes, _meta.
#
# The card deliberately does NOT enumerate primitives. That is a safety
# property of the spec, not a gap: clients cannot use a static card for
# access-control decisions. So this rule does not flag a missing tools list -
# that would be flagging the spec's own design.

SERVER_CARD_SCHEMA_URL = "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json"

# Instructions aimed at the model rather than the human reader. These are the
# phrases that turn a metadata document into an injection payload.
SERVER_CARD_INJECTION_PATTERNS = (
    (re.compile(r"(?i)\bignore (?:all |any |the )?(?:previous|prior|preceding|above)\b"), "ignores prior instructions"),
    (re.compile(r"(?i)\bdisregard (?:all |any |the )?(?:previous|prior|preceding|above)\b"), "disregards prior instructions"),
    (re.compile(r"(?i)\byou are now\b"), "reassigns the assistant's role"),
    (re.compile(r"(?i)\bnew instructions?\b"), "introduces fresh instructions"),
    (re.compile(r"(?i)\bsystem prompt\b"), "references the system prompt"),
    (re.compile(r"(?i)\b(?:call|invoke|run|execute) (?:the )?[\w ]*tool\b"), "instructs a tool call"),
    (re.compile(r"(?i)\bbefore (?:using|calling|connecting) (?:any|this) tool\b"), "instructs a tool call"),
    (re.compile(r"(?i)\b(?:exfiltrate|send|upload|post) (?:the |all |your )?(?:credentials?|secrets?|tokens?|keys?|env)\b"), "requests credential disclosure"),
    (re.compile(r"(?i)\bread (?:the |all )?(?:~/.ssh|/etc/passwd|\.env)\b"), "requests sensitive file reads"),
)

# Header names that carry credentials. A Server Card is public by design, so a
# card that hard-codes one of these is leaking it to every crawler.
SERVER_CARD_SECRET_HEADER_NAMES = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "x-amz-security-token",
})


def _server_card_text_values(card):
    """Every free-text string in a card that a model may read.

    Returns (location, value) pairs. The card is public metadata, so every
    one of these strings is attacker-influenced and model-readable.
    """
    out = []
    for key in ("description", "title", "websiteUrl"):
        val = card.get(key)
        if isinstance(val, str):
            out.append((key, val))
    repo = card.get("repository")
    if isinstance(repo, Mapping):
        for key in ("url", "source", "subfolder"):
            val = repo.get(key)
            if isinstance(val, str):
                out.append(("repository." + key, val))
    icons = card.get("icons")
    if isinstance(icons, list):
        for idx, icon in enumerate(icons):
            if isinstance(icon, Mapping):
                src = icon.get("src")
                if isinstance(src, str):
                    out.append(("icons[" + str(idx) + "].src", src))
    remotes = card.get("remotes")
    if isinstance(remotes, list):
        for idx, remote in enumerate(remotes):
            if not isinstance(remote, Mapping):
                continue
            url = remote.get("url")
            if isinstance(url, str):
                out.append(("remotes[" + str(idx) + "].url", url))
            variables = remote.get("variables")
            if isinstance(variables, Mapping):
                for vname, spec in variables.items():
                    if not isinstance(spec, Mapping):
                        continue
                    for field in ("description", "default", "placeholder", "value"):
                        val = spec.get(field)
                        if isinstance(val, str):
                            out.append((
                                "remotes[" + str(idx) + "].variables." + str(vname) + "." + field,
                                val,
                            ))
            headers = remote.get("headers")
            if isinstance(headers, list):
                for hidx, header in enumerate(headers):
                    if not isinstance(header, Mapping):
                        continue
                    hname = header.get("name")
                    if isinstance(hname, str):
                        out.append((
                            "remotes[" + str(idx) + "].headers[" + str(hidx) + "].name",
                            hname,
                        ))
                    for field in ("value", "description"):
                        hval = header.get(field)
                        if isinstance(hval, str):
                            out.append((
                                "remotes[" + str(idx) + "].headers[" + str(hidx) + "]." + field,
                                hval,
                            ))
    meta = card.get("_meta")
    if isinstance(meta, Mapping):
        for mkey, mval in meta.items():
            if isinstance(mval, str):
                out.append(("_meta." + str(mkey), mval))
    return out


def _check_server_card(report, manifest):
    """MCP074: validate an MCP Server Card document (SEP-2127)."""
    card = manifest.get("serverCard")
    if card is None:
        card = manifest.get("server_card")
    if card is None:
        return
    if not isinstance(card, Mapping):
        report.add(
            "MCP074",
            Severity.HIGH,
            "serverCard must be a JSON object, got " + type(card).__name__,
            location="serverCard",
            remediation="Make serverCard an object conforming to the Server Card schema.",
        )
        return

    # -- required fields --------------------------------------------------
    schema = card.get("$schema")
    if not isinstance(schema, str) or not schema.strip():
        report.add(
            "MCP074",
            Severity.MEDIUM,
            "Server Card is missing $schema",
            location="serverCard.$schema",
            remediation="Set $schema to " + SERVER_CARD_SCHEMA_URL,
        )
    elif schema != SERVER_CARD_SCHEMA_URL:
        report.add(
            "MCP074",
            Severity.LOW,
            "Server Card $schema is not the v1 schema URL",
            location="serverCard.$schema",
            remediation="Use " + SERVER_CARD_SCHEMA_URL,
            evidence={"found": schema[:200]},
        )

    name = card.get("name")
    if not isinstance(name, str) or not name.strip():
        report.add(
            "MCP074",
            Severity.MEDIUM,
            "Server Card is missing name",
            location="serverCard.name",
            remediation="Set name to a reverse-DNS identifier, e.g. 'acme/weather'.",
        )
    elif name.count("/") != 1:
        report.add(
            "MCP074",
            Severity.LOW,
            "Server Card name is not in reverse-DNS form (namespace/server)",
            location="serverCard.name",
            remediation="Use exactly one forward slash: 'namespace/server'.",
            evidence={"found": name[:200]},
        )

    version = card.get("version")
    if not isinstance(version, str) or not version.strip():
        report.add(
            "MCP074",
            Severity.LOW,
            "Server Card is missing version",
            location="serverCard.version",
            remediation="Set version to a semver string such as '1.0.2'.",
        )
    elif re.search(r"[\^~]|>=|\*", version):
        report.add(
            "MCP074",
            Severity.MEDIUM,
            "Server Card version is a range, not a version",
            location="serverCard.version",
            remediation="Server Cards declare a concrete version; ranges are rejected.",
            evidence={"found": version[:120]},
        )

    description = card.get("description")
    if not isinstance(description, str) or not description.strip():
        report.add(
            "MCP074",
            Severity.LOW,
            "Server Card is missing description",
            location="serverCard.description",
            remediation="Describe what the server does, in one line.",
        )

    # -- prompt injection in model-readable text ---------------------------
    for location, value in _server_card_text_values(card):
        for pattern, why in SERVER_CARD_INJECTION_PATTERNS:
            if pattern.search(value):
                report.add(
                    "MCP074",
                    Severity.CRITICAL,
                    "Server Card text contains embedded instructions (" + why + ")",
                    location="serverCard." + location,
                    remediation=(
                        "A Server Card is public metadata read by agents before any human "
                        "review. Remove the instruction-like text; describe capabilities only."
                    ),
                    evidence={"matched": pattern.pattern},
                )
                break

    # -- credentials in headers ---------------------------------------------
    remotes = card.get("remotes")
    if isinstance(remotes, list):
        for idx, remote in enumerate(remotes):
            if not isinstance(remote, Mapping):
                continue
            headers = remote.get("headers")
            if not isinstance(headers, list):
                continue
            for hidx, header in enumerate(headers):
                if not isinstance(header, Mapping):
                    continue
                hname = header.get("name")
                if not isinstance(hname, str):
                    continue
                loc = "serverCard.remotes[" + str(idx) + "].headers[" + str(hidx) + "]"
                value = header.get("value")
                if hname.strip().lower() in SERVER_CARD_SECRET_HEADER_NAMES:
                    if isinstance(value, str) and value.strip():
                        # A value in a public card is a leak, whatever else is set.
                        report.add(
                            "MCP074",
                            Severity.CRITICAL,
                            "Server Card hard-codes a credential header '" + hname + "'",
                            location=loc,
                            remediation=(
                                "Server Cards are public by design. Move the credential to a "
                                "variable with isSecret, and let the client supply it."
                            ),
                            evidence={"header": hname},
                        )
                    elif not header.get("isSecret"):
                        # No value and no isSecret: the header name is published
                        # and the client is not told to prompt for it. Flag it
                        # so the author adds isSecret.
                        report.add(
                            "MCP074",
                            Severity.MEDIUM,
                            "Server Card declares credential header '" + hname + "' without a value",
                            location=loc,
                            remediation=(
                                "Declare it as a variable with isSecret so the client prompts "
                                "for it, rather than shipping the header name."
                            ),
                            evidence={"header": hname},
                        )
                    # No value and isSecret set: the documented way to ask for a
                    # credential without publishing it. Not a finding.
                elif isinstance(value, str):
                    if any(rx.search(value) for _label, rx in SECRET_PATTERNS):
                        report.add(
                            "MCP074",
                            Severity.CRITICAL,
                            "Server Card header '" + hname + "' contains a literal secret",
                            location=loc,
                            remediation="Use a variable with isSecret instead of a literal value.",
                            evidence={"header": hname},
                        )


# ---------- Protocol conformance (MCP spec 2026-07-28) ----------

# The current specification revision. Date-based, not semver: the spec
# moved to YYYY-MM-DD revisions with the 2025-11-25 revision, and
# 2026-07-28 removed the initialize handshake entirely.
CURRENT_SPEC_REVISION = "2026-07-28"

# The revision that introduced the date-based scheme. Anything before this
# cannot be expressed as a date revision, so it predates the scheme.
FIRST_DATE_REVISION = "2025-11-25"

# Methods that the 2026-07-28 revision removed. A server that still
# advertises or implements these is speaking a pre-2026 dialect.
REMOVED_METHODS = {
    "initialize": "the initialize handshake was removed; MCP is now stateless",
    "notifications/initialized": "the initialized notification was removed",
    "logging/setLevel": "log level is now set per-request via _meta",
    "ping": "ping was removed as a core method",
    "notifications/roots/list_changed": "the Roots feature is deprecated",
    "roots/list": "the Roots feature is deprecated",
    "sampling/createMessage": "the Sampling feature is deprecated",
    "notifications/message": "the Logging feature is deprecated",
    "resources/subscribe": "replaced by subscriptions/listen",
    "resources/unsubscribe": "replaced by subscriptions/listen",
    "tasks/result": "moved to the io.modelcontextprotocol/tasks extension",
    "tasks/list": "moved to the io.modelcontextprotocol/tasks extension",
    "notifications/elicitation/complete": "removed in favour of the MRTR retry pattern",
}

# Capabilities whose underlying features are deprecated. Advertising them
# is not an error, but it signals a server built against an older spec.
DEPRECATED_CAPABILITIES = {
    "roots": "the Roots feature is deprecated (SEP-2577)",
    "sampling": "the Sampling feature is deprecated (SEP-2577)",
    "logging": "the Logging feature is deprecated (SEP-2577)",
}

# Transports the spec has deprecated. HTTP+SSE was deprecated as early as
# protocol version 2025-03-26 and is reclassified as Deprecated under the
# feature lifecycle policy (SEP-2596).
DEPRECATED_TRANSPORTS = {
    "sse": "the HTTP+SSE transport is deprecated; migrate to Streamable HTTP",
    "http+sse": "the HTTP+SSE transport is deprecated; migrate to Streamable HTTP",
}

# A protocol revision string is a date: YYYY-MM-DD.
_REVISION_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")

# Pre-date-revision version strings that some servers still advertise.
LEGACY_PROTOCOL_VERSIONS = {
    "1.0",
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
}


def _parse_revision(value):
    """Parse a date-shaped spec revision into a comparable tuple.

    Returns None when the string is not a YYYY-MM-DD revision.
    """
    if not isinstance(value, str):
        return None
    match = _REVISION_RE.match(value.strip())
    if not match:
        return None
    year, month, day = (int(part) for part in match.groups())
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return None
    return (year, month, day)


def _revision_is_older(revision, minimum):
    """True when revision parses and sorts before minimum."""
    parsed = _parse_revision(revision)
    floor = _parse_revision(minimum)
    if parsed is None or floor is None:
        return False
    return parsed < floor


def _find_protocol_version(manifest):
    """Locate the declared protocol version in a manifest, if any.

    Returns (value, location). The location is the dotted path the value
    was found at, or "" when nothing was found.
    """
    candidates = (
        ("protocolVersion", manifest.get("protocolVersion")),
        ("protocol_version", manifest.get("protocol_version")),
        ("specVersion", manifest.get("specVersion")),
    )
    for key, value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip(), key
    # The discover response nests the supported versions.
    discover = manifest.get("discover") or manifest.get("server/discover")
    if isinstance(discover, Mapping):
        for key in ("protocolVersion", "protocol_version", "specVersion"):
            value = discover.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip(), "discover." + key
        versions = discover.get("protocolVersions") or discover.get(
            "supportedProtocolVersions"
        )
        if isinstance(versions, list) and versions:
            first = versions[0]
            if isinstance(first, str) and first.strip():
                return first.strip(), "discover.protocolVersions[0]"
    meta = manifest.get("_meta")
    if isinstance(meta, Mapping):
        value = meta.get("io.modelcontextprotocol/protocolVersion")
        if isinstance(value, str) and value.strip():
            return value.strip(), "_meta.io.modelcontextprotocol/protocolVersion"
    return "", ""


def _implements_discover(manifest):
    """True when the server implements server/discover.

    The 2026-07-28 revision made this RPC mandatory. A server that
    implements it can serve current clients; one that does not is
    unreachable to them.
    """
    for key in ("methods", "implementedMethods", "advertisedMethods"):
        collection = manifest.get(key)
        if isinstance(collection, (list, tuple)) and "server/discover" in collection:
            return True
    discover = manifest.get("discover") or manifest.get("server/discover")
    return isinstance(discover, Mapping)


def _check_protocol(report, manifest):
    """MCP070-MCP073: conformance with the current MCP spec revision.

    Covers the four failure modes that make a server invisible to
    modern clients:

    - MCP070: the declared protocol version is missing, malformed, or
      older than the current revision.
    - MCP071: the server still implements or advertises a method that
      the current revision removed.
    - MCP072: the server advertises a deprecated capability.
    - MCP073: the server advertises a deprecated transport.
    """
    version, location = _find_protocol_version(manifest)

    if not version:
        report.add(
            "MCP070",
            Severity.HIGH,
            "manifest declares no protocol version - current clients cannot "
            "select a compatible revision",
            location="protocolVersion",
            remediation=(
                "Declare protocolVersion as a date revision (currently "
                + CURRENT_SPEC_REVISION
                + ") and implement server/discover."
            ),
        )
    elif _parse_revision(version) is None:
        if version in LEGACY_PROTOCOL_VERSIONS:
            report.add(
                "MCP070",
                Severity.HIGH,
                "protocol version " + repr(version) + " predates the date-based "
                "revision scheme - modern clients will not negotiate it",
                location=location,
                remediation=(
                    "Move to the date-based revision scheme and declare "
                    + CURRENT_SPEC_REVISION
                    + "."
                ),
                evidence={"version": version},
            )
        else:
            report.add(
                "MCP070",
                Severity.MEDIUM,
                "protocol version " + repr(version) + " is not a YYYY-MM-DD revision",
                location=location,
                remediation=(
                    "Protocol revisions are dates. Use "
                    + CURRENT_SPEC_REVISION
                    + " or a later revision."
                ),
                evidence={"version": version},
            )
    elif _revision_is_older(version, CURRENT_SPEC_REVISION):
        report.add(
            "MCP070",
            Severity.HIGH,
            "protocol version " + repr(version) + " is older than the current "
            "revision " + CURRENT_SPEC_REVISION,
            location=location,
            remediation=(
                "Upgrade to "
                + CURRENT_SPEC_REVISION
                + ": the initialize handshake is gone and server/discover is required."
            ),
            evidence={"version": version, "current": CURRENT_SPEC_REVISION},
        )

    # MCP071: removed methods still implemented or advertised.
    implemented = manifest.get("methods") or manifest.get("implementedMethods")
    advertised = manifest.get("advertisedMethods")
    removed_seen = {}
    for source, collection in (
        ("methods", implemented),
        ("advertisedMethods", advertised),
    ):
        if not isinstance(collection, (list, tuple)):
            continue
        for method in collection:
            if not isinstance(method, str):
                continue
            if method in REMOVED_METHODS:
                removed_seen.setdefault(method, source)
    # A legacy "initialize" advertised in capabilities implies the
    # handshake even when there is no explicit methods list.
    if "initialize" not in removed_seen:
        caps = manifest.get("capabilities")
        if isinstance(caps, Mapping) and "initialize" in caps:
            removed_seen["initialize"] = "capabilities"

    # A server that also implements server/discover is a dual-dialect
    # bridge: it keeps the legacy handler as a compatibility shim so
    # older clients still connect. A live probe of 79 registry servers
    # found every current-dialect server did exactly this, and none
    # removed initialize. Keeping it is the recommended pattern, so it
    # is informational rather than a finding.
    is_bridge = _implements_discover(manifest)

    for method, source in sorted(removed_seen.items()):
        if is_bridge:
            report.add(
                "MCP071",
                Severity.INFO,
                "server keeps removed method " + repr(method) + " as a "
                "backwards-compatible shim (server/discover is also implemented)",
                location=source,
                remediation=(
                    "This is the recommended dual-dialect bridge. Keep it until "
                    "legacy clients are no longer a concern."
                ),
                evidence={"method": method, "source": source, "bridge": True},
            )
            continue
        report.add(
            "MCP071",
            Severity.HIGH,
            "server still exposes removed method " + repr(method) + " - "
            + REMOVED_METHODS[method],
            location=source,
            remediation=(
                "Implement server/discover plus the stateless request shape "
                "(protocol version in _meta). Without server/discover no "
                "current client can negotiate with this server."
            ),
            evidence={"method": method, "source": source, "bridge": False},
        )

    # MCP072: deprecated capabilities.
    caps = manifest.get("capabilities")
    if isinstance(caps, Mapping):
        for capability, why in sorted(DEPRECATED_CAPABILITIES.items()):
            if capability in caps:
                report.add(
                    "MCP072",
                    Severity.MEDIUM,
                    "capability " + repr(capability) + " is deprecated - " + why,
                    location="capabilities." + capability,
                    remediation=(
                        "Do not advertise deprecated features in new implementations. "
                        "Pass directories or files as tool parameters instead."
                    ),
                    evidence={"capability": capability},
                )

    # MCP073: deprecated transports.
    for transport in manifest.get("transports") or []:
        if not isinstance(transport, Mapping):
            continue
        kind = str(transport.get("type") or "").strip().lower()
        if kind in DEPRECATED_TRANSPORTS:
            report.add(
                "MCP073",
                Severity.MEDIUM,
                "transport " + repr(kind) + " is deprecated - "
                + DEPRECATED_TRANSPORTS[kind],
                location="transports." + kind,
                remediation="Serve this server over Streamable HTTP or stdio.",
                evidence={"transport": kind},
            )
    transport_type = manifest.get("transport") or manifest.get("transportType")
    if isinstance(transport_type, str):
        low = transport_type.strip().lower()
        if low in DEPRECATED_TRANSPORTS and not any(
            isinstance(t, Mapping)
            and str(t.get("type") or "").strip().lower() == low
            for t in (manifest.get("transports") or [])
        ):
            report.add(
                "MCP073",
                Severity.MEDIUM,
                "transport " + repr(low) + " is deprecated - " + DEPRECATED_TRANSPORTS[low],
                location="transport",
                remediation="Serve this server over Streamable HTTP or stdio.",
                evidence={"transport": low},
            )


# ---------- Public API ----------

CHECK_NAMES = frozenset(
    [
        "identity",
        "secrets",
        "transport",
        "resources",
        "tools",
        "prompts",
        "annotations",
        "protocol",
        "server_card",
    ]
)

_RUNNERS = {
    "identity": _check_identity,
    "secrets": _check_secrets,
    "transport": _check_transport,
    "resources": _check_resources,
    "tools": _check_tools,
    "prompts": _check_prompts,
    "annotations": _check_annotations,
    "protocol": _check_protocol,
    "server_card": _check_server_card,
}


def audit_manifest(manifest, checks=None):
    """Statically audit a decoded MCP manifest.

    Args:
        manifest: Decoded manifest mapping, optionally with "tools",
            "resources", "prompts", "transports", "env", "capabilities" keys.
        checks: Optional subset of check names drawn from CHECK_NAMES.
            Defaults to running all checks.

    Returns:
        An AuditReport. Never raises for malformed input; unusable input
        yields a report with audited=False and an error message.
    """
    report = AuditReport()
    if not isinstance(manifest, Mapping):
        report.audited = False
        report.error = "manifest must be a JSON object, got " + type(manifest).__name__
        report.add(
            "MCP000",
            Severity.CRITICAL,
            report.error,
            remediation="Pass a decoded JSON object.",
        )
        return report

    enabled = set(CHECK_NAMES) if checks is None else {str(c).strip().lower() for c in checks}
    unknown = enabled - CHECK_NAMES
    if unknown:
        report.audited = False
        report.error = "unknown check(s): " + repr(sorted(unknown))
        report.add("MCP000", Severity.CRITICAL, report.error)
        return report

    for name in sorted(enabled):
        _RUNNERS[name](report, manifest)
    return report


def audit_json(source):
    """Audit a manifest given as a JSON string."""
    try:
        decoded = json.loads(source)
    except ValueError as exc:
        report = AuditReport(audited=False, error="invalid JSON: " + str(exc))
        report.add("MCP000", Severity.CRITICAL, report.error, remediation="Fix the JSON syntax.")
        return report
    return audit_manifest(decoded)


def audit_file(path, checks=None):
    """Audit a manifest file on disk."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            source = fh.read()
    except OSError as exc:
        report = AuditReport(audited=False, error="cannot read " + path + ": " + str(exc))
        report.add("MCP000", Severity.CRITICAL, report.error)
        return report
    if checks is None:
        return audit_json(source)
    return audit_manifest(json.loads(source), checks=checks)


def audit_many(paths, checks=None):
    """Audit several manifests, returning a dict keyed by path."""
    return {p: audit_file(p, checks=checks) for p in paths}


__all__ = [
    "AuditReport",
    "CHECK_NAMES",
    "CURRENT_SPEC_REVISION",
    "REMOVED_METHODS",
    "DEPRECATED_CAPABILITIES",
    "DEPRECATED_TRANSPORTS",
    "Finding",
    "Severity",
    "audit_file",
    "audit_json",
    "audit_manifest",
    "audit_many",
    "__version__",
]


# ---------- CLI ----------

USAGE = """usage: mcp-audit [options] MANIFEST [MANIFEST ...]

Statically audit MCP server manifests for risky declarations.

options:
  --format {text,json,sarif}   output format (default: text)
  --checks LIST                comma-separated checks to run
  --fail-on LEVEL              exit 1 at or above this severity
                               (critical, high, medium, low, info, never)
  --quiet                      only print the one-line summary
  -h, --help                   show this message

checks: identity, secrets, transport, resources, tools, prompts, annotations, protocol
"""


def main(argv=None):
    """CLI entry point. Returns a process exit code."""
    argv = list(sys.argv[1:] if argv is None else argv)

    fmt = "text"
    checks = None
    fail_on = Severity.HIGH
    quiet = False
    paths = []

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            sys.stdout.write(USAGE)
            return 0
        if arg == "--format":
            i += 1
            if i >= len(argv):
                sys.stderr.write("error: --format requires a value\n")
                return 2
            fmt = argv[i]
            if fmt not in ("text", "json", "sarif"):
                sys.stderr.write("error: --format must be text, json, or sarif\n")
                return 2
        elif arg == "--checks":
            i += 1
            if i >= len(argv):
                sys.stderr.write("error: --checks requires a value\n")
                return 2
            checks = [c for c in argv[i].split(",") if c]
        elif arg == "--fail-on":
            i += 1
            if i >= len(argv):
                sys.stderr.write("error: --fail-on requires a value\n")
                return 2
            raw = argv[i].strip().lower()
            if raw == "never":
                fail_on = None
            else:
                try:
                    fail_on = Severity(raw)
                except ValueError:
                    sys.stderr.write(
                        "error: --fail-on must be critical, high, medium, low, info, or never\n"
                    )
                    return 2
        elif arg == "--quiet":
            quiet = True
        elif arg.startswith("-"):
            sys.stderr.write("error: unknown option " + arg + "\n")
            sys.stderr.write(USAGE)
            return 2
        else:
            paths.append(arg)
        i += 1

    if not paths:
        sys.stderr.write("error: no manifest given\n")
        sys.stderr.write(USAGE)
        return 2

    reports = []
    for path in paths:
        if checks is None:
            reports.append((path, audit_file(path)))
        else:
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    decoded = json.loads(fh.read())
            except (OSError, ValueError) as exc:
                reports.append((path, AuditReport(audited=False, error=str(exc))))
                continue
            reports.append((path, audit_manifest(decoded, checks=checks)))

    if fmt == "json":
        payload = [r.to_dict() for _, r in reports] if len(reports) > 1 else reports[0][1].to_dict()
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    elif fmt == "sarif":
        if len(reports) > 1:
            merged = {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [],
            }
            for _, r in reports:
                merged["runs"].extend(r.to_sarif()["runs"])
            sys.stdout.write(json.dumps(merged, indent=2) + "\n")
        else:
            sys.stdout.write(json.dumps(reports[0][1].to_sarif(), indent=2) + "\n")
    else:
        for path, report in reports:
            if quiet:
                sys.stdout.write(report.summary() + "\n")
                continue
            sys.stdout.write("== " + path + " ==\n")
            if not report.audited:
                sys.stdout.write("  audit failed: " + report.error + "\n")
                continue
            for finding in report.sorted_findings():
                sys.stdout.write("  " + str(finding) + "\n")
                if finding.remediation:
                    sys.stdout.write("      fix: " + finding.remediation + "\n")
            sys.stdout.write(
                "  -> " + report.summary() + " (" + str(len(report.findings)) + " finding(s))\n"
            )
            sys.stdout.write("\n")

    worst = None
    for _, report in reports:
        if not report.audited:
            return 3
        if report.max_severity and (worst is None or report.max_severity.rank > worst.rank):
            worst = report.max_severity
    if fail_on is not None and worst is not None and worst.rank >= fail_on.rank:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
