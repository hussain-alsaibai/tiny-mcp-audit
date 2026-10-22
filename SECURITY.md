# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
(`Security` tab -> `Report a vulnerability`) rather than a public issue.

I aim to respond within 72 hours.

## Scope

`tiny-mcp-audit` reads manifests and writes reports. It performs **no network
I/O** and does **not** import or execute the code it audits. The realistic risk
surface is a crash or resource exhaustion on a hostile manifest.

Findings intentionally never include the matched secret value - only its
shape - so reports are safe to publish. Please keep that property intact in
any pull request that touches the secret-detection rules.
