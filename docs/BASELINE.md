# Advanced DevOps project baseline

- Student: Samrudh
- Student identifier: 23bcs10123
- Project: ARE MCP Bounty Tool
- Repository: https://github.com/Sam-wiz/ARE-MCP-bounty-tool
- Preserved baseline: [`8f65f098932831c4bf8429e5385446164f57d1be`](https://github.com/Sam-wiz/ARE-MCP-bounty-tool/commit/8f65f098932831c4bf8429e5385446164f57d1be)
- Baseline branch when work began: `master`; the exact commit above is the reference.

The starting application was a Go MCP server over stdio with a command-line client,
MongoDB storage, a Redis queue client, plugin definitions, finding lifecycle logic,
and an LLM review pipeline. Existing delivery support consisted of a Makefile,
Go tests, an example YAML configuration, and tool installation scripts.

The baseline had no Docker image, Kubernetes manifests, CI/CD workflows, network
service lifecycle, Prometheus endpoint, or OpenTelemetry instrumentation. Its build
failed because the engine referenced an absent Wi-Fi handler. An integration test
also used the old MongoDB constructor signature. Both are repaired in this work.

The original commit remains in repository history. Improvements belong on a separate
branch with focused commits and one pull request against that baseline.

The supplied course guide prohibits AI assistance with implementation and written
submission. These changes were developed with AI assistance. This record does not
assert compliance with that academic rule or describe the changes as unaided work.
