"""
scope_enforcer.py — mitmproxy addon for hack-ai-v2

Enforces scope boundaries at the network level.
All HTTP(S) traffic from sandboxed scripts passes through mitmproxy.
This addon checks every request against the allowed scope and KILLS
out-of-scope requests with a 403.

Usage:
    mitmproxy -s scripts/scope_enforcer.py --set scope_file=/path/to/bounty-{slug}/scope.txt
    mitmdump -s scripts/scope_enforcer.py --set scope_file=/path/to/bounty-{slug}/scope.txt

If scope_file is not set, it auto-discovers from ~/bounty-programs/bounty-*/scope.txt
(uses the most recently modified one).
"""

import fnmatch
import logging
import os
import re
from pathlib import Path

from mitmproxy import ctx, http


logger = logging.getLogger("scope_enforcer")


class ScopeEnforcer:
    def __init__(self):
        self.in_scope: list[str] = []
        self.out_of_scope: list[str] = []
        self.blocked_count = 0
        self.allowed_count = 0

    def load(self, loader):
        loader.add_option(
            name="scope_file",
            typespec=str,
            default="",
            help="Path to scope.txt file for the active bounty program",
        )

    def configure(self, updated):
        scope_file = ctx.options.scope_file

        if not scope_file:
            # Auto-discover from ~/bounty-programs/
            scope_file = self._auto_discover_scope()

        if scope_file and os.path.exists(scope_file):
            self._parse_scope_file(scope_file)
            ctx.log.info(
                f"[SCOPE] Loaded scope from {scope_file}: "
                f"{len(self.in_scope)} in-scope, {len(self.out_of_scope)} out-of-scope"
            )
        else:
            ctx.log.warn(
                "[SCOPE] No scope file found. ALL requests will be BLOCKED. "
                "Set --set scope_file=/path/to/scope.txt"
            )

    def request(self, flow: http.HTTPFlow) -> None:
        """Check every request against scope. Kill if out-of-scope.
        
        NOTE: No internal IP bypass. If you need Claude to reach localhost,
        192.168.*, or 10.*, put those IPs in scope.txt explicitly.
        An autonomous AI must never have a hardcoded pass to local infra.
        """
        host = flow.request.pretty_host

        if not self.in_scope:
            # No scope loaded — block everything (fail-safe)
            self._block(flow, host, "No scope loaded — blocking all external traffic")
            return

        # Check out-of-scope first (takes priority)
        for pattern in self.out_of_scope:
            if self._matches(host, pattern):
                self._block(flow, host, f"Matched out-of-scope pattern: {pattern}")
                return

        # Check in-scope
        for pattern in self.in_scope:
            if self._matches(host, pattern):
                self.allowed_count += 1
                return

        # Not in any scope pattern — block
        self._block(flow, host, "Domain not in any in-scope pattern")

    def _block(self, flow: http.HTTPFlow, host: str, reason: str):
        """Kill the flow with a 403 and log it."""
        self.blocked_count += 1
        ctx.log.warn(
            f"[SCOPE] ⛔ BLOCKED #{self.blocked_count}: {flow.request.method} "
            f"{flow.request.pretty_url} — {reason}"
        )
        flow.response = http.Response.make(
            403,
            f"BLOCKED BY SCOPE ENFORCER\n\n"
            f"Host: {host}\n"
            f"Reason: {reason}\n"
            f"URL: {flow.request.pretty_url}\n\n"
            f"This request was blocked because it targets a domain outside the "
            f"authorized scope. Check your bounty program's scope.txt.\n",
            {"Content-Type": "text/plain", "X-Scope-Enforcer": "blocked"},
        )

    def _matches(self, host: str, pattern: str) -> bool:
        """
        Check if a hostname matches a scope pattern.
        Supports:
          - Exact match: "example.com"
          - Wildcard subdomain: "*.example.com" 
          - fnmatch patterns: "*.api.example.com"
        """
        # Normalize
        host = host.lower().strip()
        pattern = pattern.lower().strip()

        # Remove protocol/path if accidentally included
        pattern = re.sub(r'^https?://', '', pattern)
        pattern = pattern.split('/')[0]  

        # Exact match
        if host == pattern:
            return True

        # Wildcard: *.example.com matches example.com AND sub.example.com
        if pattern.startswith("*."):
            base = pattern[2:]  # "example.com"
            if host == base:
                return True
            if host.endswith("." + base):
                return True

        # fnmatch fallback for complex patterns
        if fnmatch.fnmatch(host, pattern):
            return True

        return False

    def _parse_scope_file(self, path: str):
        """Parse a scope.txt file with # Scope / ## In Scope / ## Out of Scope sections."""
        self.in_scope = []
        self.out_of_scope = []

        section = None
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    lower = line.lower()
                    if "in scope" in lower and "out" not in lower:
                        section = "in"
                    elif "out of scope" in lower or "out-of-scope" in lower:
                        section = "out"
                    elif line.startswith("## "):
                        section = None  # reset on other sections 
                    continue

                # Skip comment lines
                if line.startswith("//") or line.startswith(";"):
                    continue

                # Clean up: remove bullet points, dashes, etc.
                # But don't strip '*' from wildcard patterns like *.example.com
                if line.startswith('*.'):
                    cleaned = line
                else:
                    cleaned = re.sub(r'^[-*•]\s*', '', line).strip()
                if not cleaned:
                    continue

                if section == "in":
                    self.in_scope.append(cleaned)
                elif section == "out":
                    self.out_of_scope.append(cleaned)

    def _auto_discover_scope(self) -> str:
        """Find the most recently modified scope.txt in ~/bounty-programs/."""
        home = Path.home()
        base_dir = home / "bounties"
        if not base_dir.exists():
            return ""

        scope_files = list(base_dir.glob("bounty-*/scope.txt"))
        if not scope_files:
            return ""

        # Return the most recently modified one
        scope_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return str(scope_files[0])


addons = [ScopeEnforcer()]
