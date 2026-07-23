#!/usr/bin/env python3
"""Standalone scanner runner for testing and debugging."""

import json
import sys
from .scanner_init import *  # noqa: F401, F403 — trigger auto-registration
from .core.registry import registry
from .core.orchestrator import ScanOrchestrator
from .core.models import ScanTarget


def scan_domain(domain: str, port: int = 443) -> dict:
    """Run the full TLS v2 scan against a domain."""
    # Trigger auto-registration
    import importlib
    importlib.import_module("tls_scanner_service.scanner.scanner_init")

    target = ScanTarget(raw_input=domain, hostname=domain, port=port)
    orchestrator = ScanOrchestrator(max_workers=6)
    result = orchestrator.run_all(target)

    print(f"\n{'='*60}")
    print(f" TLS v2 Scan: {domain}:{port}")
    print(f" Duration: {result.scan_duration_ms}ms")
    print(f" Overall Status: {result.summary.get('overall_status', 'unknown')}")
    print(f" Modules: {result.summary.get('total_modules', 0)} total, "
          f"{result.summary.get('successful', 0)} successful, "
          f"{result.summary.get('failed', 0)} failed")
    print(f"{'='*60}\n")

    for mod_name, mod_result in result.modules.items():
        status_icon = {
            "success": "✅",
            "partial": "⚠️",
            "failed": "❌",
            "skipped": "⏭️",
        }.get(mod_result.status, "❓")
        print(f"  {status_icon} {mod_name}: {mod_result.status} ({mod_result.duration_ms}ms)")
        if mod_result.warnings:
            for w in mod_result.warnings:
                print(f"     ⚠️  {w}")
        if mod_result.errors:
            for e in mod_result.errors:
                print(f"     ❌ {e}")

    return result.to_dict()


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m tls_scanner_service.scanner.run <domain> [port]")
        print("Example: python -m tls_scanner_service.scanner.run google.com 443")
        sys.exit(1)

    domain = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    result = scan_domain(domain, port)

    # Full JSON output
    print(f"\n{'='*60}")
    print(" FULL JSON OUTPUT")
    print(f"{'='*60}")
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()

