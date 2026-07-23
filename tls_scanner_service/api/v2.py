"""Flask Blueprint exposing the v2 TLS scan endpoint."""

import sys
import os

# Ensure the parent directory is in the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Blueprint, request, jsonify
from ..scanner.scanner_init import *  # noqa: F401, F403 — trigger scanner registration
from ..scanner.core.registry import registry
from ..scanner.core.orchestrator import ScanOrchestrator
from ..scanner.core.models import ScanTarget

v2_api = Blueprint("tls_v2", __name__, url_prefix="/api/tls/v2")

orchestrator = ScanOrchestrator(max_workers=6)


def sanitize_host(user_input: str) -> str:
    """Strip protocol, path, port from user input to get clean hostname."""
    raw = str(user_input or "").strip().lower()
    if not raw:
        return ""
    raw = raw.replace("https://", "").replace("http://", "")
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    raw = raw.split(":", 1)[0]
    raw = raw.strip().lower()
    raw = raw.lstrip("www.")
    return raw


@v2_api.route("/scan", methods=["POST"])
def scan_endpoint_v2():
    """Run the full TLS v2 enterprise scan against a domain."""
    data = request.get_json(silent=True) or {}
    domain_input = data.get("domain") or data.get("host") or ""

    hostname = sanitize_host(domain_input)
    if not hostname:
        return jsonify({
            "error": "A valid domain/hostname is required.",
            "input": domain_input
        }), 400

    port = int(data.get("port", 443))
    module_filter = data.get("modules", None)  # optional: list of module names to run

    try:
        target = ScanTarget(
            raw_input=domain_input,
            hostname=hostname,
            port=port,
            timeout=int(data.get("timeout", 8))
        )

        result = orchestrator.run_all(target, module_filter=module_filter)

        response = result.to_dict()
        response["input"] = domain_input
        response["target_hostname"] = hostname

        return jsonify(response), 200

    except Exception as e:
        return jsonify({
            "error": "TLS v2 scan failed.",
            "details": str(e)[:300]
        }), 500


@v2_api.route("/modules", methods=["GET"])
def list_modules():
    """List all registered scanner modules."""
    return jsonify({
        "modules": registry.list_modules(),
        "count": registry.count()
    }), 200


@v2_api.route("/health", methods=["GET"])
def health():
    """Health check for the v2 scanner."""
    return jsonify({
        "ok": True,
        "service": "tls-v2-scanner",
        "modules_loaded": registry.count(),
        "modules": registry.list_modules()
    }), 200

