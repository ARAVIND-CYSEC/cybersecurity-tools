import socket
import ssl
import json
import argparse
import sys
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import Flask, request, jsonify

# Flask lightweight wrapper; allows Node server.js to call this service via HTTP.
# Run:
#   python app.py --host 0.0.0.0 --port 8060
# Then call:
#   POST /scan {"domain":"example.com"}

app = Flask(__name__)

DEFAULT_PORT = 443
TIMEOUT_SEC = 6

CERT_SCT_EMBEDDED_OID = "1.3.6.1.4.1.11129.2.4.2"  # Embedded SCTs


def sanitize_host(user_input: str) -> str:
    raw = str(user_input or "").strip()
    if not raw:
        return ""
    # strip protocol
    raw = raw.replace("https://", "").replace("http://", "")
    # cut path/query/fragment
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    # strip port
    raw = raw.split(":", 1)[0]
    raw = raw.strip().lower()
    if raw.startswith("www."):
        raw = raw[4:]
    return raw


def tls_handshake(clean_host: str, tls_version: ssl.TLSVersion):
    ctx = ssl.create_default_context()
    ctx.minimum_version = tls_version
    ctx.maximum_version = tls_version
    with socket.create_connection((clean_host, DEFAULT_PORT), timeout=TIMEOUT_SEC) as sock:
        with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            negotiated_cipher = ssock.cipher()[0] if ssock.cipher() else None
            negotiated_protocol = ssock.version()
            return {
                "ok": True,
                "der_cert": der_cert,
                "negotiated_cipher": negotiated_cipher,
                "negotiated_protocol": negotiated_protocol,
            }


def count_embedded_scts(cert: x509.Certificate) -> int:
    sct_count = 0
    for ext in cert.extensions:
        if ext.oid.dotted_string == CERT_SCT_EMBEDDED_OID:
            # extension.value is typically an ASN.1 structure; length is best-effort.
            try:
                sct_count = len(ext.value)
            except Exception:
                sct_count = 1
    return sct_count


def scan(domain_input: str):
    clean_host = sanitize_host(domain_input)
    result = {
        "target": clean_host,
        "input": domain_input,
        "scanTimestamp": datetime.now(timezone.utc).isoformat(),
        "protocol_support": {},
        "certificate_intel": {},
        "status": "failed",
        "reason": None,
        "active_connection": {},
    }

    if not clean_host:
        result["reason"] = "Empty or invalid input."
        return result

    primary_der_cert = None
    negotiated_cipher = None
    active_version = None

    for label, v in [("TLSv1.3", ssl.TLSVersion.TLSv1_3), ("TLSv1.2", ssl.TLSVersion.TLSv1_2)]:
        try:
            hs = tls_handshake(clean_host, v)
            result["protocol_support"][label] = "Observed/Supported"
            if primary_der_cert is None or label == "TLSv1.3":
                primary_der_cert = hs["der_cert"]
                negotiated_cipher = hs["negotiated_cipher"]
                active_version = hs["negotiated_protocol"]
        except Exception as e:
            result["protocol_support"][label] = "Not Observed/Rejected"

    if not primary_der_cert:
        result["reason"] = "Could not establish a verified TLS handshake on port 443 (TLS 1.2/1.3)."
        return result

    try:
        cert = x509.load_der_x509_certificate(primary_der_cert)

        valid_from = cert.not_valid_before
        valid_until = cert.not_valid_after

        days_remaining = int((valid_until - datetime.now(timezone.utc)).days)
        days_remaining = max(0, days_remaining)

        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = cn_attrs[0].value if cn_attrs else "Unknown"

        issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        issuer_org = issuer_attrs[0].value if issuer_attrs else "Unknown"

        san = []
        try:
            ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            san = []

        sct_count = count_embedded_scts(cert)

        result["status"] = "success"
        result["active_connection"] = {
            "established_protocol": active_version,
            "cipher_suite": negotiated_cipher,
        }
        result["certificate_intel"] = {
            "common_name_cn": common_name,
            "issuer_o": issuer_org,
            "serial_number": hex(cert.serial_number)[2:].upper(),
            "sha256": cert.fingerprint(cert.signature_hash_algorithm).hex().upper(),
            "valid_from": valid_from.strftime("%Y-%m-%d"),
            "valid_until": valid_until.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
            "certificate_transparency_records": sct_count,
            "subject_alternative_names": san,
        }

        return result

    except Exception as e:
        result["status"] = "parsing_error"
        result["reason"] = str(e)
        return result


@app.post("/scan")
def scan_endpoint():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain") or data.get("host") or ""
    res = scan(domain)
    code = 200 if res.get("status") == "success" else 400
    return jsonify(res), code


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8060)
    args = parser.parse_args()

    # Flask dev server (for local usage). Production should use gunicorn.
    app.run(host=args.host, port=args.port, debug=False)

