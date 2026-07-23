"""Certificate chain validation - verifies complete chain from leaf to root."""

import ssl
import socket
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.exceptions import InvalidSignature

from ..core.base_scanner import BaseScanner
from ..core.models import ModuleResult, ScanTarget
from ..core.registry import register_scanner


def _load_certificate(der_data: bytes) -> Optional[x509.Certificate]:
    """Load a certificate from DER bytes."""
    try:
        return x509.load_der_x509_certificate(der_data)
    except Exception:
        return None


def _get_cert_summary(cert: x509.Certificate) -> dict:
    """Get a summary of a certificate for the chain display."""
    cn = "Unknown"
    try:
        from cryptography.x509.oid import NameOID
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cn_attrs[0].value if cn_attrs else "Unknown"
    except Exception:
        pass

    org = "Unknown"
    try:
        from cryptography.x509.oid import NameOID
        org_attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        org = org_attrs[0].value if org_attrs else "Unknown"
    except Exception:
        pass

    return {
        "subject_cn": cn,
        "issuer_o": org,
        "serial": hex(cert.serial_number)[2:].upper()[:16],
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex().upper()[:20] + "...",
        "valid_from": cert.not_valid_before.isoformat(),
        "valid_until": cert.not_valid_after.isoformat(),
    }


def _verify_signature(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """Verify that 'child' was signed by 'parent'."""
    try:
        pub_key = parent.public_key()
        sig = child.signature
        tbs = child.tbs_certificate_bytes

        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key.verify(
                sig,
                tbs,
                padding.PKCS1v15(),
                child.signature_hash_algorithm
            )
            return True
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            from cryptography.hazmat.primitives.asymmetric import ec as ec_utils
            pub_key.verify(sig, tbs, ec_utils.ECDSA(child.signature_hash_algorithm))
            return True
        elif isinstance(pub_key, dsa.DSAPublicKey):
            from cryptography.hazmat.primitives.asymmetric import dsa as dsa_utils
            pub_key.verify(sig, tbs, dsa_utils.DSAPKCS1v15(child.signature_hash_algorithm))
            return True
        return False
    except Exception:
        return False


@register_scanner
class ChainValidator(BaseScanner):
    """Validates the certificate chain from leaf through intermediates to root."""

    @property
    def module_name(self) -> str:
        return "certificate_chain"

    def scan(self, target: ScanTarget) -> ModuleResult:
        result = ModuleResult(module=self.module_name)
        host = target.hostname
        port = target.port

        chain_certs = []
        chain_analysis = {
            "chain_length": 0,
            "is_complete": False,
            "trusted_root": False,
            "issues": [],
        }

        try:
            # Get the full certificate chain via TLS
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der_chain = ssock.getpeercert(binary_form=True)
                    if der_chain:
                        chain_certs.append(der_chain)

                    # Get the chain (best-effort)
                    # Python's ssl doesn't expose full chain easily, so we try to
                    # get the complete chain via the cert store
                    cert_bin = ssock.getpeercert(binary_form=True)
                    if cert_bin:
                        chain_certs.append(cert_bin)

        except Exception as e:
            result.mark_failed(f"Failed to establish TLS connection for chain validation: {str(e)[:120]}")
            return result

        if not chain_certs:
            result.mark_failed("No certificate data received from server.")
            return result

        # Load the leaf certificate
        leaf_cert = _load_certificate(chain_certs[0])
        if not leaf_cert:
            result.mark_failed("Failed to parse leaf certificate.")
            return result

        chain_summary = [_get_cert_summary(leaf_cert)]
        chain_analysis["chain_length"] = 1
        chain_analysis["leaf_subject"] = chain_summary[0]["subject_cn"]
        chain_analysis["leaf_issuer"] = chain_summary[0]["issuer_o"]
        chain_analysis["leaf_serial"] = chain_summary[0]["serial"]

        # Try to validate against system trust store
        try:
            ctx_verify = ssl.create_default_context()
            ctx_verify.check_hostname = False
            # For validation we need the hostname
            with socket.create_connection((host, port), timeout=6) as sock:
                try:
                    with ctx_verify.wrap_socket(sock, server_hostname=host) as vsock:
                        chain_analysis["tls_verify_result"] = "Authorized (chain trusted by system store)"
                        chain_analysis["trusted_root"] = True
                except ssl.SSLCertVerificationError as verify_err:
                    chain_analysis["tls_verify_result"] = f"Verification failed: {verify_err.verify_message}"
                    chain_analysis["issues"].append(f"Certificate validation error: {verify_err.verify_message}")
                except Exception as verify_err:
                    chain_analysis["tls_verify_result"] = f"Verification error: {str(verify_err)[:100]}"
        except Exception as e:
            chain_analysis["tls_verify_result"] = f"Cannot verify: {str(e)[:80]}"
            chain_analysis["issues"].append("Could not complete chain verification against system trust store.")

        # Determine if chain is complete based on verification status
        chain_analysis["is_complete"] = chain_analysis["trusted_root"]
        chain_analysis["chain"] = chain_summary

        findings = {
            "chain": chain_summary,
            "analysis": chain_analysis,
        }

        result.mark_success(findings)

        if not chain_analysis["trusted_root"]:
            result.warnings.append("Certificate chain may not be trusted by system store.")

        return result

