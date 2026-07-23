"""Comprehensive X.509 Certificate Parser."""

from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, padding

from ..core.base_scanner import BaseScanner
from ..core.models import ModuleResult, ScanTarget
from ..core.registry import register_scanner
from ..utils.timeout import tls_handshake


OID_MAP = {
    "2.5.4.3": "Common Name (CN)",
    "2.5.4.6": "Country (C)",
    "2.5.4.7": "Locality (L)",
    "2.5.4.8": "State/Province (ST)",
    "2.5.4.10": "Organization (O)",
    "2.5.4.11": "Organizational Unit (OU)",
    "2.5.4.5": "Serial Number (SN)",
    "2.5.4.46": "Domain Component (DC)",
}

CERT_SCT_EMBEDDED_OID = "1.3.6.1.4.1.11129.2.4.2"


def _get_name_attributes(name: x509.Name) -> dict:
    """Extract structured name attributes."""
    attrs = {}
    for attr in name:
        oid_str = attr.oid.dotted_string
        label = OID_MAP.get(oid_str, attr.oid._name if hasattr(attr.oid, '_name') else oid_str)
        attrs[label] = attr.value
    return attrs


def _get_key_info(pub_key) -> dict:
    """Extract key algorithm and size information."""
    info = {"algorithm": "Unknown", "size": 0, "curve": None}
    if isinstance(pub_key, rsa.RSAPublicKey):
        info["algorithm"] = "RSA"
        info["size"] = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        info["algorithm"] = "ECDSA" if hasattr(pub_key.curve, 'name') else "EC"
        info["size"] = pub_key.key_size
        info["curve"] = pub_key.curve.name if hasattr(pub_key.curve, 'name') else str(pub_key.curve)
    elif isinstance(pub_key, dsa.DSAPublicKey):
        info["algorithm"] = "DSA"
        info["size"] = pub_key.key_size
    return info


def _get_signature_info(cert: x509.Certificate) -> dict:
    """Extract signature algorithm details."""
    sig_hash = cert.signature_hash_algorithm
    return {
        "signature_algorithm": cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid),
        "hash_algorithm": sig_hash.name if isinstance(sig_hash, hashes.HashAlgorithm) else str(sig_hash),
        "hash_bits": sig_hash.digest_size * 8 if isinstance(sig_hash, hashes.HashAlgorithm) else None,
    }


def _parse_extensions(cert: x509.Certificate) -> dict:
    """Parse all X.509v3 extensions."""
    extensions = {}

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ext.value.get_values_for_type(x509.DNSName)
        extensions["subject_alternative_names"] = san
        extensions["san_count"] = len(san)
    except x509.ExtensionNotFound:
        extensions["subject_alternative_names"] = []
        extensions["san_count"] = 0

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        bc = ext.value
        extensions["ca"] = bc.ca
        extensions["path_length_constraint"] = bc.path_length
    except x509.ExtensionNotFound:
        extensions["ca"] = False
        extensions["path_length_constraint"] = None

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        ku = ext.value
        extensions["key_usage"] = {
            "digital_signature": ku.digital_signature,
            "content_commitment": ku.content_commitment,
            "key_encipherment": ku.key_encipherment,
            "data_encipherment": ku.data_encipherment,
            "key_agreement": ku.key_agreement,
            "key_cert_sign": ku.key_cert_sign,
            "crl_sign": ku.crl_sign,
            "encipher_only": ku.encipher_only,
            "decipher_only": ku.decipher_only,
        }
    except x509.ExtensionNotFound:
        pass

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        eku = ext.value
        extensions["extended_key_usage"] = [
            oid._name if hasattr(oid, '_name') else oid.dotted_string
            for oid in eku
        ]
    except x509.ExtensionNotFound:
        pass

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
        policies = ext.value
        extensions["certificate_policies"] = [
            p.policy_identifier.dotted_string for p in policies
        ]
    except x509.ExtensionNotFound:
        pass

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        extensions["authority_key_id"] = ext.value.key_identifier.hex() if ext.value.key_identifier else None
    except x509.ExtensionNotFound:
        pass

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        extensions["subject_key_id"] = ext.value.digest.hex() if hasattr(ext.value, 'digest') else str(ext.value)
    except x509.ExtensionNotFound:
        pass

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        aia = ext.value
        ocsp_urls = []
        issuer_urls = []
        for desc in aia:
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                ocsp_urls.append(desc.access_location.value)
            elif desc.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                issuer_urls.append(desc.access_location.value)
        extensions["ocsp_responder_urls"] = ocsp_urls
        extensions["ca_issuer_urls"] = issuer_urls
    except x509.ExtensionNotFound:
        pass

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        crl_dps = ext.value
        extensions["crl_distribution_points"] = [
            str(dp.full_name[0].value) for dp in crl_dps if dp.full_name
        ]
    except x509.ExtensionNotFound:
        pass

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
        nc = ext.value
        extensions["name_constraints"] = {
            "permitted_subtrees": [str(s.base.value) for s in nc.permitted_subtrees] if nc.permitted_subtrees else [],
            "excluded_subtrees": [str(s.base.value) for s in nc.excluded_subtrees] if nc.excluded_subtrees else [],
        }
    except x509.ExtensionNotFound:
        pass

    # SCT extension
    sct_count = 0
    for ext in cert.extensions:
        if ext.oid.dotted_string == CERT_SCT_EMBEDDED_OID:
            try:
                sct_count = len(ext.value)
            except Exception:
                sct_count = 1
    extensions["sct_count"] = sct_count

    return extensions


@register_scanner
class CertificateParser(BaseScanner):
    """Comprehensive X.509 certificate parsing and validation."""

    @property
    def module_name(self) -> str:
        return "certificate"

    def scan(self, target: ScanTarget) -> ModuleResult:
        result = ModuleResult(module=self.module_name)
        host = target.hostname
        port = target.port

        try:
            hs = tls_handshake(host, port, target.timeout)
            if not hs.get("ok") or not hs.get("der_cert"):
                result.mark_failed("Failed to obtain peer certificate.")
                return result

            der_cert = hs["der_cert"]
            cert = x509.load_der_x509_certificate(der_cert)

            pub_key = cert.public_key()
            key_info = _get_key_info(pub_key)
            signature_info = _get_signature_info(cert)
            extensions = _parse_extensions(cert)

            now = datetime.now(timezone.utc)
            valid_from = cert.not_valid_before
            valid_until = cert.not_valid_after
            days_remaining = max(0, (valid_until - now).days)
            days_since_issued = max(0, (now - valid_from).days)
            total_validity_days = max(1, (valid_until - valid_from).days)

            # Wildcard detection
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            common_name = cn_attrs[0].value if cn_attrs else "Unknown"
            is_wildcard = " *." in common_name or common_name.startswith("*.") or any(
                " *." in san or san.startswith("*.") for san in extensions.get("subject_alternative_names", [])
            )

            findings = {
                "subject": _get_name_attributes(cert.subject),
                "issuer": _get_name_attributes(cert.issuer),
                "common_name": common_name,
                "serial_number": hex(cert.serial_number)[2:].upper(),
                "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex().upper(),
                "fingerprint_sha1": cert.fingerprint(hashes.SHA1()).hex().upper(),
                "version": cert.version.value,
                "valid_from": valid_from.isoformat(),
                "valid_until": valid_until.isoformat(),
                "days_remaining": days_remaining,
                "days_since_issued": days_since_issued,
                "total_validity_days": total_validity_days,
                "is_expired": now > valid_until,
                "is_not_yet_valid": now < valid_from,
                "is_wildcard": is_wildcard,
                "public_key": key_info,
                "signature": signature_info,
                "extensions": extensions,
            }

            result.mark_success(findings)

            if is_wildcard:
                result.warnings.append("Wildcard certificate detected.")

            if findings["is_expired"]:
                result.warnings.append(f"Certificate expired {abs(days_remaining)} days ago.")

            if total_validity_days > 825:  # > ~2.26 years (Apple/CA/B requirement)
                result.warnings.append(f"Certificate validity period ({total_validity_days} days) exceeds recommended 825-day limit.")

        except Exception as e:
            result.mark_failed(f"Certificate parsing failed: {str(e)[:200]}")

        return result

