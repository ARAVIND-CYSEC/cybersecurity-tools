"""Socket timeout and connection utilities."""

import socket
import ssl
from typing import Optional, Tuple


DEFAULT_TIMEOUT = 8
DEFAULT_PORT = 443


def create_socket_connection(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: int = DEFAULT_TIMEOUT,
    source_address: Optional[Tuple[str, int]] = None
) -> socket.socket:
    """Create a TCP socket connection with timeout."""
    sock = socket.create_connection(
        (host, port),
        timeout=timeout,
        source_address=source_address
    )
    return sock


def create_tls_context(
    min_version: Optional[ssl.TLSVersion] = None,
    max_version: Optional[ssl.TLSVersion] = None,
) -> ssl.SSLContext:
    """Create a custom SSL context for version-specific probing."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if min_version:
        ctx.minimum_version = min_version
    if max_version:
        ctx.maximum_version = max_version
    return ctx


def tls_handshake(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: int = DEFAULT_TIMEOUT,
    tls_version: Optional[ssl.TLSVersion] = None,
    servername: Optional[str] = None
) -> dict:
    """Perform a TLS handshake and return connection details."""
    ctx = create_tls_context(
        min_version=tls_version,
        max_version=tls_version
    )
    with create_socket_connection(host, port, timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=servername or host) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            cipher = ssock.cipher()
            return {
                "ok": True,
                "der_cert": der_cert,
                "negotiated_cipher": cipher[0] if cipher else None,
                "negotiated_protocol": ssock.version(),
                "cipher_bits": cipher[1] if cipher else None,
                "alpn": ssock.selected_alpn_protocol(),
            }


def is_host_reachable(host: str, port: int = DEFAULT_PORT, timeout: int = 3) -> bool:
    """Quick check if a host:port is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

