"""Auto-registration: imports all scanner modules to trigger @register_scanner decorators."""

# DNS
from .dns.dns_scanner import DNSScanner  # noqa: F401

# TLS
from .tls.protocol_scanner import TLSProtocolScanner  # noqa: F401
from .tls.cipher_scanner import CipherScanner  # noqa: F401
from .tls.alpn import ALPNScanner  # noqa: F401
from .tls.features import TLSFeatureScanner  # noqa: F401
from .tls.performance import PerformanceScanner  # noqa: F401

# Certificate
from .certificate.parser import CertificateParser  # noqa: F401
from .certificate.chain import ChainValidator  # noqa: F401
from .certificate.ct import CTScanner  # noqa: F401
from .certificate.ocsp import OCSPValidator  # noqa: F401
from .certificate.validator import CertificateValidator  # noqa: F401

