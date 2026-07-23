"""Standard result models for every scanner module."""

from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from datetime import datetime, timezone


@dataclass
class ModuleResult:
    """Standard result structure returned by every scanner module."""
    module: str
    status: str = "pending"  # pending, success, partial, failed, skipped
    duration_ms: float = 0.0
    findings: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    raw: Optional[Any] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def mark_success(self, findings: dict = None):
        self.status = "success"
        if findings:
            self.findings.update(findings)

    def mark_partial(self, warning: str = None):
        self.status = "partial"
        if warning:
            self.warnings.append(warning)

    def mark_failed(self, error: str):
        self.status = "failed"
        self.errors.append(error)

    def mark_skipped(self, reason: str):
        self.status = "skipped"
        self.warnings.append(reason)


@dataclass
class ScanTarget:
    """Normalised scan target."""
    raw_input: str
    hostname: str
    port: int = 443
    timeout: int = 8

    @property
    def display_name(self) -> str:
        return self.hostname


@dataclass
class UnifiedScanResult:
    """Top-level result from the orchestrator."""
    target: ScanTarget
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_duration_ms: float = 0.0
    modules: dict = field(default_factory=dict)  # module_name -> ModuleResult
    summary: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def add_module(self, name: str, result: ModuleResult):
        self.modules[name] = result

    def get_module(self, name: str) -> Optional[ModuleResult]:
        return self.modules.get(name)

    def to_dict(self) -> dict:
        return {
            "target": {
                "hostname": self.target.hostname,
                "port": self.target.port,
                "display_name": self.target.display_name
            },
            "scan_timestamp": self.scan_timestamp,
            "scan_duration_ms": self.scan_duration_ms,
            "modules": {k: v.to_dict() for k, v in self.modules.items()},
            "summary": self.summary,
            "errors": self.errors
        }

