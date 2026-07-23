"""Base class for all scanner plugins."""

import time
from abc import ABC, abstractmethod
from .models import ModuleResult, ScanTarget


class BaseScanner(ABC):
    """All scanner modules inherit from this class."""

    @property
    @abstractmethod
    def module_name(self) -> str:
        """Unique module identifier (e.g. 'dns', 'tls_protocol')."""
        ...

    @abstractmethod
    def scan(self, target: ScanTarget) -> ModuleResult:
        """Execute the scan for the given target."""
        ...

    def execute(self, target: ScanTarget) -> ModuleResult:
        """Wrapper that times execution and handles exceptions."""
        start = time.perf_counter()
        result = ModuleResult(module=self.module_name)

        try:
            result = self.scan(target)
            result.duration_ms = round((time.perf_counter() - start) * 1000, 2)
            if result.status == "pending":
                result.status = "success"
        except Exception as e:
            result.duration_ms = round((time.perf_counter() - start) * 1000, 2)
            result.mark_failed(str(e))

        return result

