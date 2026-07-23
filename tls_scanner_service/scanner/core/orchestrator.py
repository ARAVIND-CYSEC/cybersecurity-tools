"""Central orchestrator that runs all scanner modules in parallel."""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from .models import ModuleResult, ScanTarget, UnifiedScanResult
from .registry import registry


class ScanOrchestrator:
    """Executes all registered scanner modules against a target."""

    def __init__(self, max_workers: int = 6):
        self.max_workers = max_workers

    def run_all(self, target: ScanTarget, module_filter: Optional[List[str]] = None) -> UnifiedScanResult:
        """Run all (or filtered) scanner modules in parallel."""
        result = UnifiedScanResult(target=target)
        start = time.perf_counter()

        scanners = registry.all()
        if module_filter:
            scanners = {k: v for k, v in scanners.items() if k in module_filter}

        if not scanners:
            result.errors.append("No scanner modules registered.")
            return result

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(scanners))) as executor:
            future_map = {
                executor.submit(scanner.execute, target): name
                for name, scanner in scanners.items()
            }

            for future in as_completed(future_map):
                module_name = future_map[future]
                try:
                    module_result = future.result()
                    result.add_module(module_name, module_result)
                except Exception as e:
                    err_result = ModuleResult(module=module_name)
                    err_result.mark_failed(str(e))
                    result.add_module(module_name, err_result)

        result.scan_duration_ms = round((time.perf_counter() - start) * 1000, 2)

        # Build summary
        total = len(result.modules)
        successful = sum(1 for m in result.modules.values() if m.status == "success")
        failed = sum(1 for m in result.modules.values() if m.status == "failed")
        partial = sum(1 for m in result.modules.values() if m.status == "partial")

        result.summary = {
            "total_modules": total,
            "successful": successful,
            "partial": partial,
            "failed": failed,
            "overall_status": "success" if failed == 0 else "partial" if successful > 0 else "failed"
        }

        return result

    def run_module(self, target: ScanTarget, module_name: str) -> Optional[ModuleResult]:
        """Run a single module by name."""
        scanner = registry.get(module_name)
        if not scanner:
            return None
        return scanner.execute(target)

