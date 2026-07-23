"""Plugin registry for scanner modules."""

from typing import Dict, Optional, Type
from .base_scanner import BaseScanner


class ScannerRegistry:
    """Holds references to all registered scanner plugins."""

    def __init__(self):
        self._scanners: Dict[str, BaseScanner] = {}

    def register(self, scanner: BaseScanner):
        name = scanner.module_name
        if name in self._scanners:
            raise ValueError(f"Scanner '{name}' is already registered.")
        self._scanners[name] = scanner

    def get(self, name: str) -> Optional[BaseScanner]:
        return self._scanners.get(name)

    def all(self) -> Dict[str, BaseScanner]:
        return dict(self._scanners)

    def list_modules(self) -> list:
        return list(self._scanners.keys())

    def count(self) -> int:
        return len(self._scanners)


# Global singleton
registry = ScannerRegistry()


def register_scanner(scanner_cls: Type[BaseScanner]):
    """Decorator to auto-register scanner classes."""
    instance = scanner_cls()
    registry.register(instance)
    return scanner_cls

