"""Simple TTL-based in-memory cache for scanner results."""

import time
from typing import Any, Optional


class TTLCache:
    """Thread-safe TTL cache with max size."""

    def __init__(self, default_ttl: int = 300, max_size: int = 500):
        self._default_ttl = default_ttl
        self._max_size = max_size
        self._store: dict = {}
        self._expires: dict = {}

    def get(self, key: str) -> Optional[Any]:
        if key not in self._store:
            return None
        if time.monotonic() > self._expires.get(key, 0):
            self._invalidate(key)
            return None
        return self._store[key]

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        if len(self._store) >= self._max_size:
            self._evict_oldest()
        self._store[key] = value
        self._expires[key] = time.monotonic() + (ttl or self._default_ttl)

    def _invalidate(self, key: str):
        self._store.pop(key, None)
        self._expires.pop(key, None)

    def _evict_oldest(self):
        if self._expires:
            oldest = min(self._expires, key=self._expires.get)
            self._invalidate(oldest)

    def clear(self):
        self._store.clear()
        self._expires.clear()


# Global cache instances
dns_cache = TTLCache(default_ttl=300)      # 5 min
ct_cache = TTLCache(default_ttl=600)       # 10 min
ocsp_cache = TTLCache(default_ttl=300)     # 5 min
geo_cache = TTLCache(default_ttl=900)      # 15 min
asn_cache = TTLCache(default_ttl=900)      # 15 min
tls_cache = TTLCache(default_ttl=180)      # 3 min (TLS configs can change)

