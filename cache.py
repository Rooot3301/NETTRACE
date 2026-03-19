"""
NetTrace v2 - Local Cache Manager
Stores analysis results as JSON files with TTL-based expiration.
"""
import json
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any, List

from config import CACHE_DIR, CACHE_TTL


class CacheManager:
    """Manages local JSON-based cache for domain analysis results."""

    def __init__(self, cache_dir: Path = CACHE_DIR, ttl: int = CACHE_TTL):
        self.cache_dir = cache_dir
        self.ttl = ttl
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Create cache directory if it doesn't exist."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def _cache_path(self, domain: str) -> Path:
        """Return the path for a domain's cache file."""
        safe_name = domain.lower().strip().replace("/", "_").replace("\\", "_")
        return self.cache_dir / f"{safe_name}.json"

    def get(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached result for a domain.
        Returns None if not cached or TTL expired.
        """
        path = self._cache_path(domain)
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            cached_at = data.get("_cached_at", 0)
            if time.time() - cached_at > self.ttl:
                # Expired - remove and return None
                path.unlink(missing_ok=True)
                return None
            return data.get("result")
        except (json.JSONDecodeError, OSError, KeyError):
            return None

    def set(self, domain: str, data: Dict[str, Any]) -> bool:
        """
        Store result for a domain in cache.
        Returns True on success, False on failure.
        """
        path = self._cache_path(domain)
        payload = {
            "_cached_at": time.time(),
            "_domain": domain.lower().strip(),
            "result": data,
        }
        try:
            self._ensure_dir()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
            return True
        except OSError:
            return False

    def clear(self, domain: Optional[str] = None) -> int:
        """
        Clear cache entries.
        If domain is specified, only clears that domain.
        Returns number of entries cleared.
        """
        cleared = 0
        if domain is not None:
            path = self._cache_path(domain)
            if path.exists():
                try:
                    path.unlink()
                    cleared = 1
                except OSError:
                    pass
        else:
            # Clear all cache files
            try:
                for p in self.cache_dir.glob("*.json"):
                    try:
                        p.unlink()
                        cleared += 1
                    except OSError:
                        pass
            except OSError:
                pass
        return cleared

    def list_cached(self) -> List[Dict[str, Any]]:
        """
        List all cached domains with metadata.
        Returns list of dicts: {domain, cached_at, expires_at, expired}
        """
        entries = []
        try:
            for p in self.cache_dir.glob("*.json"):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    cached_at = data.get("_cached_at", 0)
                    domain = data.get("_domain", p.stem)
                    expires_at = cached_at + self.ttl
                    expired = time.time() > expires_at
                    entries.append({
                        "domain": domain,
                        "cached_at": cached_at,
                        "expires_at": expires_at,
                        "expired": expired,
                        "file": str(p),
                    })
                except (json.JSONDecodeError, OSError):
                    continue
        except OSError:
            pass
        return sorted(entries, key=lambda x: x["cached_at"], reverse=True)

    def is_cached(self, domain: str) -> bool:
        """Check if a valid (non-expired) cache entry exists for domain."""
        return self.get(domain) is not None
