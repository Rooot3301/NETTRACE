"""Unit tests for the cache manager, including passive/active variants."""
from cache import CacheManager


def test_set_and_get_roundtrip(tmp_path):
    cm = CacheManager(cache_dir=tmp_path, ttl=3600)
    cm.set("example.com", {"score": 42})
    assert cm.get("example.com") == {"score": 42}


def test_passive_and_active_variants_are_separate(tmp_path):
    cm = CacheManager(cache_dir=tmp_path, ttl=3600)
    cm.set("example.com", {"mode": "passive"})
    cm.set("example.com", {"mode": "active"}, variant="active")
    # A passive lookup must NOT return the active result and vice versa.
    assert cm.get("example.com") == {"mode": "passive"}
    assert cm.get("example.com", variant="active") == {"mode": "active"}


def test_active_lookup_misses_when_only_passive_cached(tmp_path):
    cm = CacheManager(cache_dir=tmp_path, ttl=3600)
    cm.set("example.com", {"mode": "passive"})
    # Regression: --active must not be served a passive cache entry.
    assert cm.get("example.com", variant="active") is None


def test_ttl_expiry(tmp_path):
    cm = CacheManager(cache_dir=tmp_path, ttl=0)
    cm.set("example.com", {"x": 1})
    assert cm.get("example.com") is None


def test_clear_removes_all_variants(tmp_path):
    cm = CacheManager(cache_dir=tmp_path, ttl=3600)
    cm.set("example.com", {"mode": "passive"})
    cm.set("example.com", {"mode": "active"}, variant="active")
    cleared = cm.clear("example.com")
    assert cleared == 2
    assert cm.get("example.com") is None
    assert cm.get("example.com", variant="active") is None
