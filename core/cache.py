#!/usr/bin/env python3
"""
Système de cache intelligent pour NetTrace
"""

import json
import time
import hashlib
from pathlib import Path
from typing import Any, Optional
from config.settings import CACHE_DIR, CACHE_TTL, CACHE_ENABLED

class CacheManager:
    """Gestionnaire de cache avec TTL"""
    
    def __init__(self):
        self.cache_dir = CACHE_DIR
        self.enabled = CACHE_ENABLED
    
    def _get_cache_path(self, key: str, cache_type: str) -> Path:
        """Génère le chemin du fichier cache"""
        hash_key = hashlib.md5(f"{cache_type}:{key}".encode()).hexdigest()
        return self.cache_dir / f"{cache_type}_{hash_key}.json"
    
    def get(self, key: str, cache_type: str) -> Optional[Any]:
        """Récupère une valeur du cache"""
        if not self.enabled:
            return None
        
        cache_file = self._get_cache_path(key, cache_type)
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Vérifier TTL
            ttl = CACHE_TTL.get(cache_type, 3600)
            if time.time() - data['timestamp'] > ttl:
                cache_file.unlink()  # Supprimer le cache expiré
                return None
            
            return data['value']
        
        except (json.JSONDecodeError, KeyError, FileNotFoundError):
            return None
    
    def set(self, key: str, value: Any, cache_type: str) -> None:
        """Stocke une valeur dans le cache"""
        if not self.enabled:
            return
        
        cache_file = self._get_cache_path(key, cache_type)
        
        data = {
            'timestamp': time.time(),
            'value': value
        }
        
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        except Exception:
            pass  # Échec silencieux du cache
    
    def clear(self, cache_type: Optional[str] = None) -> None:
        """Vide le cache"""
        pattern = f"{cache_type}_*" if cache_type else "*"
        for cache_file in self.cache_dir.glob(f"{pattern}.json"):
            try:
                cache_file.unlink()
            except Exception:
                pass
    
    def get_stats(self) -> dict:
        """Statistiques du cache"""
        cache_files = list(self.cache_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in cache_files)
        
        return {
            'files': len(cache_files),
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'enabled': self.enabled
        }

# Instance globale
cache = CacheManager()