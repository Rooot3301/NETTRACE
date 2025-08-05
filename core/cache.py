#!/usr/bin/env python3
"""
Production-ready intelligent cache system for NetTrace
Optimized for performance and reliability
"""

import json
import time
import hashlib
import gzip
import pickle
import threading
from pathlib import Path
from typing import Any, Optional, Dict, List
from config.settings import CACHE_DIR, CACHE_TTL, CACHE_ENABLED
import logging

logger = logging.getLogger(__name__)

class CacheManager:
    """Production-ready cache manager with TTL, compression, and thread safety"""
    
    def __init__(self):
        self.cache_dir = CACHE_DIR
        self.enabled = CACHE_ENABLED
        self._lock = threading.RLock()
        self._memory_cache = {}
        self._max_memory_items = 1000
        
        # Créer le dossier cache
        self.cache_dir.mkdir(exist_ok=True)
        
        # Nettoyage automatique au démarrage
        self._cleanup_expired()
    
    def _get_cache_path(self, key: str, cache_type: str) -> Path:
        """Génère le chemin du fichier cache"""
        hash_key = hashlib.md5(f"{cache_type}:{key}".encode()).hexdigest()
        return self.cache_dir / f"{cache_type}_{hash_key}.json"
    
    def _get_memory_key(self, key: str, cache_type: str) -> str:
        """Génère la clé pour le cache mémoire"""
        return f"{cache_type}:{key}"
    
    def _is_expired(self, timestamp: float, cache_type: str) -> bool:
        """Vérifie si un élément du cache a expiré"""
        ttl = CACHE_TTL.get(cache_type, 3600)
        return time.time() - timestamp > ttl
    
    def _compress_data(self, data: bytes) -> bytes:
        """Compresse les données si elles sont volumineuses"""
        if len(data) > 1024:  # Compresser si > 1KB
            return gzip.compress(data)
        return data
    
    def _decompress_data(self, data: bytes) -> bytes:
        """Décompresse les données"""
        try:
            return gzip.decompress(data)
        except gzip.BadGzipFile:
            return data  # Données non compressées
    
    def get(self, key: str, cache_type: str) -> Optional[Any]:
        """Récupère une valeur du cache (mémoire puis disque)"""
        if not self.enabled:
            return None
        
        with self._lock:
            # Vérifier le cache mémoire d'abord
            memory_key = self._get_memory_key(key, cache_type)
            if memory_key in self._memory_cache:
                cached_item = self._memory_cache[memory_key]
                if not self._is_expired(cached_item['timestamp'], cache_type):
                    logger.debug(f"Cache hit (memory): {cache_type}:{key}")
                    return cached_item['value']
                else:
                    del self._memory_cache[memory_key]
            
            # Vérifier le cache disque
            cache_file = self._get_cache_path(key, cache_type)
            
            if not cache_file.exists():
                return None
            
            try:
                with open(cache_file, 'rb') as f:
                    compressed_data = f.read()
                
                # Décompresser et désérialiser
                data_bytes = self._decompress_data(compressed_data)
                data = pickle.loads(data_bytes)
                
                # Vérifier TTL
                if self._is_expired(data['timestamp'], cache_type):
                    cache_file.unlink()  # Supprimer le cache expiré
                    return None
                
                # Ajouter au cache mémoire
                self._add_to_memory_cache(memory_key, data['value'], data['timestamp'])
                
                logger.debug(f"Cache hit (disk): {cache_type}:{key}")
                return data['value']
            
            except Exception as e:
                logger.warning(f"Erreur lecture cache {cache_type}:{key}: {str(e)}")
                # Supprimer le fichier corrompu
                try:
                    cache_file.unlink()
                except:
                    pass
                return None
    
    def set(self, key: str, value: Any, cache_type: str) -> None:
        """Stocke une valeur dans le cache (mémoire et disque)"""
        if not self.enabled:
            return
        
        with self._lock:
            timestamp = time.time()
            
            # Ajouter au cache mémoire
            memory_key = self._get_memory_key(key, cache_type)
            self._add_to_memory_cache(memory_key, value, timestamp)
            
            # Sauvegarder sur disque
            cache_file = self._get_cache_path(key, cache_type)
            
            data = {
                'timestamp': timestamp,
                'value': value,
                'cache_type': cache_type,
                'key': key
            }
            
            try:
                # Sérialiser et compresser
                data_bytes = pickle.dumps(data)
                compressed_data = self._compress_data(data_bytes)
                
                with open(cache_file, 'wb') as f:
                    f.write(compressed_data)
                
                logger.debug(f"Cache set: {cache_type}:{key}")
                
            except Exception as e:
                logger.warning(f"Erreur écriture cache {cache_type}:{key}: {str(e)}")
    
    def _add_to_memory_cache(self, memory_key: str, value: Any, timestamp: float) -> None:
        """Ajoute un élément au cache mémoire avec gestion de la taille"""
        # Nettoyer le cache mémoire si trop plein
        if len(self._memory_cache) >= self._max_memory_items:
            # Supprimer les éléments les plus anciens
            oldest_keys = sorted(
                self._memory_cache.keys(),
                key=lambda k: self._memory_cache[k]['timestamp']
            )[:100]  # Supprimer les 100 plus anciens
            
            for old_key in oldest_keys:
                del self._memory_cache[old_key]
        
        self._memory_cache[memory_key] = {
            'value': value,
            'timestamp': timestamp
        }
    
    def clear(self, cache_type: Optional[str] = None) -> None:
        """Vide le cache (mémoire et disque)"""
        with self._lock:
            # Vider le cache mémoire
            if cache_type:
                keys_to_remove = [k for k in self._memory_cache.keys() if k.startswith(f"{cache_type}:")]
                for key in keys_to_remove:
                    del self._memory_cache[key]
            else:
                self._memory_cache.clear()
            
            # Vider le cache disque
            pattern = f"{cache_type}_*" if cache_type else "*"
            for cache_file in self.cache_dir.glob(f"{pattern}.cache"):
                try:
                    cache_file.unlink()
                    logger.debug(f"Cache file deleted: {cache_file.name}")
                except Exception as e:
                    logger.warning(f"Erreur suppression cache {cache_file}: {str(e)}")
    
    def _cleanup_expired(self) -> None:
        """Nettoie les éléments expirés du cache"""
        with self._lock:
            current_time = time.time()
            
            # Nettoyer le cache mémoire
            expired_keys = []
            for memory_key, cached_item in self._memory_cache.items():
                cache_type = memory_key.split(':', 1)[0]
                if self._is_expired(cached_item['timestamp'], cache_type):
                    expired_keys.append(memory_key)
            
            for key in expired_keys:
                del self._memory_cache[key]
            
            # Nettoyer le cache disque
            for cache_file in self.cache_dir.glob("*.cache"):
                try:
                    with open(cache_file, 'rb') as f:
                        compressed_data = f.read()
                    
                    data_bytes = self._decompress_data(compressed_data)
                    data = pickle.loads(data_bytes)
                    
                    cache_type = data.get('cache_type', 'unknown')
                    if self._is_expired(data['timestamp'], cache_type):
                        cache_file.unlink()
                        logger.debug(f"Expired cache file deleted: {cache_file.name}")
                
                except Exception:
                    # Fichier corrompu, le supprimer
                    try:
                        cache_file.unlink()
                    except:
                        pass
    
    def get_stats(self) -> dict:
        """Statistiques détaillées du cache"""
        with self._lock:
            cache_files = list(self.cache_dir.glob("*.cache"))
            total_size = sum(f.stat().st_size for f in cache_files if f.exists())
            
            # Statistiques par type
            stats_by_type = {}
            for cache_file in cache_files:
                try:
                    cache_type = cache_file.name.split('_')[0]
                    if cache_type not in stats_by_type:
                        stats_by_type[cache_type] = {'files': 0, 'size': 0}
                    
                    stats_by_type[cache_type]['files'] += 1
                    stats_by_type[cache_type]['size'] += cache_file.stat().st_size
                except:
                    continue
            
            return {
                'enabled': self.enabled,
                'disk_files': len(cache_files),
                'disk_size_mb': round(total_size / (1024 * 1024), 2),
                'memory_items': len(self._memory_cache),
                'memory_limit': self._max_memory_items,
                'stats_by_type': stats_by_type,
                'cache_dir': str(self.cache_dir)
            }
    
    def optimize(self) -> Dict[str, int]:
        """Optimise le cache en supprimant les éléments expirés"""
        with self._lock:
            initial_disk_files = len(list(self.cache_dir.glob("*.cache")))
            initial_memory_items = len(self._memory_cache)
            
            self._cleanup_expired()
            
            final_disk_files = len(list(self.cache_dir.glob("*.cache")))
            final_memory_items = len(self._memory_cache)
            
            return {
                'disk_files_removed': initial_disk_files - final_disk_files,
                'memory_items_removed': initial_memory_items - final_memory_items
            }

# Instance globale
cache = CacheManager()