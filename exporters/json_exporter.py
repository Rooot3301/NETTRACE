"""
NetTrace v2 - JSON Exporter
Exports full analysis results to pretty-printed JSON.
"""
import json
from typing import Dict, Any


def export_json(results: Dict[str, Any], filename: str) -> bool:
    """
    Export full analysis results to a JSON file.

    Args:
        results: complete analysis results dict
        filename: output file path

    Returns:
        True on success, False on failure
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str, ensure_ascii=False)
        return True
    except (OSError, TypeError, ValueError):
        return False
