"""
Local secure storage for scan results.
- Stores JSON files under data/reports/
- Directory: chmod 700 (owner-only)
- Files: chmod 600 (owner-read-write only)
- No network access, no temp files left in /tmp
"""

import os
import json
import stat
from datetime import datetime
from typing import Dict, List, Optional


REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "reports")


def _ensure_dir():
    """Create the reports directory with secure permissions if it doesn't exist."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    # chmod 700: only owner can read/write/execute
    os.chmod(REPORTS_DIR, stat.S_IRWXU)


def save_scan(analysis: Dict, enriched_findings: List[Dict]) -> str:
    """
    Persist a scan result to disk.
    Returns the filepath of the saved file.
    """
    _ensure_dir()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname  = analysis.get("meta", {}).get("hostname", "host")
    filename  = f"scan_{timestamp}_{hostname}.json"
    filepath  = os.path.join(REPORTS_DIR, filename)

    payload = {
        "saved_at":   datetime.now().isoformat(),
        "meta":       analysis.get("meta", {}),
        "score":      analysis.get("score"),
        "risk":       analysis.get("risk"),
        "total_findings":    analysis.get("total_findings"),
        "warnings_count":    analysis.get("warnings_count"),
        "suggestions_count": analysis.get("suggestions_count"),
        "severity_counts":   analysis.get("severity_counts"),
        "top_categories":    analysis.get("top_categories"),
        "findings":          enriched_findings,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)

    # chmod 600: owner read/write only
    os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)

    return filepath


def load_all_scans() -> List[Dict]:
    """
    Load all saved scan summaries (metadata only, no findings list)
    sorted by scan date ascending.
    """
    if not os.path.isdir(REPORTS_DIR):
        return []

    scans = []
    for fname in sorted(os.listdir(REPORTS_DIR)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(REPORTS_DIR, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            scans.append({
                "filename":          fname,
                "filepath":          fpath,
                "meta":              data.get("meta", {}),
                "score":             data.get("score"),
                "risk":              data.get("risk"),
                "total_findings":    data.get("total_findings"),
                "warnings_count":    data.get("warnings_count"),
                "suggestions_count": data.get("suggestions_count"),
                "saved_at":          data.get("saved_at"),
            })
        except Exception:
            continue

    return scans


def load_scan(filepath: str) -> Optional[Dict]:
    """Load a full scan result including findings."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def report_dir_info() -> Dict:
    """Return info about the reports directory."""
    if not os.path.isdir(REPORTS_DIR):
        return {"exists": False, "path": REPORTS_DIR, "count": 0}

    count = sum(1 for f in os.listdir(REPORTS_DIR) if f.endswith(".json"))
    return {
        "exists": True,
        "path":   REPORTS_DIR,
        "count":  count,
    }
