from typing import Dict, List
from datetime import datetime, timedelta


class SecurityAnalyzer:
    """Analyse parsed Lynis findings and produce a structured report."""

    # Weight used to compute a weighted risk score
    _WEIGHT = {"high": 7, "medium": 4, "low": 1}

    def analyze(self, parsed: Dict) -> Dict:
        """
        Main entry point.  `parsed` is the dict returned by LynisReportParser.
        Returns a ready-to-use analysis dict.
        """
        meta      = parsed.get("metadata", {})
        warnings  = parsed.get("warnings", [])
        suggestions = parsed.get("suggestions", [])
        findings  = parsed.get("findings", [])

        # Prefer the hardening_index from Lynis itself (0-100)
        lynis_hi = meta.get("hardening_index", 0)

        category_map = self._group_by_category(findings)
        severity_counts = self._count_severity(findings)
        score = self._compute_score(lynis_hi, severity_counts, len(findings))
        risk  = self._risk_level(score)
        deadline_map = {"high": "24 h", "medium": "7 days", "low": "30 days"}

        return {
            "meta": meta,
            "score": score,
            "risk": risk,
            "total_findings": len(findings),
            "warnings_count": len(warnings),
            "suggestions_count": len(suggestions),
            "severity_counts": severity_counts,
            "category_map": category_map,
            "deadline_map": deadline_map,
            "top_categories": self._top_categories(category_map, n=5),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _group_by_category(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        groups: Dict[str, List[Dict]] = {}
        for f in findings:
            cat = f.get("category", "Other")
            groups.setdefault(cat, []).append(f)
        return dict(sorted(groups.items()))

    def _count_severity(self, findings: List[Dict]) -> Dict[str, int]:
        counts: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _compute_score(self, lynis_hi: int, severity_counts: Dict, total: int) -> int:
        """
        If Lynis produced a hardening_index, use it directly.
        Otherwise estimate from findings.
        """
        if lynis_hi and lynis_hi > 0:
            return lynis_hi

        if total == 0:
            return 100

        penalty = (
            severity_counts.get("high", 0) * 5 +
            severity_counts.get("medium", 0) * 2 +
            severity_counts.get("low", 0) * 1
        )
        return max(0, 100 - penalty)

    def _risk_level(self, score: int) -> str:
        if score >= 75:
            return "low"
        elif score >= 55:
            return "medium"
        elif score >= 35:
            return "high"
        else:
            return "critical"

    def _top_categories(self, category_map: Dict, n: int = 5) -> List[tuple]:
        return sorted(
            [(cat, len(items)) for cat, items in category_map.items()],
            key=lambda x: x[1],
            reverse=True,
        )[:n]
