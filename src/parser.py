import re
from datetime import datetime
from typing import Dict, List, Optional


SEVERITY_MAP = {
    "warning": "high",
    "suggestion": "medium",
}

# Map Lynis test-ID prefixes to human-readable category names
CATEGORY_MAP = {
    "AUTH": "Authentication",
    "BOOT": "Boot",
    "CONT": "Containers",
    "CRYP": "Cryptography",
    "DBS" : "Databases",
    "FILE": "File Systems",
    "FIRE": "Firewall",
    "HOME": "Home Directories",
    "HTTP": "Web Server",
    "INSE": "Insecure Services",
    "KRNL": "Kernel",
    "LOGG": "Logging",
    "MAIL": "Mail",
    "MALW": "Malware",
    "NAME": "DNS",
    "NET" : "Networking",
    "NFS" : "NFS",
    "PKGS": "Packages",
    "PRNT": "Printing",
    "PROC": "Processes",
    "SCHD": "Scheduled Tasks",
    "SHLL": "Shells",
    "SNMP": "SNMP",
    "SSH" : "SSH",
    "STRG": "Storage",
    "TIME": "Time",
    "TOOL": "Security Tools",
    "USB" : "USB",
    "ACCT": "Accounting",
    "BANN": "Banners",
    "CRON": "Cron",
    "FINT": "File Integrity",
    "HRDN": "Hardening",
    "LYNI": "Lynis",
    "MACF": "MAC Framework",
    "MTDT": "Metadata",
    "NGIN": "Nginx",
    "RSYS": "Rsyslog",
    "SSHD": "SSH Daemon",
    "SUDO": "Sudo",
    "SYSC": "Syscalls",
    "USNG": "USB Guard",
}


def _category_from_id(test_id: str) -> str:
    prefix = test_id[:4].upper()
    prefix3 = test_id[:3].upper()
    return CATEGORY_MAP.get(prefix) or CATEGORY_MAP.get(prefix3) or test_id.split("-")[0]


class LynisReportParser:
    """Parse Lynis .dat report files produced by `lynis audit system`."""

    def parse_content(self, content: str) -> Dict:
        """Parse raw .dat content string."""
        return self._parse_dat_format(content)

    def parse_report_file(self, file_path: str) -> Dict:
        """Read and parse a Lynis .dat file."""
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return self._parse_dat_format(content)

    # ------------------------------------------------------------------
    # Core parser
    # ------------------------------------------------------------------

    def _parse_dat_format(self, content: str) -> Dict:
        """
        Lynis .dat is a flat key=value file.  The important entries are:

          warning[]=TEST-ID|description|additional detail|
          suggestion[]=TEST-ID|description|additional detail|
          hardening_index=68
          hostname=myserver
          lynis_version=3.0.8
          report_datetime_start=2024-01-15 14:30:00
        """
        metadata: Dict = {}
        warnings: List[Dict] = []
        suggestions: List[Dict] = []
        kv: Dict = {}  # all other key-value pairs

        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            if key == "warning[]":
                w = self._parse_pipe_entry(value, "warning")
                if w:
                    warnings.append(w)
            elif key == "suggestion[]":
                s = self._parse_pipe_entry(value, "suggestion")
                if s:
                    suggestions.append(s)
            else:
                kv[key] = value

        # Build metadata
        metadata["lynis_version"]  = kv.get("lynis_version", "unknown")
        metadata["hostname"]       = kv.get("hostname", "unknown")
        metadata["scan_date"]      = kv.get("report_datetime_start",
                                             kv.get("report_datetime_end", "unknown"))
        metadata["os"]             = kv.get("os", kv.get("os_name", "unknown"))
        metadata["os_version"]     = kv.get("os_version", "unknown")
        metadata["kernel_version"] = kv.get("kernel_version", "unknown")
        metadata["hardening_index"]= int(kv.get("hardening_index", 0))
        metadata["lynis_tests_done"] = int(kv.get("lynis_tests_done", 0))

        all_findings = warnings + suggestions

        return {
            "metadata": metadata,
            "warnings": warnings,
            "suggestions": suggestions,
            "findings": all_findings,
            "total_findings": len(all_findings),
            "parsed_at": datetime.now().isoformat(),
        }

    def _parse_pipe_entry(self, value: str, kind: str) -> Optional[Dict]:
        """
        Parse a pipe-delimited Lynis entry:
          TEST-ID|description|additional detail|
        """
        parts = [p.strip() for p in value.split("|")]
        # Drop trailing empty part
        while parts and parts[-1] == "":
            parts.pop()

        if not parts:
            return None

        test_id     = parts[0] if len(parts) > 0 else "UNKNOWN"
        description = parts[1] if len(parts) > 1 else "No description"
        detail      = parts[2] if len(parts) > 2 else ""
        solution    = parts[3] if len(parts) > 3 else ""

        return {
            "id":          test_id,
            "type":        kind,
            "category":    _category_from_id(test_id),
            "description": description,
            "detail":      detail,
            "solution":    solution,
            "severity":    SEVERITY_MAP.get(kind, "low"),
        }
