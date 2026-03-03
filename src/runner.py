import os
import sys
import subprocess
import shutil
from typing import Optional, Tuple

def get_default_report_path():
    """Get the default Lynis report path based on OS."""
    if os.name == 'posix':
        home = os.path.expanduser('~')
        # On macOS, Lynis uses user home directory
        if sys.platform == 'darwin':
            return f"{home}/lynis-report.dat"
        # On Linux, uses /var/log
        return "/var/log/lynis-report.dat"
    return "/var/log/lynis-report.dat"

def get_default_log_path():
    """Get the default Lynis log path based on OS."""
    if os.name == 'posix':
        home = os.path.expanduser('~')
        # On macOS, Lynis uses user home directory  
        if sys.platform == 'darwin':
            return f"{home}/lynis.log"
        # On Linux, uses /var/log
        return "/var/log/lynis.log"
    return "/var/log/lynis.log"

LYNIS_REPORT_PATH = get_default_report_path()
LYNIS_LOG_PATH = get_default_log_path()


def check_root() -> bool:
    """Check if script is running as root."""
    return os.geteuid() == 0


def find_lynis() -> Optional[str]:
    """Locate lynis binary on the system."""
    # Common install locations
    locations = [
        shutil.which("lynis"),
        "/usr/bin/lynis",
        "/usr/local/bin/lynis",
        "/usr/sbin/lynis",
        "/opt/lynis/lynis",
    ]
    for path in locations:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def get_lynis_version(lynis_bin: str) -> Optional[str]:
    """Get the installed Lynis version."""
    try:
        result = subprocess.run(
            [lynis_bin, "--version"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip() or result.stderr.strip()
        for line in output.splitlines():
            if line.strip().isdigit() or "." in line:
                return line.strip()
        return output.split()[-1] if output else None
    except Exception:
        return None


def fix_lynis_permissions(lynis_bin: str) -> bool:
    """Fix common Lynis permission issues automatically."""
    fixed = False
    
    if sys.platform == 'darwin' and '/usr/local/Cellar/lynis' in lynis_bin:
        try:
            result = subprocess.run(['sudo', 'chown', '-R', '0:0', '/usr/local/Cellar/lynis'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                fixed = True
        except Exception:
            pass
    
    return fixed


def run_lynis_audit(lynis_bin: str, progress_callback=None) -> Tuple[bool, str]:
    """
    Run `lynis audit system` and stream output.
    Returns (success, error_message).
    """
    # Auto-fix permissions
    if fix_lynis_permissions(lynis_bin):
        if progress_callback:
            progress_callback("✓ Fixed Lynis permissions for Homebrew installation")
    
    cmd = [lynis_bin, "audit", "system", "--quiet"]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,  # Add stdin for automated responses
            text=True,
            bufsize=1,
        )

        lines_seen = 0
        for line in process.stdout:
            lines_seen += 1
            if progress_callback:
                progress_callback(line.rstrip())
            
            # Auto-respond to security prompts
            if "pressing ENTER" in line.lower() or "option 1" in line.lower():
                process.stdin.write("\n")
                process.stdin.flush()

        process.wait()

        if process.returncode not in (0, 1):
            stderr = process.stderr.read()
            return False, f"Lynis exited with code {process.returncode}: {stderr}"

        if not os.path.isfile(LYNIS_REPORT_PATH):
            return False, f"Lynis finished but report not found at {LYNIS_REPORT_PATH}"

        return True, ""

    except FileNotFoundError:
        return False, f"Lynis binary not found at {lynis_bin}"
    except PermissionError:
        return False, "Permission denied. Run with sudo."
    except subprocess.TimeoutExpired:
        return False, "Lynis audit timed out."
    except Exception as e:
        return False, str(e)


def read_report_file(path: str = LYNIS_REPORT_PATH) -> Optional[str]:
    """Read the Lynis report .dat file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except PermissionError:
        return None
    except FileNotFoundError:
        return None


def install_instructions() -> str:
    """Return platform-appropriate Lynis install instructions."""
    return (
        "Lynis is not installed or not found in PATH.\n\n"
        "Install it with:\n"
        "  Debian/Ubuntu : sudo apt install lynis\n"
        "  RHEL/CentOS   : sudo yum install lynis\n"
        "  Fedora        : sudo dnf install lynis\n"
        "  Arch Linux    : sudo pacman -S lynis\n"
        "  macOS         : brew install lynis\n"
        "  Manual        : https://cisofy.com/lynis/\n"
    )
