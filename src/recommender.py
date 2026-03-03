from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Fix database: maps Lynis test IDs (or ID prefixes) to fix recipes.
# Each recipe has:
#   why    – one-sentence explanation of the risk
#   cmds   – list of shell commands (strings) to copy-paste
# ---------------------------------------------------------------------------
_FIX_DB: Dict[str, Dict] = {
    # ── SSH ────────────────────────────────────────────────────────────────
    "SSH-7408": {
        "why": "SSH with weak settings (root login / passwords) enables brute-force attacks.",
        "cmds": [
            "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak",
            "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
            "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
            "sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config",
            "sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config",
            "echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config",
            "systemctl restart sshd",
        ],
    },
    "SSH-7412": {
        "why": "SSH protocol version 1 has critical cryptographic weaknesses.",
        "cmds": [
            "sed -i 's/^#*Protocol.*/Protocol 2/' /etc/ssh/sshd_config",
            "systemctl restart sshd",
        ],
    },
    "SSH-7440": {
        "why": "SSH AllowTcpForwarding can be abused to tunnel unwanted traffic.",
        "cmds": [
            "echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config",
            "systemctl restart sshd",
        ],
    },
    # ── Authentication / PAM ───────────────────────────────────────────────
    "AUTH-9262": {
        "why": "No PAM brute-force protection lets attackers try unlimited passwords.",
        "cmds": [
            "apt-get install -y libpam-faillock  # Debian/Ubuntu",
            "# RHEL/CentOS: yum install -y pam",
            "echo 'auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900' >> /etc/pam.d/common-auth",
            "echo 'auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' >> /etc/pam.d/common-auth",
        ],
    },
    "AUTH-9286": {
        "why": "Passwords without expiry stay valid indefinitely, increasing exposure.",
        "cmds": [
            "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs",
            "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'  /etc/login.defs",
            "sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs",
        ],
    },
    "AUTH-9328": {
        "why": "Weak password hashing (MD5/SHA-1) is easily cracked offline.",
        "cmds": [
            "sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs",
        ],
    },
    # ── Firewall ───────────────────────────────────────────────────────────
    "FIRE-4502": {
        "why": "No active firewall means all ports are reachable from the network.",
        "cmds": [
            "apt-get install -y ufw   # Debian/Ubuntu",
            "# RHEL: systemctl enable --now firewalld",
            "ufw default deny incoming",
            "ufw default allow outgoing",
            "ufw allow ssh",
            "ufw --force enable",
        ],
    },
    "FIRE-4508": {
        "why": "An empty iptables ruleset provides no actual network protection.",
        "cmds": [
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables-save > /etc/iptables/rules.v4",
        ],
    },
    # ── Kernel / sysctl ────────────────────────────────────────────────────
    "KRNL-5820": {
        "why": "Unrestricted dmesg access leaks kernel addresses useful to attackers.",
        "cmds": [
            "echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.d/99-hardening.conf",
            "sysctl -p /etc/sysctl.d/99-hardening.conf",
        ],
    },
    "KRNL-6000": {
        "why": "Kernel parameter weaknesses enable network-based attacks (redirects, spoofing).",
        "cmds": [
            "cat >> /etc/sysctl.d/99-hardening.conf << 'EOF'",
            "net.ipv4.conf.all.accept_redirects = 0",
            "net.ipv4.conf.default.accept_redirects = 0",
            "net.ipv4.conf.all.send_redirects = 0",
            "net.ipv4.conf.all.accept_source_route = 0",
            "net.ipv4.conf.all.log_martians = 1",
            "net.ipv4.icmp_echo_ignore_broadcasts = 1",
            "net.ipv4.conf.all.rp_filter = 1",
            "kernel.randomize_va_space = 2",
            "EOF",
            "sysctl -p /etc/sysctl.d/99-hardening.conf",
        ],
    },
    # ── File system / permissions ──────────────────────────────────────────
    "FILE-6310": {
        "why": "World-writable files allow any user to modify critical data.",
        "cmds": [
            "find / -xdev -type f -perm -0002 -ls 2>/dev/null",
            "# Review output and for each file: chmod o-w <file>",
        ],
    },
    "FILE-6374": {
        "why": "Sticky bit missing on /tmp lets users delete other users' files.",
        "cmds": [
            "chmod +t /tmp",
            "chmod +t /var/tmp",
        ],
    },
    "FILE-7524": {
        "why": "/tmp is not on a separate mount, so it can fill the root filesystem.",
        "cmds": [
            "# Add to /etc/fstab:",
            "echo 'tmpfs  /tmp  tmpfs  defaults,noexec,nosuid,nodev,size=512M  0  0' >> /etc/fstab",
            "mount -o remount /tmp",
        ],
    },
    # ── Logging / Auditing ─────────────────────────────────────────────────
    "LOGG-2190": {
        "why": "Without auditd, privileged actions leave no forensic trail.",
        "cmds": [
            "apt-get install -y auditd audispd-plugins   # Debian/Ubuntu",
            "# RHEL: yum install -y audit",
            "systemctl enable --now auditd",
            "auditctl -w /etc/passwd -p wa -k identity",
            "auditctl -w /etc/sudoers -p wa -k sudoers",
            "auditctl -a always,exit -F arch=b64 -S execve -k exec",
        ],
    },
    "LOGG-2154": {
        "why": "syslog not running means system events are silently dropped.",
        "cmds": [
            "apt-get install -y rsyslog",
            "systemctl enable --now rsyslog",
        ],
    },
    # ── Packages / Updates ─────────────────────────────────────────────────
    "PKGS-7392": {
        "why": "Outdated packages contain publicly known, exploitable vulnerabilities.",
        "cmds": [
            "apt-get update && apt-get upgrade -y",
            "# Or: yum update -y",
        ],
    },
    "PKGS-7394": {
        "why": "Automatic security updates ensure patches are applied without delay.",
        "cmds": [
            "apt-get install -y unattended-upgrades",
            "dpkg-reconfigure -plow unattended-upgrades",
            "echo 'Unattended-Upgrade::Automatic-Reboot \"false\";' >> /etc/apt/apt.conf.d/50unattended-upgrades",
        ],
    },
    # ── Malware / Integrity ────────────────────────────────────────────────
    "MALW-3280": {
        "why": "No malware scanner means infections go undetected.",
        "cmds": [
            "apt-get install -y clamav clamav-daemon",
            "freshclam",
            "systemctl enable --now clamav-daemon",
            "clamscan -r /home /tmp /var/www 2>/dev/null",
        ],
    },
    "FINT-4350": {
        "why": "Without file integrity monitoring, unauthorized changes go unnoticed.",
        "cmds": [
            "apt-get install -y aide",
            "aideinit",
            "mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db",
            "echo '0 5 * * * root aide --check' >> /etc/cron.d/aide",
        ],
    },
    # ── Banners / Info disclosure ──────────────────────────────────────────
    "BANN-7126": {
        "why": "A login banner is required by many compliance frameworks (CIS, NIST).",
        "cmds": [
            "echo 'Authorized use only. All activity may be monitored.' > /etc/issue",
            "echo 'Authorized use only. All activity may be monitored.' > /etc/issue.net",
            "echo 'Banner /etc/issue.net' >> /etc/ssh/sshd_config",
            "systemctl restart sshd",
        ],
    },
    # ── Boot / GRUB ────────────────────────────────────────────────────────
    "BOOT-5122": {
        "why": "No boot loader password allows anyone with physical access to change boot params.",
        "cmds": [
            "grub-mkpasswd-pbkdf2  # Copy the hash",
            "echo 'set superusers=\"root\"' >> /etc/grub.d/40_custom",
            "echo 'password_pbkdf2 root <PASTE_HASH_HERE>' >> /etc/grub.d/40_custom",
            "update-grub",
        ],
    },
    # ── Sudo ───────────────────────────────────────────────────────────────
    "SUDO-0010": {
        "why": "Sudo without logging makes it impossible to audit privileged command execution.",
        "cmds": [
            "echo 'Defaults  log_output' >> /etc/sudoers.d/99-logging",
            "echo 'Defaults  logfile=/var/log/sudo.log' >> /etc/sudoers.d/99-logging",
            "chmod 440 /etc/sudoers.d/99-logging",
        ],
    },
    # ── MAC Framework ─────────────────────────────────────────────────────
    "MACF-6208": {
        "why": "Without SELinux/AppArmor, a compromised process has unconstrained OS access.",
        "cmds": [
            "# AppArmor (Debian/Ubuntu):",
            "apt-get install -y apparmor apparmor-utils",
            "systemctl enable --now apparmor",
            "aa-enforce /etc/apparmor.d/*",
            "# OR SELinux (RHEL/CentOS): setenforce 1 && sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
        ],
    },
}

# Fallback rules keyed on category (partial match of test-ID prefix)
_CATEGORY_FALLBACK: Dict[str, Dict] = {
    "SSH": {
        "why": "Insecure SSH settings expose the server to remote attacks.",
        "cmds": [
            "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak",
            "# Edit /etc/ssh/sshd_config — set PermitRootLogin no, PasswordAuthentication no",
            "systemctl restart sshd",
        ],
    },
    "AUTH": {
        "why": "Weak authentication settings allow credential-based attacks.",
        "cmds": [
            "# Review /etc/login.defs and /etc/pam.d/ for weak settings",
            "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs",
        ],
    },
    "FIRE": {
        "why": "Missing or incomplete firewall rules expose open ports to attackers.",
        "cmds": [
            "ufw default deny incoming && ufw default allow outgoing && ufw allow ssh && ufw --force enable",
        ],
    },
    "KRNL": {
        "why": "Unsafe kernel parameters enable network attacks and information leaks.",
        "cmds": [
            "# Add hardening params to /etc/sysctl.d/99-hardening.conf then: sysctl -p",
        ],
    },
    "LOGG": {
        "why": "Insufficient logging hinders incident detection and forensic investigation.",
        "cmds": [
            "systemctl enable --now auditd rsyslog",
        ],
    },
    "PKGS": {
        "why": "Unpatched packages expose the system to known CVEs.",
        "cmds": [
            "apt-get update && apt-get upgrade -y",
        ],
    },
    "FILE": {
        "why": "Incorrect file permissions allow unauthorized access or modification.",
        "cmds": [
            "find / -xdev -type f -perm -0002 -ls 2>/dev/null  # review and fix world-writable files",
        ],
    },
}


class RecommendationEngine:
    """Map each Lynis finding to a specific fix with a short explanation."""

    def enrich(self, findings: List[Dict]) -> List[Dict]:
        """
        Add 'fix' key to each finding dict.
        Returns findings sorted: warnings (high) first, then suggestions.
        """
        enriched = []
        for f in findings:
            fix = self._lookup(f.get("id", ""), f.get("category", ""))
            enriched.append({**f, "fix": fix})

        # Sort: high severity first, then by id
        enriched.sort(key=lambda x: (0 if x.get("severity") == "high" else 1, x.get("id", "")))
        return enriched

    def _lookup(self, test_id: str, category: str) -> Optional[Dict]:
        """Return a fix recipe by exact test_id, then category prefix fallback."""
        if test_id in _FIX_DB:
            return _FIX_DB[test_id]
        # Try category fallback
        for prefix, recipe in _CATEGORY_FALLBACK.items():
            if test_id.startswith(prefix) or category.upper().startswith(prefix):
                return recipe
        return None
