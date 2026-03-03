# Enterprise macOS Security Hardening Commands
## Generated: 2026-03-03 | System: unknown-2 | Score: 74/100 (Medium Risk)

### 🚨 Critical Priority Fixes
```bash
# 1. Install brute-force protection for authentication
brew install pam_faillock 2>/dev/null || echo "Manual PAM configuration required"
sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.backup
sudo tee -a /etc/pam.d/sshd << 'EOF'
auth       required     pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth       [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
EOF

# 2. Enable system auditing for forensic tracking
sudo brew install auditd 2>/dev/null || echo "auditd may require manual installation"
sudo launchctl enable system/com.apple.auditd
sudo launchctl start system/com.apple.auditd
sudo auditctl -w /etc/passwd -p wa -k identity
sudo auditctl -w /etc/sudoers -p wa -k sudoers
```

### 🔒 File System Security
```bash
# 3. Find and fix world-writable files
find / -xdev -type f -perm -0002 -ls 2>/dev/null | head -20
# Review output and fix each: sudo chmod o-w <file>

# 4. Secure /tmp directory
echo 'tmpfs  /tmp  tmpfs  defaults,noexec,nosuid,nodev,size=512M  0  0' | sudo tee -a /etc/fstab
sudo mount -o remount /tmp

# 5. Check symlinked mount points (/home, /tmp, /var)
ls -la /home /tmp /var
# Manual review required for each symlink
```

### 🛡️ System Hardening
```bash
# 6. Install malware scanner
brew install rkhunter chkrootkit
sudo rkhunter --update
sudo rkhunter --checkall

# 7. Restrict compiler access to root only
sudo chmod 750 /usr/bin/gcc
sudo chmod 750 /usr/bin/clang
sudo chmod 750 /usr/bin/cc

# 8. Update all packages (Homebrew)
brew update && brew upgrade
```

### 🌐 Network & DNS
```bash
# 9. Clean up /etc/hosts
sudo cp /etc/hosts /etc/hosts.backup
sudo awk '!seen[$0]++' /etc/hosts.backup | sudo tee /etc/hosts

# 10. Add proper FQDN to hosts
echo "127.0.0.1 $(hostname).local $(hostname)" | sudo tee -a /etc/hosts
```

### 🏢 Enterprise Web Server (if Apache installed)
```bash
# 11. Install Apache security modules
brew install apache2
sudo apachectl stop
# Note: mod_evasive and mod_security may require manual compilation on macOS
```

### 📊 Verification Commands
```bash
# Verify audit status
sudo auditctl -l

# Check malware scanner
sudo rkhunter --versioncheck

# Verify file permissions
find / -xdev -type f -perm -0002 2>/dev/null | wc -l

# Check hardening index (run Lynis again)
sudo lynis audit system --quick
```

### 📋 Manual Review Required
- [ ] HOME-9304: Review home directory permissions
- [ ] HRDN-7222: Confirm compiler access restrictions
- [ ] HRDN-7230: Schedule regular malware scans
- [ ] HTTP-6640/HTTP-6643: Web server hardening (if applicable)

### 🔄 Ongoing Maintenance
```bash
# Weekly security updates
brew update && brew upgrade

# Monthly malware scans
sudo rkhunter --checkall --reportfile /var/log/rkhunter_$(date +%Y%m).log

# Quarterly Lynis audit
sudo lynis audit system
```

---
**Next Steps:**
1. Execute commands in priority order
2. Document any deviations or issues
3. Schedule regular security scans
4. Update security policies based on findings
