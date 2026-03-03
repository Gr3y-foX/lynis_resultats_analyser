# Lynis Audit Analyzer

**Local · Private · Automated** — one command to run Lynis, analyse the results, and get exact fix commands.

No web server. No uploads. No network calls. All data stays on your machine.

## Quick Start (Two-Phase Workflow)

```bash
# Phase 1: Run Lynis audit (one-time setup)
sudo lynis audit system

# Phase 2: Analyze results instantly
python3 lynis_audit.py --both
```

That's it. The tool will:
1. Load `~/lynis-report.dat` automatically
2. Show your security score + risk level
3. Display review and fix commands

## Usage Modes

| Command | What it does |
|---------|-------------|
| `python3 lynis_audit.py --both` | Review + fix commands (default) |
| `python3 lynis_audit.py --review` | Full security report |
| `python3 lynis_audit.py --fix` | Fix commands only |
| `python3 lynis_audit.py --report FILE` | Analyze specific .dat file |
| `python3 lynis_audit.py --history` | Show previous scans |
| `sudo python3 lynis_audit.py --run --both` | Legacy: Run Lynis + analyze (slow) |

## Install Lynis

```bash
# Debian / Ubuntu
sudo apt install lynis

# RHEL / CentOS
sudo yum install lynis

# macOS
brew install lynis
```

## Project Structure

```
lynis_audit.py       ← single entry point  (sudo python3 lynis_audit.py)
src/
  runner.py          ← runs Lynis subprocess, detects install
  parser.py          ← parses /var/log/lynis-report.dat
  analyzer.py        ← risk scoring, category grouping
  recommender.py     ← per-test-ID fix database (SSH, Firewall, Kernel…)
  display.py         ← rich terminal UI (no browser needed)
  storage.py         ← local secure storage (chmod 600 files)
config/
  settings.yaml      ← risk thresholds, custom rules
data/
  reports/           ← saved scans (chmod 700 dir, chmod 600 files)
```

## Security & Privacy

- `data/reports/` is created with `chmod 700` (owner-only access)
- Each report JSON is saved as `chmod 600`
- Zero network requests — all processing is local
- No temp files left in `/tmp`

## Adding Custom Fix Recipes

Edit `src/recommender.py` and add entries to `_FIX_DB`:

```python
"SSH-XXXX": {
    "why": "One sentence explaining the risk.",
    "cmds": [
        "command-to-run",
        "another-command",
    ],
},
```
