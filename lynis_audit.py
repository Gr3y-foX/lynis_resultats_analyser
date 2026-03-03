#!/usr/bin/env python3
"""
Lynis Audit Analyzer — single-command local security auditor.

Usage:
    # Phase 1: Run Lynis separately (recommended)
    sudo lynis audit system
    sudo python3 lynis_audit.py --report ~/lynis-report.dat --both
    
    # Phase 2: Analyze existing report
    python3 lynis_audit.py --report /path/to/lynis-report.dat --review
    python3 lynis_audit.py --report /path/to/lynis-report.dat --fix
    python3 lynis_audit.py --report /path/to/lynis-report.dat --both
    
    # Legacy: Run Lynis + analyze (slow)
    sudo python3 lynis_audit.py --run --both
    
    # History
    python3 lynis_audit.py --history

All data stays local.  No network calls.  Reports saved to data/reports/ (chmod 600).
"""

import sys
import os
import argparse

# ── Ensure project root is in the module search path ─────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from src.runner     import (check_root, find_lynis, get_lynis_version,
                             run_lynis_audit, read_report_file,
                             install_instructions, LYNIS_REPORT_PATH)
from src.parser     import LynisReportParser
from src.analyzer   import SecurityAnalyzer
from src.recommender import RecommendationEngine
from src.display    import (console, print_banner, print_run_start,
                             lynis_progress_callback, print_run_done,
                             print_summary, print_review, print_fixes,
                             print_history, print_error, print_info,
                             print_success, print_warning, prompt_mode)
from src.storage    import save_scan, load_all_scans


# ──────────────────────────────────────────────────────────────────────────────
# CLI argument parser
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lynis_audit.py",
        description="Analyze Lynis results and get fix commands — all locally.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--review",  action="store_true",
                      help="Show full report grouped by category")
    mode.add_argument("--fix",     action="store_true",
                      help="Show per-issue fix commands with explanation")
    mode.add_argument("--both",    action="store_true",
                      help="Show review then fix commands")
    mode.add_argument("--history", action="store_true",
                      help="List previous scan results (no audit run)")
    mode.add_argument("--run", action="store_true",
                      help="Run Lynis audit first, then analyze (legacy mode)")
    p.add_argument("--report", metavar="FILE",
                   help="Analyse an existing Lynis .dat file (default: ~/lynis-report.dat)")
    p.add_argument("--no-save", action="store_true",
                   help="Do not save results to data/reports/")
    return p


# ──────────────────────────────────────────────────────────────────────────────
# History sub-command
# ──────────────────────────────────────────────────────────────────────────────

def cmd_history():
    scans = load_all_scans()
    print_history(scans)


# ──────────────────────────────────────────────────────────────────────────────
# Main pipeline
# ──────────────────────────────────────────────────────────────────────────────

def run_pipeline(args: argparse.Namespace):
    """Full scan → parse → analyse → display pipeline."""

    # ── 1. Determine source of the report ────────────────────────────────────
    if args.run:
        # Legacy mode: Run Lynis live
        if not check_root():
            print_error(
                "Lynis requires root privileges.\n"
                "Re-run with: sudo python3 lynis_audit.py --run"
            )
            sys.exit(1)

        lynis_bin = find_lynis()
        if not lynis_bin:
            print_error(install_instructions())
            sys.exit(1)

        version = get_lynis_version(lynis_bin)
        print_run_start(lynis_bin, version)

        success, err = run_lynis_audit(lynis_bin, progress_callback=None)

        if not success:
            print_error(f"Lynis audit failed:\n{err}")
            sys.exit(1)

        print_run_done()
        report_path = LYNIS_REPORT_PATH
    else:
        # Use existing .dat file (default or specified)
        report_path = args.report or os.path.expanduser("~/lynis-report.dat")
        
        if not os.path.isfile(report_path):
            print_error(f"Report file not found: {report_path}")
            print_info("Run Lynis first: sudo lynis audit system")
            print_info("Then analyze: python3 lynis_audit.py --report ~/lynis-report.dat --both")
            sys.exit(1)
            
        print_info(f"Loading existing report: {report_path}")
    
    raw = read_report_file(report_path)
    if raw is None:
        print_error(f"Cannot read {report_path}. Check permissions.")
        sys.exit(1)

    # ── 2. Parse ──────────────────────────────────────────────────────────────
    parser   = LynisReportParser()
    parsed   = parser.parse_content(raw)

    # ── 3. Analyse ────────────────────────────────────────────────────────────
    analyzer = SecurityAnalyzer()
    analysis = analyzer.analyze(parsed)

    # ── 4. Enrich with fix recipes ────────────────────────────────────────────
    engine   = RecommendationEngine()
    enriched = engine.enrich(parsed.get("findings", []))

    # ── 5. Save locally ───────────────────────────────────────────────────────
    if not args.no_save:
        try:
            saved_path = save_scan(analysis, enriched)
            print_success(f"Report saved → {saved_path}")
        except Exception as e:
            print_warning(f"Could not save report: {e}")

    # ── 6. Summary (always shown) ─────────────────────────────────────────────
    print_summary(analysis)

    # ── 7. Determine output mode ──────────────────────────────────────────────
    if args.review:
        mode = "review"
    elif args.fix:
        mode = "fix"
    elif args.both:
        mode = "both"
    else:
        mode = prompt_mode()

    # ── 8. Display ────────────────────────────────────────────────────────────
    if mode in ("review", "both"):
        print_review(analysis, enriched)

    if mode in ("fix", "both"):
        print_fixes(enriched)

    if mode == "history":
        cmd_history()


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print_banner()
    args = build_parser().parse_args()

    if args.history:
        cmd_history()
        return

    run_pipeline(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Aborted.[/dim]")
        sys.exit(0)
