"""
Module 4: Command-Line Interface & Human/JSON Reporting (veripack/cli.py)

Orchestrates verification between published packages (npm, PyPI, or local archive/dir)
and upstream source trees, outputting interactive colored reports or machine-readable JSON.
"""

from __future__ import annotations
import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any

from veripack.analyzer import (
    analyze_integrity,
    run_benchmark,
)
from veripack.models import (
    Verdict,
    ScanReport,
)
from veripack.fetcher import (
    fetch_npm_package,
    fetch_pypi_package,
    fetch_upstream_source,
    safe_extract_archive,
    calculate_sha256,
)


def print_colored_report(report: dict):
    verdict = report.get("verdict", "UNKNOWN")
    risk = report.get("risk_score", 0)
    summary = report.get("summary_counts") or report.get("summary", {})

    color = "\033[92m" if verdict in ("SAFE", "VERIFIED_CLEAN") else "\033[91m"
    reset = "\033[0m"
    bold = "\033[1m"

    print(f"\n{bold}======================= VERIPACK INTEGRITY AUDIT ======================={reset}")
    print(f"Verdict: {color}{bold}{verdict}{reset}  |  Risk Score: {bold}{risk}/100{reset}")
    print(
        f"Summary: {summary.get('suspicious', 0) + summary.get('critical', 0)} suspicious, "
        f"{summary.get('expected_artifacts', 0)} expected, {summary.get('identical', 0)} exact matches"
    )
    print("------------------------------------------------------------------------")

    for f in report.get("findings", []):
        status = f.get("classification") or f.get("status")
        tag_color = "\033[92m" if status in ("IDENTICAL", "EXPECTED_BUILD_ARTIFACT", "EXPECTED") else "\033[91m"
        file_name = f.get("file_path") or f.get("file")
        print(f"{tag_color}[{status}]{reset} {bold}{file_name}{reset}")
        print(f"  Category:    {f.get('category', status)}")
        print(f"  Explanation: {f.get('explanation', '')}")
        if "evidence" in f and f["evidence"]:
            print(f"  Evidence:    {json.dumps(f['evidence'])}")
        print()
    print(f"{bold}========================================================================{reset}\n")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--archive", "--package",
        dest="package",
        default=None,
        help="Path to published package (.tgz, .whl, or extracted directory)"
    )
    common.add_argument(
        "--repo", "--source",
        dest="source",
        default=None,
        help="Path to upstream source repository or local directory"
    )
    common.add_argument("--npm", default=None, help="Fetch and analyze an npm package by spec (e.g. chalk@5.3.0)")
    common.add_argument("--pypi", default=None, help="Fetch and analyze a PyPI package by spec (e.g. requests==2.31.0)")
    common.add_argument("--json", action="store_true", help="Output machine-readable JSON report")
    common.add_argument("--output", default=None, help="Write JSON report to specified destination file")
    common.add_argument("--self-test", action="store_true", help="Run built-in benchmark self-test")
    common.add_argument("--no-llm", action="store_true", help="Disable local LLM semantic explanation engine")
    common.add_argument("--enable-llm", action="store_true", help="Enable local LLM semantic explanation engine")

    parser = argparse.ArgumentParser(
        prog="veripack",
        description="VeriPack: Published Package vs Upstream Source Code Integrity Analyzer",
        parents=[common],
    )
    subparsers = parser.add_subparsers(dest="subcommand")
    subparsers.add_parser("analyze", parents=[common], help="Analyze package against source repository")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.self_test:
        report = run_benchmark()
        report["status"] = "ok"

        if args.output:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print_colored_report(report)
        return 0

    # Ensure required arguments are provided
    if not (args.package or args.npm or args.pypi):
        parser.print_help(sys.stderr)
        return 1
    if not args.source and not (args.npm or args.pypi):
        parser.print_help(sys.stderr)
        return 1

    # Validate file path existence
    if args.package and not Path(args.package).exists():
        print(f"[-] Error: Package path does not exist: {args.package}", file=sys.stderr)
        return 1
    if args.source and not (
        args.source.startswith("http://")
        or args.source.startswith("https://")
        or args.source.startswith("git@")
        or Path(args.source).exists()
    ):
        print(f"[-] Error: Source path does not exist: {args.source}", file=sys.stderr)
        return 1

    enable_llm = args.enable_llm and not args.no_llm

    with tempfile.TemporaryDirectory(prefix="veripack_cli_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        pkg_name = None
        pkg_version = None
        eco = "npm"
        archive_sha = "manual_scan"
        prov = False

        if args.npm:
            print(f"[*] Fetching npm package: {args.npm} ...", file=sys.stderr)
            pkg_meta = fetch_npm_package(args.npm, tmp_path / "npm")
            pkg_dir = pkg_meta.extracted_path
            pkg_name = pkg_meta.name
            pkg_version = pkg_meta.version
            eco = "npm"
            archive_sha = pkg_meta.sha256
            prov = pkg_meta.has_provenance
        elif args.pypi:
            print(f"[*] Fetching PyPI package: {args.pypi} ...", file=sys.stderr)
            pkg_meta = fetch_pypi_package(args.pypi, tmp_path / "pypi")
            pkg_dir = pkg_meta.extracted_path
            pkg_name = pkg_meta.name
            pkg_version = pkg_meta.version
            eco = "pypi"
            archive_sha = pkg_meta.sha256
            prov = pkg_meta.has_provenance
        elif args.package:
            target_pkg = Path(args.package)
            if target_pkg.is_file():
                pkg_dir = safe_extract_archive(target_pkg, tmp_path / "pkg_extracted")
                archive_sha = calculate_sha256(target_pkg)
            elif target_pkg.is_dir():
                pkg_dir = target_pkg.resolve()
            else:
                print(f"[-] Error: Package path invalid: {args.package}", file=sys.stderr)
                return 1

        # Resolve upstream source
        if args.source:
            target_src = Path(args.source)
            if target_src.is_dir():
                src_dir = target_src.resolve()
            elif target_src.is_file():
                src_dir = safe_extract_archive(target_src, tmp_path / "source_extracted")
            else:
                src_meta = fetch_upstream_source(args.source, version=pkg_version or "", work_dir=tmp_path / "source")
                src_dir = src_meta.source_path
        else:
            print("[-] Error: Source repository path or URL must be provided.", file=sys.stderr)
            return 1

        # Read package metadata if not already extracted
        if not pkg_name:
            pkg_json = pkg_dir / "package.json"
            if pkg_json.is_file():
                try:
                    with open(pkg_json, "r", encoding="utf-8") as f:
                        pj = json.load(f)
                        pkg_name = pj.get("name", "package")
                        pkg_version = pj.get("version", "1.0.0")
                        eco = "npm"
                except Exception:
                    pass
        if not pkg_name:
            pkg_name = pkg_dir.name
            pkg_version = "1.0.0"

        scan_report = analyze_integrity(
            package_dir=pkg_dir,
            source_dir=src_dir,
            package_name=pkg_name,
            version=pkg_version or "1.0.0",
            ecosystem=eco,
            archive_sha256=archive_sha,
            provenance_verified=prov,
            enable_llm=enable_llm,
        )

        report = scan_report.to_dict()

        report["summary"] = {
            "suspicious_findings": scan_report.summary_counts.get("suspicious", 0) + scan_report.summary_counts.get("critical", 0),
            "expected_build_artifacts": scan_report.summary_counts.get("expected_artifacts", 0),
            "identical_files": scan_report.summary_counts.get("identical", 0),
            **scan_report.summary_counts,
        }
        report["risk_score"] = 100 if scan_report.verdict == Verdict.COMPROMISED else (75 if scan_report.verdict == Verdict.TAMPERED else 0)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_colored_report(report)

    verdict = report.get("verdict", "")
    if verdict == "SAFE":
        return 0
    elif verdict in ("TAMPERED", "COMPROMISED"):
        return 2
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())
