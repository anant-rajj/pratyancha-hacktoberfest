import argparse
import json
import sys
from pathlib import Path
from veripack.analyzer import compare_trees, analyze_paths
from veripack.fetcher import download_npm_tarball, download_pypi_archive


def print_colored_report(report: dict):
    verdict = report.get("verdict", "UNKNOWN")
    risk = report.get("risk_score", 0)
    summary = report.get("summary", {})

    color = "\033[92m" if verdict == "VERIFIED_CLEAN" else "\033[91m"
    reset = "\033[0m"
    bold = "\033[1m"

    print(f"\n{bold}======================= VERIPACK INTEGRITY AUDIT ======================={reset}")
    print(f"Verdict: {color}{bold}{verdict}{reset}  |  Risk Score: {bold}{risk}/100{reset}")
    print(f"Summary: {summary.get('suspicious_findings', 0)} suspicious, {summary.get('expected_build_artifacts', 0)} expected, {summary.get('identical_files', 0)} exact matches")
    print("------------------------------------------------------------------------")

    for f in report.get("findings", []):
        status = f.get("status")
        tag_color = "\033[92m" if status in ("IDENTICAL", "EXPECTED") else "\033[91m"
        print(f"{tag_color}[{status}]{reset} {bold}{f.get('file')}{reset}")
        print(f"  Category:    {f.get('category')}")
        print(f"  Explanation: {f.get('explanation')}")
        if "evidence" in f and f["evidence"]:
            print(f"  Evidence:    {json.dumps(f['evidence'])}")
        print()
    print(f"{bold}========================================================================{reset}\n")


def main():
    parser = argparse.ArgumentParser(
        prog="veripack",
        description="VeriPack: Published Package vs Source Code Integrity Analyzer"
    )
    parser.add_argument("--source", help="Path to local source directory or repo")
    parser.add_argument("--package", help="Path to published package (.tgz, .whl, or directory)")
    parser.add_argument("--npm", help="Fetch and analyze an npm package by name/version (e.g. chalk@5.3.0)")
    parser.add_argument("--pypi", help="Fetch and analyze a PyPI package by name/version (e.g. requests==2.31.0)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of human report")
    parser.add_argument("--output", help="Write JSON report to a destination file")
    parser.add_argument("--self-test", action="store_true", help="Run built-in benchmark covering all 3 hackathon slide cases")

    args = parser.parse_args()

    if args.self_test:
        from veripack.analyzer import run_benchmark
        report = run_benchmark()
    elif args.source and (args.package or args.npm or args.pypi):
        pkg_path = args.package
        if args.npm:
            print(f"[*] Fetching npm package: {args.npm} ...", file=sys.stderr)
            pkg_path = download_npm_tarball(args.npm)
        elif args.pypi:
            print(f"[*] Fetching PyPI package: {args.pypi} ...", file=sys.stderr)
            pkg_path = download_pypi_archive(args.pypi)

        report = analyze_paths(args.source, pkg_path)
    else:
        parser.print_help()
        sys.exit(1)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_colored_report(report)


if __name__ == "__main__":
    main()
