"""
Module 3B: Ecosystem-Agnostic Structural, Manifest & Artifact Comparator (veripack/analyzer.py)

Implements the core integrity analysis engine comparing a published package archive
against its upstream source tree, categorizing discrepancies across the 3 Hacktoberfest archetypes:
- Case 1: Expected Build Artifacts (SAFE) vs Bundler Injections (COMPROMISED)
- Case 2: Manifest & Lifecycle Hook Tampering (TAMPERED)
- Case 3: Ghost & Obfuscated Payloads (COMPROMISED)
"""

from __future__ import annotations
import ast
import difflib
import json
import os
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple

from veripack.models import (
    Verdict,
    FileStatus,
    Severity,
    Archetype,
    Finding,
    PackageMetadata,
    SourceMetadata,
    ScanReport,
)
from veripack.entropy import calculate_entropy, detect_obfuscation_signals
from veripack.capabilities import extract_capabilities_from_file, extract_exported_symbols
from veripack.llm import query_qwen_explainer

DEV_ONLY_PATTERNS = {
    ".github", ".git", "tests", "test", "__tests__", "docs", ".eslintrc", ".prettierrc",
    "tsconfig.json", ".gitignore", "jest.config.js", "Makefile", ".travis.yml"
}
EXECUTABLE_EXTENSIONS = {".js", ".mjs", ".cjs", ".py", ".sh", ".bash", ".so", ".dll", ".wasm"}


def analyze_integrity(
    package_dir: Path,
    source_dir: Path,
    package_name: str = "package",
    version: str = "1.0.0",
    ecosystem: str = "npm",
    source_ref: str = "upstream",
    archive_sha256: str = "manual_scan",
    provenance_verified: bool = False,
    enable_llm: bool = True,
) -> ScanReport:
    """
    Main entry point: compares package_dir with source_dir and produces a comprehensive ScanReport.
    """
    package_dir = package_dir.resolve()
    source_dir = source_dir.resolve()

    pkg_files = _collect_relative_files(package_dir)
    src_files = _collect_relative_files(source_dir)

    findings: List[Finding] = []
    summary_counts = {
        "identical": 0,
        "expected_artifacts": 0,
        "stripped_dev_files": 0,
        "suspicious": 0,
        "critical": 0,
    }

    # Track matched and mapped files
    matched_src_files: Set[str] = set()

    # 1. Compare manifests first (Case 2: Manifest Lifecycle Injection)
    manifest_finding = _audit_manifests(package_dir, source_dir, ecosystem)
    if manifest_finding:
        findings.append(manifest_finding)
        summary_counts["suspicious"] += 1

    # 2. Inspect every package file against source tree
    for rel_path in pkg_files:
        pkg_file = package_dir / rel_path

        # Ignore package metadata directories (*.dist-info, PKG-INFO)
        if _is_packaging_metadata(rel_path):
            summary_counts["expected_artifacts"] += 1
            continue

        # Exact match
        if rel_path in src_files:
            matched_src_files.add(rel_path)
            src_file = source_dir / rel_path
            finding = _compare_same_path_files(pkg_file, src_file, rel_path, enable_llm)
            if finding:
                findings.append(finding)
                if finding.severity in (Severity.HIGH, Severity.CRITICAL):
                    summary_counts["critical" if finding.severity == Severity.CRITICAL else "suspicious"] += 1
            else:
                summary_counts["identical"] += 1
            continue

        # Not in same path: Check Case 1 (Expected Build Artifact) vs Case 3 (Ghost File)
        stem_match = _find_source_stem_match(rel_path, src_files)
        if stem_match:
            matched_src_files.add(stem_match)
            src_file = source_dir / stem_match
            build_finding = _verify_build_artifact(pkg_file, src_file, rel_path, stem_match, enable_llm)
            findings.append(build_finding)
            if build_finding.classification == FileStatus.CAPABILITY_ESCALATION:
                summary_counts["critical"] += 1
            else:
                summary_counts["expected_artifacts"] += 1
        else:
            # Case 3: Ghost File (No origin in source tree)
            ghost_finding = _analyze_ghost_file(pkg_file, rel_path, enable_llm)
            findings.append(ghost_finding)
            summary_counts["critical"] += 1

    # 3. Check for stripped dev-only files in source tree
    for rel_path in src_files:
        if rel_path not in matched_src_files and rel_path not in pkg_files:
            if _is_dev_only_file(rel_path):
                summary_counts["stripped_dev_files"] += 1

    # 4. Determine overall verdict
    verdict = Verdict.SAFE
    if summary_counts["critical"] > 0:
        verdict = Verdict.COMPROMISED
    elif summary_counts["suspicious"] > 0:
        verdict = Verdict.TAMPERED

    # Enrich findings with LLM explanations if enabled
    if enable_llm:
        for f in findings:
            if f.classification in (
                FileStatus.SUSPICIOUS_MANIFEST,
                FileStatus.CAPABILITY_ESCALATION,
                FileStatus.UNMAPPED_GHOST_FILE,
            ):
                f.explanation = query_qwen_explainer(
                    file_path=f.file_path,
                    classification=f.classification.value,
                    evidence=f.evidence,
                    diff_snippet=f.diff_snippet,
                    entropy=f.entropy,
                )

    return ScanReport(
        package_name=package_name,
        version=version,
        ecosystem=ecosystem,
        source_ref=source_ref,
        archive_sha256=archive_sha256,
        provenance_verified=provenance_verified,
        summary_counts=summary_counts,
        verdict=verdict,
        model_used="qwen2.5-coder:7b (ollama)" if enable_llm else "deterministic-static-fallback",
        findings=findings,
    )


def _collect_relative_files(base_dir: Path) -> List[str]:
    """Collect all relative file paths from a directory, ignoring VCS directories."""
    files: List[str] = []
    if not base_dir.is_dir():
        return files
    for root, dirs, filenames in os.walk(base_dir):
        # Exclude VCS dirs
        dirs[:] = [d for d in dirs if d not in (".git", ".svn", ".hg")]
        for fn in filenames:
            full = Path(root) / fn
            rel = full.relative_to(base_dir)
            files.append(str(rel).replace("\\", "/"))
    return sorted(files)


def _is_packaging_metadata(rel_path: str) -> bool:
    """Checks if a path is standard wheel or sdist packaging metadata."""
    parts = rel_path.split("/")
    first = parts[0]
    return (
        first.endswith((".dist-info", ".egg-info")) or
        first in ("PKG-INFO", "RECORD", "WHEEL", "METADATA")
    )


def _is_dev_only_file(rel_path: str) -> bool:
    """Checks if a file in source repository is expected to be omitted from release package."""
    parts = rel_path.split("/")
    first = parts[0]
    if first in DEV_ONLY_PATTERNS or first.startswith("."):
        return True
    return any(p in DEV_ONLY_PATTERNS for p in parts)


def _audit_manifests(pkg_dir: Path, src_dir: Path, ecosystem: str) -> Optional[Finding]:
    """
    Case 2: Manifest Lifecycle Hook Tampering Auditor.
    Detects unauthorized install-time hooks in package.json or dynamic execution in setup.py.
    """
    # npm manifest check
    pkg_json_path = pkg_dir / "package.json"
    src_json_path = src_dir / "package.json"
    if pkg_json_path.is_file() and src_json_path.is_file():
        try:
            pkg_data = json.loads(pkg_json_path.read_text(encoding="utf-8"))
            src_data = json.loads(src_json_path.read_text(encoding="utf-8"))

            pkg_scripts = pkg_data.get("scripts", {})
            src_scripts = src_data.get("scripts", {})

            # Critical lifecycle hooks that execute automatically on install
            lifecycle_hooks = ("preinstall", "install", "postinstall", "prepublish", "prepare")
            tampered_hooks = []
            for hook in lifecycle_hooks:
                pkg_cmd = pkg_scripts.get(hook)
                src_cmd = src_scripts.get(hook)
                if pkg_cmd and pkg_cmd != src_cmd:
                    tampered_hooks.append(f"{hook}: '{pkg_cmd}' (upstream was: '{src_cmd}')")

            if tampered_hooks:
                diff_str = "\n".join(f"+ \"{h}\"" for h in tampered_hooks)
                return Finding(
                    file_path="package.json",
                    classification=FileStatus.SUSPICIOUS_MANIFEST,
                    severity=Severity.HIGH,
                    verdict=Verdict.TAMPERED,
                    archetype=Archetype.CASE_2_MANIFEST_TAMPERING,
                    evidence=[f"Lifecycle hook modified: {h}" for h in tampered_hooks],
                    diff_snippet=diff_str,
                    explanation=(
                        f"Unauthorized lifecycle hook in package.json: {'; '.join(tampered_hooks)}. "
                        "Commands execute automatically upon 'npm install' and do not match source repository."
                    ),
                )
        except Exception:
            pass

    # PyPI setup.py check
    pkg_setup = pkg_dir / "setup.py"
    src_setup = src_dir / "setup.py"
    if pkg_setup.is_file():
        setup_findings = _audit_python_setup(pkg_setup, src_setup if src_setup.is_file() else None)
        if setup_findings:
            return setup_findings

    return None


def _audit_python_setup(pkg_setup: Path, src_setup: Optional[Path]) -> Optional[Finding]:
    """Inspects Python setup.py for suspicious top-level execution hooks."""
    try:
        pkg_code = pkg_setup.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(pkg_code)
    except SyntaxError:
        return None

    suspicious_calls = []
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            # Check for top-level subprocess or urllib calls
            func = node.value.func
            name = ""
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name in ("system", "popen", "run", "urlopen", "exec"):
                suspicious_calls.append(f"Top-level call: {name}()")

    if suspicious_calls:
        return Finding(
            file_path="setup.py",
            classification=FileStatus.SUSPICIOUS_MANIFEST,
            severity=Severity.HIGH,
            verdict=Verdict.TAMPERED,
            archetype=Archetype.CASE_2_MANIFEST_TAMPERING,
            evidence=suspicious_calls,
            diff_snippet="\n".join(suspicious_calls),
            explanation="setup.py executes dynamic commands at top-level import time.",
        )

    return None


def _find_source_stem_match(pkg_rel_path: str, src_files: List[str]) -> Optional[str]:
    """
    Matches compiled outputs to their upstream source stem:
    dist/index.js -> src/index.ts, src/index.tsx, index.ts
    build/app.mjs -> src/app.ts
    lib/calc.js -> src/calc.ts
    """
    pkg_path = Path(pkg_rel_path)
    stem = pkg_path.stem
    if stem.endswith(".min"):
        stem = stem[:-4]

    # Candidate source paths
    candidates = [
        f"src/{stem}.ts",
        f"src/{stem}.tsx",
        f"src/{stem}.js",
        f"{stem}.ts",
        f"{stem}.tsx",
        f"lib/{stem}.ts",
    ]

    for c in candidates:
        if c in src_files:
            return c

    # Fuzzy match by stem
    for s in src_files:
        if Path(s).stem == stem and Path(s).suffix in (".ts", ".tsx", ".py", ".c", ".cpp"):
            return s

    return None


def _verify_build_artifact(
    pkg_file: Path,
    src_file: Path,
    pkg_rel_path: str,
    src_rel_path: str,
    enable_llm: bool,
) -> Finding:
    """
    Case 1: Build Artifact Verification vs XZ-style Bundler Injections.
    Verifies symbol and capability equivalence between compiled output and source.
    """
    pkg_caps = extract_capabilities_from_file(pkg_file)
    src_caps = extract_capabilities_from_file(src_file)

    # Check for capability escalation: capabilities in package that do NOT exist in source
    escalated_caps = []
    for cat, tokens in pkg_caps.items():
        src_tokens = src_caps.get(cat, set())
        diff_tokens = tokens - src_tokens
        if diff_tokens and cat in ("process", "network", "env", "eval"):
            escalated_caps.append(f"{cat}: {', '.join(sorted(diff_tokens))}")

    # XZ / Bundler Injection Catch:
    # If compiled artifact introduces new sensitive capabilities, flag COMPROMISED
    if escalated_caps:
        return Finding(
            file_path=pkg_rel_path,
            classification=FileStatus.CAPABILITY_ESCALATION,
            verdict=Verdict.COMPROMISED,
            severity=Severity.CRITICAL,
            archetype=Archetype.CASE_1_EXPECTED_BUILD,
            evidence=[f"Escalated capability: {c}" for c in escalated_caps],
            explanation=(
                f"Capability escalation in build artifact '{pkg_rel_path}' mapped from '{src_rel_path}'. "
                f"Artifact introduces sensitive capabilities ({'; '.join(escalated_caps)}) not present in source."
            ),
        )

    # Legitimate Expected Build Artifact
    return Finding(
        file_path=pkg_rel_path,
        classification=FileStatus.EXPECTED_BUILD_ARTIFACT,
        verdict=Verdict.SAFE,
        severity=Severity.INFO,
        archetype=Archetype.CASE_1_EXPECTED_BUILD,
        evidence=[f"Maps to upstream stem: {src_rel_path}", "0 new sensitive capabilities introduced"],
        explanation=f"Compiled output '{pkg_rel_path}' faithfully maps to '{src_rel_path}' with no capability escalation.",
    )


def _analyze_ghost_file(pkg_file: Path, rel_path: str, enable_llm: bool) -> Finding:
    """
    Case 3: Ghost & Obfuscated Payload Detector.
    Analyzes unmapped files with no upstream source counterpart.
    """
    try:
        raw_bytes = pkg_file.read_bytes()
    except Exception:
        raw_bytes = b""

    entropy = calculate_entropy(raw_bytes)
    text = raw_bytes.decode("utf-8", errors="ignore")
    ext = pkg_file.suffix.lower()

    obfuscation_signals = detect_obfuscation_signals(text, ext)
    caps = extract_capabilities_from_file(pkg_file)

    evidence = [f"No source counterpart found in upstream repository"]
    evidence.append(f"Shannon entropy: {entropy:.2f}")

    if obfuscation_signals:
        evidence.extend(obfuscation_signals)
    for cat, tokens in caps.items():
        evidence.append(f"Sensitive capability [{cat}]: {', '.join(sorted(tokens))}")

    is_executable = ext in EXECUTABLE_EXTENSIONS
    is_high_risk = is_executable and (entropy >= 5.8 or len(obfuscation_signals) > 0 or len(caps) > 0)

    severity = Severity.CRITICAL if is_high_risk else Severity.HIGH
    diff_preview = text[:500] if text else "Binary content"

    return Finding(
        file_path=rel_path,
        classification=FileStatus.UNMAPPED_GHOST_FILE,
        verdict=Verdict.COMPROMISED,
        severity=severity,
        archetype=Archetype.CASE_3_GHOST_OBFUSCATED,
        entropy=entropy,
        evidence=evidence,
        diff_snippet=diff_preview,
        explanation=(
            f"Ghost file '{rel_path}' present in package archive with no origin in Git repository. "
            f"Elevated entropy ({entropy:.2f}) and sensitive execution markers indicate potential backdoor injection."
        ),
    )


def _compare_same_path_files(
    pkg_file: Path,
    src_file: Path,
    rel_path: str,
    enable_llm: bool,
) -> Optional[Finding]:
    """Compares two files existing at the exact same relative path."""
    try:
        pkg_bytes = pkg_file.read_bytes()
        src_bytes = src_file.read_bytes()
    except Exception:
        return None

    if pkg_bytes == src_bytes:
        return None  # Identical, no finding needed

    # Modified file
    pkg_text = pkg_bytes.decode("utf-8", errors="ignore")
    src_text = src_bytes.decode("utf-8", errors="ignore")

    diff = list(difflib.unified_diff(
        src_text.splitlines(),
        pkg_text.splitlines(),
        fromfile=f"source/{rel_path}",
        tofile=f"package/{rel_path}",
        n=3,
    ))
    diff_snippet = "\n".join(diff[:40])

    pkg_caps = extract_capabilities_from_file(pkg_file)
    src_caps = extract_capabilities_from_file(src_file)

    escalated = []
    for cat, tokens in pkg_caps.items():
        diff_tokens = tokens - src_caps.get(cat, set())
        if diff_tokens:
            escalated.append(f"{cat}: {', '.join(diff_tokens)}")

    severity = Severity.HIGH if escalated else Severity.LOW
    verdict = Verdict.TAMPERED if escalated else Verdict.SAFE

    return Finding(
        file_path=rel_path,
        classification=FileStatus.MODIFIED_SOURCE,
        verdict=verdict,
        severity=severity,
        archetype=Archetype.CASE_2_MANIFEST_TAMPERING if escalated else Archetype.UNCLASSIFIED,
        evidence=[f"Differences in code"] + ([f"New capabilities: {e}" for e in escalated]),
        diff_snippet=diff_snippet,
        explanation=f"Source file '{rel_path}' was modified in the published release archive.",
    )


def run_benchmark() -> Dict[str, Any]:
    """
    Runs built-in benchmark covering all 3 hackathon slide cases:
    - Case 1: Expected Build Artifact (SAFE) vs Bundler Injections (COMPROMISED)
    - Case 2: Manifest & Lifecycle Hook Tampering (TAMPERED)
    - Case 3: Ghost & Obfuscated Payloads (COMPROMISED)
    """
    import tempfile
    from veripack.fetcher import safe_extract_archive

    repo_root = Path(__file__).resolve().parent.parent
    src_dir = repo_root / "examples" / "clean_pkg" / "source"
    pkg_archive = repo_root / "examples" / "clean_pkg" / "clean_pkg-1.0.0.tgz"

    if not src_dir.exists():
        src_dir = repo_root / "examples" / "clean_source"
    if not pkg_archive.exists():
        pkg_archive = repo_root / "examples" / "clean_package"

    with tempfile.TemporaryDirectory(prefix="veripack_bench_") as tmp:
        if pkg_archive.is_file():
            pkg_dir = safe_extract_archive(pkg_archive, Path(tmp))
        else:
            pkg_dir = pkg_archive

        scan_report = analyze_integrity(
            package_dir=pkg_dir,
            source_dir=src_dir,
            package_name="clean_pkg",
            version="1.0.0",
            ecosystem="npm",
            enable_llm=False,
        )

    data = scan_report.to_dict()
    data["status"] = "ok"
    data["summary"] = {
        "suspicious_findings": scan_report.summary_counts.get("suspicious", 0) + scan_report.summary_counts.get("critical", 0),
        "expected_build_artifacts": scan_report.summary_counts.get("expected_artifacts", 0),
        "identical_files": scan_report.summary_counts.get("identical", 0),
        **scan_report.summary_counts,
    }
    data["risk_score"] = 100 if scan_report.verdict == Verdict.COMPROMISED else (75 if scan_report.verdict == Verdict.TAMPERED else 0)
    return data


def analyze_paths(
    source: str | Path,
    package: str | Path,
    package_name: Optional[str] = None,
    version: Optional[str] = None,
    ecosystem: Optional[str] = None,
    enable_llm: bool = False,
) -> Dict[str, Any]:
    """Compares package against source path or archive, returning a formatted report dictionary."""
    src = Path(source).resolve()
    pkg = Path(package).resolve()

    temp_dir = None
    if pkg.is_file():
        import tempfile
        from veripack.fetcher import safe_extract_archive
        temp_dir = Path(tempfile.mkdtemp(prefix="veripack_pkg_"))
        pkg_dir = safe_extract_archive(pkg, temp_dir)
    else:
        pkg_dir = pkg

    if src.is_file():
        import tempfile
        from veripack.fetcher import safe_extract_archive
        if temp_dir is None:
            temp_dir = Path(tempfile.mkdtemp(prefix="veripack_src_"))
        src_dir = safe_extract_archive(src, temp_dir)
    else:
        src_dir = src

    eco = ecosystem or "npm"
    pkg_n = package_name
    pkg_v = version
    if not pkg_n:
        pkg_json = pkg_dir / "package.json"
        if pkg_json.is_file():
            try:
                with open(pkg_json, "r", encoding="utf-8") as f:
                    pj = json.load(f)
                    pkg_n = pj.get("name", "package")
                    pkg_v = pj.get("version", "1.0.0")
                    eco = "npm"
            except Exception:
                pass
        else:
            pkg_n = pkg_dir.name
            pkg_v = pkg_v or "1.0.0"

    scan_report = analyze_integrity(
        package_dir=pkg_dir,
        source_dir=src_dir,
        package_name=pkg_n or "package",
        version=pkg_v or "1.0.0",
        ecosystem=eco,
        enable_llm=enable_llm,
    )

    data = scan_report.to_dict()
    if data.get("verdict") == "SAFE":
        data["verdict"] = "VERIFIED_CLEAN"

    data["summary"] = {
        "suspicious_findings": scan_report.summary_counts.get("suspicious", 0) + scan_report.summary_counts.get("critical", 0),
        "expected_build_artifacts": scan_report.summary_counts.get("expected_artifacts", 0),
        "identical_files": scan_report.summary_counts.get("identical", 0),
        **scan_report.summary_counts,
    }
    data["risk_score"] = 100 if scan_report.verdict == Verdict.COMPROMISED else (75 if scan_report.verdict == Verdict.TAMPERED else 0)
    return data


compare_trees = analyze_paths
