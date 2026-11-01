"""Tests for advanced supply-chain hardening: Zip/Tar-Slip boundaries, Trojan Source, decompression bombs, and binary ghosts."""
import tempfile
import zipfile
import tarfile
import io
from pathlib import Path
import pytest
from veripack.fetcher import safe_extract_archive, SecurityError, _safe_extract_zip, _safe_extract_tar
from veripack.entropy import detect_obfuscation_signals
from veripack.analyzer import analyze_integrity
from veripack.models import Verdict


def test_trojan_source_bidi_override_detected():
    # CVE-2021-42574 Bidi override character \u202E
    malicious_code = "if (accessLevel != 'user\u202E \u2066// Check admin\u2069 \u2066') {"
    signals = detect_obfuscation_signals(malicious_code)
    assert any("trojan_source_bidi_override" in s for s in signals)


def test_zero_width_invisible_unicode_detected():
    invisible_code = "const\u200B admin\u200C = \u200Dtrue;\u200B"
    signals = detect_obfuscation_signals(invisible_code)
    assert any("invisible_unicode_injection" in s for s in signals)


def test_unmapped_native_binary_is_critical_ghost():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = Path(tmp)
        src_dir = tmp_p / "src"
        pkg_dir = tmp_p / "pkg"
        src_dir.mkdir()
        pkg_dir.mkdir()

        (src_dir / "index.js").write_text("module.exports = {};", encoding="utf-8")
        (pkg_dir / "index.js").write_text("module.exports = {};", encoding="utf-8")

        # Inject an unmapped native compiled binary
        (pkg_dir / "addon.node").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100)

        report = analyze_integrity(pkg_dir, src_dir, enable_llm=False)
        assert report.verdict == Verdict.COMPROMISED
        ghost_findings = [f for f in report.findings if f.file_path == "addon.node"]
        assert len(ghost_findings) == 1
        assert ghost_findings[0].severity.value == "CRITICAL"
        assert any("unmapped_native_binary" in ev for ev in ghost_findings[0].evidence)


def test_decompression_bomb_cumulative_size_limit():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = Path(tmp)
        zip_path = tmp_p / "bomb.zip"
        extract_dir = tmp_p / "extracted"
        extract_dir.mkdir()

        # Create a zip containing cumulative sizes exceeding 150 MB (e.g. 7 * 24 MB = 168 MB)
        # using zipfile's compressed stream of repeated zeroes so the file is tiny on disk
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            chunk = b"\x00" * (24 * 1024 * 1024)
            for i in range(22):
                zf.writestr(f"large_file_{i}.bin", chunk)

        with pytest.raises(ValueError, match="Archive exceeds cumulative decompression threshold"):
            _safe_extract_zip(zip_path, extract_dir)
