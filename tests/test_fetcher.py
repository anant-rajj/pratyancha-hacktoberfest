"""
Unit tests for veripack/fetcher.py: Safe extraction, Zip-Slip defense,
root prefix normalization, and offline source ingestion.
"""

import io
import tarfile
import zipfile
from pathlib import Path
import pytest

from veripack.fetcher import (
    safe_extract_archive,
    calculate_sha256,
    parse_package_spec,
    fetch_upstream_source,
    SecurityError,
)


def test_calculate_sha256(tmp_path: Path):
    """Verify SHA-256 calculation on known content."""
    test_file = tmp_path / "hello.txt"
    test_file.write_text("veripack integrity test")
    digest = calculate_sha256(test_file)
    assert len(digest) == 64
    assert isinstance(digest, str)


def test_parse_package_spec():
    """Verify package spec parsing for npm and PyPI formats."""
    # npm format
    name, ver = parse_package_spec("express@4.21.2")
    assert name == "express"
    assert ver == "4.21.2"

    # PyPI format
    name, ver = parse_package_spec("requests==2.32.3")
    assert name == "requests"
    assert ver == "2.32.3"

    # Scoped npm format
    name, ver = parse_package_spec("@angular/core@17.0.0")
    assert name == "@angular/core"
    assert ver == "17.0.0"

    # Bare package
    name, ver = parse_package_spec("lodash")
    assert name == "lodash"
    assert ver is None


def test_safe_extract_tar_and_prefix_normalization(tmp_path: Path):
    """Verify tar archive extraction and root prefix (package/) normalization."""
    tar_path = tmp_path / "sample.tgz"
    with tarfile.open(tar_path, "w:gz") as tar:
        # Add index.js inside package/
        data = b'console.log("hello world");'
        ti = tarfile.TarInfo(name="package/index.js")
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))

        # Add package.json inside package/
        pkg_json = b'{"name": "sample", "version": "1.0.0"}'
        ti2 = tarfile.TarInfo(name="package/package.json")
        ti2.size = len(pkg_json)
        tar.addfile(ti2, io.BytesIO(pkg_json))

    dest = tmp_path / "extracted"
    normalized = safe_extract_archive(tar_path, dest)

    # Should unwrap single package/ directory
    assert (normalized / "index.js").exists()
    assert (normalized / "package.json").exists()
    assert (normalized / "index.js").read_text() == 'console.log("hello world");'


def test_safe_extract_zip(tmp_path: Path):
    """Verify zip archive extraction."""
    zip_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("module.py", "def run(): pass\n")

    dest = tmp_path / "zip_extracted"
    normalized = safe_extract_archive(zip_path, dest)
    assert (normalized / "module.py").exists()
    assert "def run" in (normalized / "module.py").read_text()


def test_zip_slip_prevention(tmp_path: Path):
    """Verify Tar-Slip path traversal attempt is blocked with SecurityError."""
    tar_path = tmp_path / "malicious.tar"
    with tarfile.open(tar_path, "w") as tar:
        data = b"malicious content"
        ti = tarfile.TarInfo(name="../../evil.sh")
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))

    dest = tmp_path / "safe_zone"
    with pytest.raises(SecurityError) as excinfo:
        safe_extract_archive(tar_path, dest)
    assert "Tar-Slip" in str(excinfo.value) or "traversal" in str(excinfo.value)


def test_fetch_upstream_source_local_directory(tmp_path: Path):
    """Verify offline local source directory ingestion (essential for offline grading)."""
    source_dir = tmp_path / "my_source_repo"
    source_dir.mkdir()
    (source_dir / "index.ts").write_text("export const x = 1;")
    (source_dir / "package.json").write_text('{"name": "my-pkg"}')

    work_dir = tmp_path / "work"
    meta = fetch_upstream_source(str(source_dir), "1.0.0", None, work_dir)

    assert meta.exact_version_matched is True
    assert meta.ref_matched == "local_directory"
    assert (meta.source_path / "index.ts").exists()
    assert (meta.source_path / "package.json").exists()


def test_fetch_upstream_source_local_archive(tmp_path: Path):
    """Verify offline local archive ingestion with repo root normalization."""
    archive_path = tmp_path / "upstream.tgz"
    with tarfile.open(archive_path, "w:gz") as tar:
        # Standard GitHub archive format: <repo-name>-<version>/src/math.ts
        data = b"export const pi = 3.14;"
        ti = tarfile.TarInfo(name="repo-1.0.0/src/math.ts")
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))

    work_dir = tmp_path / "work2"
    meta = fetch_upstream_source(str(archive_path), "1.0.0", None, work_dir)

    assert meta.exact_version_matched is True
    assert meta.ref_matched == "local_archive"
    assert (meta.source_path / "src" / "math.ts").exists()
