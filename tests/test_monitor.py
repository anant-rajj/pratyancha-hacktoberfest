"""
Unit tests for veripack/monitor.py verifying safe release polling and analyzer invocation.
"""

from pathlib import Path
from unittest.mock import patch
from veripack.models import PackageMetadata, SourceMetadata, ScanReport, Verdict
from veripack.monitor import check_release_once, _invoke_analyzer


def test_invoke_analyzer_direct(tmp_path: Path):
    src = tmp_path / "src"
    pkg = tmp_path / "pkg"
    src.mkdir()
    pkg.mkdir()

    (src / "package.json").write_text('{"name": "test-pkg", "version": "1.0.0"}')
    (pkg / "package.json").write_text('{"name": "test-pkg", "version": "1.0.0"}')

    report = _invoke_analyzer(src, pkg, package_name="test-pkg", version="1.0.0", use_llm=False)
    assert isinstance(report, ScanReport)
    assert report.verdict == Verdict.SAFE


def test_check_release_once_attribute_resolution(tmp_path: Path):
    src_dir = tmp_path / "mock_src"
    pkg_dir = tmp_path / "mock_pkg"
    src_dir.mkdir()
    pkg_dir.mkdir()

    (src_dir / "package.json").write_text('{"name": "mock-pkg", "version": "1.0.0"}')
    (pkg_dir / "package.json").write_text('{"name": "mock-pkg", "version": "1.0.0"}')

    mock_pkg = PackageMetadata(
        name="mock-pkg",
        version="1.0.0",
        ecosystem="npm",
        archive_path=pkg_dir,
        extracted_path=pkg_dir,
        sha256="dummy_sha256",
        repository_url="https://github.com/example/mock-pkg",
    )

    mock_src = SourceMetadata(
        source_path=src_dir,
        ref_matched="v1.0.0",
        exact_version_matched=True,
        repo_url="https://github.com/example/mock-pkg",
    )

    with patch("veripack.fetcher.fetch_npm_package", return_value=mock_pkg), \
         patch("veripack.fetcher.fetch_upstream_source", return_value=mock_src):
        report = check_release_once(npm_spec="mock-pkg@1.0.0", use_llm=False)
        assert isinstance(report, ScanReport)
        assert report.package_name == "mock-pkg"
        assert report.verdict == Verdict.SAFE
