"""Release polling monitor for npm and PyPI packages."""
import inspect
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from veripack import analyzer, fetcher


def _invoke_analyzer(source_dir: Path, archive_dir: Path, **kwargs) -> Any:
    """Invokes the primary analysis entrypoint in veripack.analyzer."""
    enable_llm = kwargs.get("enable_llm", kwargs.get("use_llm", True))
    pkg_name = kwargs.get("package_name", "package")
    ver = kwargs.get("version", "1.0.0")
    eco = kwargs.get("ecosystem", "npm")
    source_ref = kwargs.get("source_ref", "upstream")
    archive_sha256 = kwargs.get("archive_sha256", "manual_scan")
    provenance = kwargs.get("provenance_verified", False)

    if hasattr(analyzer, "analyze_integrity") and callable(analyzer.analyze_integrity):
        return analyzer.analyze_integrity(
            package_dir=Path(archive_dir),
            source_dir=Path(source_dir),
            package_name=pkg_name,
            version=ver,
            ecosystem=eco,
            source_ref=source_ref,
            archive_sha256=archive_sha256,
            provenance_verified=provenance,
            enable_llm=enable_llm,
        )

    # Dynamic fallback if function name differs
    for fn_name in ("analyze_package", "analyze_directories", "compare_directories", "run_analysis"):
        fn = getattr(analyzer, fn_name, None)
        if callable(fn):
            try:
                return fn(Path(archive_dir), Path(source_dir), **kwargs)
            except TypeError:
                return fn(Path(source_dir), Path(archive_dir))

    raise RuntimeError("Could not locate analysis entrypoint in veripack.analyzer")


def check_release_once(
    npm_spec: Optional[str] = None,
    pypi_spec: Optional[str] = None,
    repo_override: Optional[str] = None,
    use_llm: bool = True,
) -> Any:
    """Fetches the latest release from npm or PyPI, resolves upstream source, and runs VeriPack."""
    with tempfile.TemporaryDirectory(prefix="veripack_mon_") as tmp:
        work_dir = Path(tmp)
        if npm_spec:
            pkg_meta = fetcher.fetch_npm_package(npm_spec, work_dir / "pkg")
            ecosystem = "npm"
        elif pypi_spec:
            pkg_meta = fetcher.fetch_pypi_package(pypi_spec, work_dir / "pkg")
            ecosystem = "pypi"
        else:
            raise ValueError("Must specify either npm_spec or pypi_spec")

        pkg_name = getattr(pkg_meta, "package_name", None) or getattr(pkg_meta, "name", npm_spec or pypi_spec)
        version = getattr(pkg_meta, "version", "unknown")
        extracted_pkg = (
            getattr(pkg_meta, "extracted_path", None)
            or getattr(pkg_meta, "extracted_dir", None)
            or getattr(pkg_meta, "extract_dir", None)
            or getattr(pkg_meta, "root_dir", None)
            or getattr(pkg_meta, "path", None)
        )
        repo_url = repo_override or getattr(pkg_meta, "repository_url", None) or getattr(pkg_meta, "repo_url", None)
        git_head = getattr(pkg_meta, "git_head", None)
        archive_sha256 = getattr(pkg_meta, "sha256", None) or getattr(pkg_meta, "archive_sha256", "")
        provenance = getattr(pkg_meta, "provenance_verified", False)

        if not repo_url:
            raise ValueError(f"No upstream repository URL found for {pkg_name}@{version}")

        src_meta = fetcher.fetch_upstream_source(repo_url, version, git_head, work_dir / "src")
        extracted_src = (
            getattr(src_meta, "source_path", None)
            or getattr(src_meta, "extracted_dir", None)
            or getattr(src_meta, "extract_dir", None)
            or getattr(src_meta, "root_dir", None)
            or getattr(src_meta, "path", None)
        )
        source_ref = getattr(src_meta, "source_ref", None) or getattr(src_meta, "ref", version)

        return _invoke_analyzer(
            Path(extracted_src),
            Path(extracted_pkg),
            package_name=pkg_name,
            version=version,
            ecosystem=ecosystem,
            source_ref=source_ref,
            archive_sha256=archive_sha256,
            provenance_verified=provenance,
            enable_llm=use_llm,
        )


def monitor_loop(
    npm_spec: Optional[str] = None,
    pypi_spec: Optional[str] = None,
    repo_override: Optional[str] = None,
    interval: int = 60,
    once: bool = True,
    use_llm: bool = True,
    on_report: Optional[Callable[[Any], None]] = None,
) -> Any:
    """Polls package releases continuously or once (--once)."""
    while True:
        report = check_release_once(
            npm_spec=npm_spec,
            pypi_spec=pypi_spec,
            repo_override=repo_override,
            use_llm=use_llm,
        )
        if on_report:
            on_report(report)
        if once:
            return report
        time.sleep(max(1, interval))
