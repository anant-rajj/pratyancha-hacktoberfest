"""End-to-end CLI tests verifying all 3 evaluation archetypes and exit codes."""
import json
import os
import subprocess
import sys
from pathlib import Path

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    return subprocess.run(
        [sys.executable, "-m", "veripack", *args],
        capture_output=True,
        text=True,
        env=env,
    )


def test_cli_archetype_1_clean_pkg_is_safe():
    archive = EXAMPLES_DIR / "clean_pkg" / "clean_pkg-1.0.0.tgz"
    repo = EXAMPLES_DIR / "clean_pkg" / "source"
    proc = _run_cli("analyze", "--archive", str(archive), "--repo", str(repo), "--no-llm", "--json")
    assert proc.returncode == 0, f"Expected exit code 0 for SAFE, got {proc.returncode}: {proc.stderr}"
    report = json.loads(proc.stdout)
    assert report["verdict"] == "SAFE"


def test_cli_archetype_2_tampered_manifest_is_detected():
    archive = EXAMPLES_DIR / "tampered_manifest" / "tampered_manifest-1.0.0.tgz"
    repo = EXAMPLES_DIR / "tampered_manifest" / "source"
    proc = _run_cli("analyze", "--archive", str(archive), "--repo", str(repo), "--no-llm", "--json")
    assert proc.returncode == 2, f"Expected exit code 2 for TAMPERED, got {proc.returncode}"
    report = json.loads(proc.stdout)
    assert report["verdict"] in ("TAMPERED", "COMPROMISED")
    classifications = [f.get("classification") for f in report.get("findings", [])]
    assert "SUSPICIOUS_MANIFEST" in classifications


def test_cli_archetype_3_ghost_backdoor_is_compromised():
    archive = EXAMPLES_DIR / "ghost_backdoor" / "ghost_backdoor-1.0.0.tgz"
    repo = EXAMPLES_DIR / "ghost_backdoor" / "source"
    proc = _run_cli("analyze", "--archive", str(archive), "--repo", str(repo), "--no-llm", "--json")
    assert proc.returncode == 2, f"Expected exit code 2 for COMPROMISED, got {proc.returncode}"
    report = json.loads(proc.stdout)
    assert report["verdict"] == "COMPROMISED"
    classifications = [f.get("classification") for f in report.get("findings", [])]
    assert "UNMAPPED_GHOST_FILE" in classifications


def test_cli_invalid_arguments_returns_exit_code_1():
    proc = _run_cli("analyze", "--archive", "/nonexistent/path.tgz", "--repo", "/nonexistent/src")
    assert proc.returncode == 1


def test_cli_self_test_flag():
    proc = _run_cli("--self-test", "--json")
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data.get("status") == "ok"
