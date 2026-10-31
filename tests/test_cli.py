import json
import subprocess
import sys


def test_cli_self_test():
    proc = subprocess.run(
        [sys.executable, "-m", "veripack.cli", "--self-test", "--json"],
        capture_output=True,
        text=True,
        check=True
    )
    report = json.loads(proc.stdout)
    assert "verdict" in report
    assert "findings" in report
    assert report["verdict"] in ("COMPROMISED", "VERIFIED_CLEAN")


def test_cli_examples_tampered_detection():
    proc = subprocess.run(
        [
            sys.executable, "-m", "veripack.cli",
            "--source", "examples/clean_source",
            "--package", "examples/tampered_package",
            "--json"
        ],
        capture_output=True,
        text=True,
        check=True
    )
    report = json.loads(proc.stdout)
    assert report["verdict"] == "COMPROMISED"
    categories = [f["category"] for f in report["findings"]]
    assert "MANIFEST_LIFECYCLE_TAMPERING" in categories
    assert "ORPHAN_GHOST_FILE" in categories
