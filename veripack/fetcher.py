import json
import os
import re
import shutil
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional, Tuple


def download_npm_tarball(pkg_name: str, version: Optional[str] = None, dest_dir: Optional[str] = None) -> str:
    """Downloads an npm tarball (.tgz) directly from registry.npmjs.org."""
    target_dir = dest_dir or tempfile.mkdtemp(prefix="veripack_npm_")
    clean_name = pkg_name.strip()
    
    # Parse name@version if present
    if "@" in clean_name and not clean_name.startswith("@"):
        clean_name, version = clean_name.split("@", 1)
    elif clean_name.startswith("@") and clean_name.count("@") > 1:
        parts = clean_name.split("@")
        clean_name = f"@{parts[1]}"
        version = parts[2]

    meta_url = f"https://registry.npmjs.org/{clean_name}"
    req = urllib.request.Request(meta_url, headers={"User-Agent": "veripack-integrity-analyzer/0.1.0"})
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        metadata = json.loads(resp.read().decode("utf-8"))

    resolved_ver = version or metadata.get("dist-tags", {}).get("latest")
    if not resolved_ver or resolved_ver not in metadata.get("versions", {}):
        raise ValueError(f"Version '{resolved_ver}' not found in npm registry for '{clean_name}'.")

    tarball_url = metadata["versions"][resolved_ver]["dist"]["tarball"]
    filename = Path(tarball_url).name
    tarball_path = os.path.join(target_dir, filename)

    urllib.request.urlretrieve(tarball_url, tarball_path)
    return tarball_path


def download_pypi_archive(pkg_name: str, version: Optional[str] = None, dest_dir: Optional[str] = None) -> str:
    """Downloads a release archive (.whl or .tar.gz) from pypi.org."""
    target_dir = dest_dir or tempfile.mkdtemp(prefix="veripack_pypi_")
    url = f"https://pypi.org/pypi/{pkg_name}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "veripack-integrity-analyzer/0.1.0"})
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    resolved_ver = version or data.get("info", {}).get("version")
    releases = data.get("releases", {}).get(resolved_ver, [])
    if not releases:
        raise ValueError(f"No release artifacts found on PyPI for {pkg_name}=={resolved_ver}")

    # Prioritize wheel, fallback to sdist
    chosen = next((r for r in releases if r.get("packagetype") == "bdist_wheel"), releases[0])
    download_url = chosen["url"]
    filename = chosen["filename"]
    save_path = os.path.join(target_dir, filename)

    urllib.request.urlretrieve(download_url, save_path)
    return save_path
