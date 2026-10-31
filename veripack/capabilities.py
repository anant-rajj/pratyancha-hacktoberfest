"""
Module 3A: Capability & Symbol Extractor (veripack/capabilities.py)

Extracts sensitive runtime capabilities (network, subprocess execution, environment exfiltration,
dynamic code evaluation) and exported symbols from Python AST and JS/TS tokens.
Essential for Case 1 build-equivalence verification and XZ-style bundler backdoor detection.
"""

from __future__ import annotations
import ast
import re
from pathlib import Path
from typing import Set, Dict, List

CAPABILITY_DEFINITIONS = {
    "network": [
        "fetch", "http", "https", "axios", "urllib", "requests", "socket", "net.connect", "XMLHttpRequest"
    ],
    "process": [
        "child_process", "spawn", "exec", "execSync", "os.system", "subprocess", "popen", "posix_spawn"
    ],
    "env": [
        "process.env", "os.environ", "getenv"
    ],
    "eval": [
        "eval", "Function", "compile", "vm.runInContext", "vm.runInThisContext"
    ],
}


def extract_capabilities_from_file(file_path: Path) -> Dict[str, Set[str]]:
    """
    Extracts sensitive capabilities from a file based on its extension.
    Returns a dictionary of category -> set of detected tokens.
    """
    if not file_path.is_file():
        return {}

    ext = file_path.suffix.lower()
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {}

    if ext == ".py":
        return _extract_python_capabilities(content)
    elif ext in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        return _extract_javascript_capabilities(content)
    else:
        # Fallback keyword scan for shell scripts, JSON, etc.
        return _extract_generic_capabilities(content)


def _extract_python_capabilities(source_code: str) -> Dict[str, Set[str]]:
    """Uses Python's native AST parser to accurately find capability calls and imports."""
    found: Dict[str, Set[str]] = {cat: set() for cat in CAPABILITY_DEFINITIONS}
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return _extract_generic_capabilities(source_code)

    for node in ast.walk(tree):
        # 1. Inspect imports (e.g. import subprocess, from os import system)
        if isinstance(node, ast.Import):
            for alias in node.names:
                for cat, tokens in CAPABILITY_DEFINITIONS.items():
                    for token in tokens:
                        if token in alias.name:
                            found[cat].add(token)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                full_name = f"{mod}.{alias.name}" if mod else alias.name
                for cat, tokens in CAPABILITY_DEFINITIONS.items():
                    for token in tokens:
                        if token in full_name or token == alias.name:
                            found[cat].add(token)

        # 2. Inspect attribute accesses (e.g. os.environ, os.system)
        elif isinstance(node, ast.Attribute):
            attr_name = node.attr
            if attr_name in ("environ", "system", "popen"):
                for cat, tokens in CAPABILITY_DEFINITIONS.items():
                    for token in tokens:
                        if token.endswith(attr_name):
                            found[cat].add(token)

        # 3. Inspect direct function calls (e.g. eval(), exec())
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
                for cat, tokens in CAPABILITY_DEFINITIONS.items():
                    if func_name in tokens:
                        found[cat].add(func_name)

    return {k: v for k, v in found.items() if v}


def _extract_javascript_capabilities(source_code: str) -> Dict[str, Set[str]]:
    """Token/regex-based capability extraction for JavaScript and TypeScript."""
    found: Dict[str, Set[str]] = {cat: set() for cat in CAPABILITY_DEFINITIONS}

    for cat, tokens in CAPABILITY_DEFINITIONS.items():
        for token in tokens:
            # Match word boundary or property access
            escaped = re.escape(token)
            pattern = re.compile(rf"\b{escaped}\b")
            if pattern.search(source_code):
                found[cat].add(token)

    return {k: v for k, v in found.items() if v}


def _extract_generic_capabilities(content: str) -> Dict[str, Set[str]]:
    """Fast keyword search fallback."""
    found: Dict[str, Set[str]] = {cat: set() for cat in CAPABILITY_DEFINITIONS}
    for cat, tokens in CAPABILITY_DEFINITIONS.items():
        for token in tokens:
            if token in content:
                found[cat].add(token)
    return {k: v for k, v in found.items() if v}


def extract_exported_symbols(file_path: Path) -> Set[str]:
    """
    Extracts exported top-level function and class names for capability equivalence verification.
    """
    if not file_path.is_file():
        return set()

    symbols: Set[str] = set()
    ext = file_path.suffix.lower()
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return symbols

    if ext == ".py":
        try:
            tree = ast.parse(content)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if not node.name.startswith("_"):
                        symbols.add(node.name)
        except SyntaxError:
            pass
    elif ext in (".js", ".mjs", ".ts", ".tsx"):
        # Match export function foo, export const foo, exports.foo = ...
        matches = re.findall(r"(?:export\s+(?:async\s+)?function\s+([A-Za-z0-9_$]+)|export\s+const\s+([A-Za-z0-9_$]+)|exports\.([A-Za-z0-9_$]+)\s*=)", content)
        for m in matches:
            for s in m:
                if s:
                    symbols.add(s)

    return symbols
