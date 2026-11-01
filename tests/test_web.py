"""
Unit and integration tests for the VeriPack web dashboard backend and API endpoints.
Tests multi-ecosystem heuristics, dynamic repository simulation, presets, and HTTP handlers.
"""
from __future__ import annotations
import json
import io
import urllib.parse
from pathlib import Path
import pytest

from veripack.web import (
    verify_target_backend,
    _simulate_dynamic_target,
    VeriPackHandler,
    PRESETS,
)


def test_presets_loaded_and_complete():
    """Verify all 7 Problem 04 and ecosystem presets are loaded and structured."""
    expected_keys = [
        "pratyancha",
        "express",
        "flask",
        "event_stream",
        "clean_pkg",
        "tampered_manifest",
        "ghost_backdoor",
    ]
    for key in expected_keys:
        res = verify_target_backend(key)
        assert res is not None, f"Preset {key} returned None"
        assert "verdict" in res
        assert "score_val" in res
        assert "files" in res
        assert len(res["files"]) > 0
        assert "checklist" in res
        assert "ai_response" in res


def test_codex_rust_ecosystem_verification():
    """Verify Rust / OpenAI Codex releases trigger Rust heuristics and Cargo.toml manifest."""
    res = verify_target_backend("https://github.com/openai/codex/releases/tag/rust-v0.166.0")
    assert res["verdict"] == "SAFE"
    assert res["score_val"] == "100"
    file_names = [f["name"] for f in res["files"]]
    assert any("Cargo.toml" in name for name in file_names)
    assert any("codex-rs" in name or ".rs" in name for name in file_names)


def test_linux_kernel_ecosystem_verification():
    """Verify Linux kernel targets trigger C/Kernel Makefile and sched files."""
    res = verify_target_backend("https://github.com/torvalds/linux")
    assert res["verdict"] == "SAFE"
    assert res["score_val"] == "100"
    file_names = [f["name"] for f in res["files"]]
    assert "Makefile" in file_names
    assert any("kernel/" in name or "sched" in name for name in file_names)


def test_swift_macos_ecosystem_verification():
    """Verify Swift / macOS targets trigger Package.swift or install script heuristics."""
    res = verify_target_backend("https://github.com/anant-rajj/mac-insomnia")
    assert res["verdict"] == "SAFE"
    assert int(res["score_val"]) >= 90
    file_names = [f["name"] for f in res["files"]]
    assert len(file_names) >= 2


def test_supply_chain_attack_trojan_detection():
    """Verify malicious or trojan targets trigger TAMPERED verdict and score penalty."""
    res = verify_target_backend("https://github.com/malicious-actor/crypto-stealer-trojan")
    assert res["verdict"] in ("TAMPERED", "COMPROMISED")
    assert int(res["score_val"]) <= 25
    assert "GRADE F" in res["score_grade"]
    file_names = [f["name"] for f in res["files"]]
    assert any("flatmap" in name or "package.json" in name for name in file_names)


def test_generic_python_ecosystem():
    """Verify arbitrary Python package queries trigger pyproject.toml and pytest files."""
    res = _simulate_dynamic_target("python:my-custom-framework", owner="acme", repo="my-custom-framework")
    assert res["verdict"] == "SAFE"
    file_names = [f["name"] for f in res["files"]]
    assert "pyproject.toml" in file_names
    assert any("test_" in name or "tests/" in name for name in file_names)


class MockWFile(io.BytesIO):
    pass


class MockRFile(io.BytesIO):
    pass


class DummyVeriPackHandler(VeriPackHandler):
    """Subclass VeriPackHandler for testing HTTP handler methods in-memory."""
    def __init__(self, method="GET", path="/api/health", body=b""):
        self.command = method
        self.path = path
        self.request_version = "HTTP/1.1"
        self.headers = {"Content-Length": str(len(body)), "Content-Type": "application/json"}
        self.rfile = MockRFile(body)
        self.wfile = MockWFile()
        self._headers_buffer = []

    def send_response(self, code, message=None):
        self._response_code = code

    def send_header(self, keyword, value):
        self._headers_buffer.append((keyword, value))

    def end_headers(self):
        pass


def test_http_api_health_endpoint():
    """Verify GET and POST /api/health returns status ok JSON."""
    handler = DummyVeriPackHandler(method="GET", path="/api/health")
    handler.do_GET()
    assert handler._response_code == 200
    resp = json.loads(handler.wfile.getvalue().decode("utf-8"))
    assert resp["status"] == "ok"
    assert resp["model"] == "qwen2.5-coder:7b"


def test_http_api_verify_post_endpoint():
    """Verify POST /api/verify returns verification payload for custom target."""
    req_body = json.dumps({"target": "express"}).encode("utf-8")
    handler = DummyVeriPackHandler(method="POST", path="/api/verify", body=req_body)
    handler.do_POST()
    assert handler._response_code == 200
    resp = json.loads(handler.wfile.getvalue().decode("utf-8"))
    assert resp["verdict"] == "SAFE"
    assert resp["score_val"] == "100"
    assert any("lib/express.js" in f["name"] for f in resp["files"])
