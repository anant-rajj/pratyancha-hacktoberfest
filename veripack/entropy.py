"""
Module 2: Entropy & Obfuscation Heuristics (veripack/entropy.py)

Calculates byte-level Shannon entropy and detects multi-signal obfuscation patterns
(hex arrays, unicode escapes, dynamic eval/Function execution, long packed lines)
without relying on brittle single-threshold checks.
"""

from __future__ import annotations
import math
import re
from typing import List

# Patterns matching typical malicious obfuscation tools (e.g. javascript-obfuscator, pyarmor)
HEX_IDENTIFIER_PATTERN = re.compile(r"\b_0x[a-fA-F0-9]{4,}\b")
HEX_STRING_ARRAY_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
UNICODE_ESCAPE_PATTERN = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
DYNAMIC_EXEC_PATTERNS = [
    re.compile(r"\beval\s*\("),
    re.compile(r"\bnew\s+Function\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\bcompile\s*\("),
    re.compile(r"\bbase64\.b64decode\s*\("),
    re.compile(r"\bBuffer\.from\s*\([^)]+['\"]base64['\"]\s*\)"),
    re.compile(r"\batob\s*\("),
]


def calculate_entropy(data: bytes) -> float:
    """
    Computes standard byte-wise Shannon entropy of raw bytes in range 0.0 to 8.0.

    Typical distributions:
    - 0.0: Empty or completely uniform repeating bytes (e.g., all zeros)
    - 3.5 - 4.9: Standard formatted source code (JavaScript, Python, TypeScript)
    - 5.0 - 5.6: Minified JavaScript without obfuscation
    - 5.8 - 8.0: Packed, encrypted, or heavily obfuscated payloads
    """
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256

    for b in data:
        byte_counts[b] += 1

    for count in byte_counts:
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)


def detect_obfuscation_signals(text: str, file_ext: str = "") -> List[str]:
    """
    Combines multiple structural heuristics to detect code packing and obfuscation:
    1. Average line length exceeding 500 characters without source map reference.
    2. Hex and unicode identifier arrays (_0x hex, \\x65\\x76\\x61\\x6c).
    3. Dynamic code execution (eval, new Function, exec, base64 decode).
    """
    signals: List[str] = []
    if not text:
        return signals

    lines = text.splitlines()
    num_lines = len(lines)

    # 1. Long line packing check
    if num_lines > 0:
        total_chars = len(text)
        avg_line_len = total_chars / num_lines
        has_sourcemap = "//# sourceMappingURL" in text or "/*# sourceMappingURL" in text
        if avg_line_len > 500 and not has_sourcemap:
            signals.append(f"packed_lines_without_sourcemap (avg_len={int(avg_line_len)})")
        elif any(len(line) > 2000 for line in lines) and not has_sourcemap:
            signals.append("extreme_line_length (>2000 chars)")

    # 2. Hex identifier arrays (_0x...)
    hex_matches = HEX_IDENTIFIER_PATTERN.findall(text)
    if len(hex_matches) >= 3:
        sample = hex_matches[:3]
        signals.append(f"hex_identifier_arrays ({len(hex_matches)} occurrences, e.g. {sample})")

    # 3. Hex string arrays (\x65\x76\x61\x6c)
    if HEX_STRING_ARRAY_PATTERN.search(text):
        signals.append("hex_escaped_string_array")

    # 4. Unicode escape sequences (\u0065\u0076)
    if UNICODE_ESCAPE_PATTERN.search(text):
        signals.append("unicode_escaped_string_array")

    # 5. Dynamic code execution primitives
    for pattern in DYNAMIC_EXEC_PATTERNS:
        match = pattern.search(text)
        if match:
            matched_str = match.group(0).strip()
            signals.append(f"dynamic_execution: {matched_str}")

    return signals
