"""
Unit tests for veripack/entropy.py: Shannon entropy & obfuscation heuristics.
"""

from veripack.entropy import calculate_entropy, detect_obfuscation_signals


def test_calculate_entropy_zero_and_uniform():
    """Verify empty and single-byte uniform data entropy."""
    assert calculate_entropy(b"") == 0.0
    assert calculate_entropy(b"AAAAAAA") == 0.0


def test_calculate_entropy_realistic_code():
    """Verify realistic code entropy falls within expected boundaries."""
    source_code = b"""
    function add(a, b) {
        // Simple addition helper
        return a + b;
    }
    module.exports = { add };
    """
    entropy = calculate_entropy(source_code)
    # Plain text code is usually between 3.5 and 4.8
    assert 3.5 <= entropy <= 5.0


def test_calculate_entropy_high_entropy_payload():
    """Verify high-entropy random/packed data exceeds threshold."""
    # Byte sequence simulating packed / encrypted payload
    pseudo_encrypted = bytes((i * 37 + 13) % 256 for i in range(1024))
    entropy = calculate_entropy(pseudo_encrypted)
    assert entropy > 6.0


def test_detect_obfuscation_signals_clean_code():
    """Verify clean code does not trigger false positive obfuscation signals."""
    clean_code = "export function hello() { console.log('hello'); }"
    signals = detect_obfuscation_signals(clean_code)
    assert len(signals) == 0


def test_detect_obfuscation_signals_malicious_obfuscation():
    """Verify obfuscated patterns (hex arrays, eval, long packed lines) are caught."""
    obfuscated_code = (
        "var _0x1234 = ['\x65\x76\x61\x6c', '\x68\x65\x78', '_0xabcd'];\n"
        "var _0x5678 = function(_0x9999) { eval(_0x9999); };\n"
        + "x" * 600
    )
    signals = detect_obfuscation_signals(obfuscated_code)
    assert any("dynamic_execution" in s for s in signals)
    assert any("packed_lines" in s or "hex" in s for s in signals)
