# VeriPack — Published Package vs Source Code Integrity Analyzer

**Team:** `pratyancha` (Anant Raj, Anshul Pandey, Vinayak Agrawal, Amrit Sagar)  
**Track:** Problem 04 — Published Package vs Source Code Integrity Analyzer  

VeriPack is an evidence-first supply-chain security analyzer for **npm** (`.tgz`) and **PyPI** (`.whl` / `.tar.gz`) releases. It verifies whether a published registry artifact corresponds to its claimed upstream GitHub source repository, separating benign build artifacts (`src/index.ts` -> `dist/index.js`) from supply-chain attacks (`postinstall` lifecycle injections, bundler capability escalations, and obfuscated ghost files).

---

## Architecture

```text
+--------------------+      +-----------------------+      +-------------------------+
|   Input Surface    |      |  Safe Archive Parser  |      |  Capability & Manifest  |
| - Local .tgz/.whl  | ---> | - Zip/Tar-Slip Guard  | ---> |  Comparator (AST/Regex) |
| - Live npm / PyPI  |      | - 25MB / 5000-file Cap|      | - Entropy & Obfuscation |
+--------------------+      +-----------------------+      +------------+------------+
                                                                        |
                                                                        v
+--------------------+      +-----------------------+      +-------------------------+
|  Verdict & Report  | <--- | Deterministic Static  | <--- | Local Ollama AI Engine  |
| - SAFE (Exit 0)    |      | Fallback (CI-Safe)    |      | - qwen2.5-coder:7b      |
| - TAMPERED/COMP(2) |      +-----------------------+      | - 3.0s Strict Timeout   |
+--------------------+                                     +-------------------------+
```

---

## Installation & Local Ollama Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt
pip install -e .

# 2. (Optional) Start local Ollama with Qwen 2.5 Coder 7B for AI explanations
ollama pull qwen2.5-coder:7b
ollama serve
```

*Note: VeriPack includes a mandatory deterministic static fallback when Ollama is unreachable, ensuring 100% reliability in headless CI/CD pipelines.*

---

## CLI Usage

### 1. Audit Local Package Archives Against Source (`examples/`)

```bash
# Archetype 1: Expected TypeScript Build Artifact (Verdict: SAFE, Exit Code: 0)
python -m veripack analyze \
  --archive ./examples/clean_pkg/clean_pkg-1.0.0.tgz \
  --repo ./examples/clean_pkg/source

# Archetype 2: Injected npm postinstall Hook (Verdict: TAMPERED, Exit Code: 2)
python -m veripack analyze \
  --archive ./examples/tampered_manifest/tampered_manifest-1.0.0.tgz \
  --repo ./examples/tampered_manifest/source

# Archetype 3: Obfuscated Ghost File lib/x.min.js (Verdict: COMPROMISED, Exit Code: 2)
python -m veripack analyze \
  --archive ./examples/ghost_backdoor/ghost_backdoor-1.0.0.tgz \
  --repo ./examples/ghost_backdoor/source --json
```

### 2. Live Registry Audit & Release Monitoring

```bash
# Audit a live npm or PyPI package version
python -m veripack analyze --npm express@4.21.2
python -m veripack analyze --pypi requests==2.32.3

# Monitor latest release once (--once)
python -m veripack monitor --npm debug --once
```

---

## Running Automated Tests

```bash
PYTHONPATH=. pytest -v tests/
```

---

## License

MIT License — see LICENSE.
