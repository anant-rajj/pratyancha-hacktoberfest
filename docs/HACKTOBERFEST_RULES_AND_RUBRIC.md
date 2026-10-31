# Hacktoberfest HackDay Sonipat 2026 — Official Rules, Rubric & Guidelines

> **Source:** Extracted directly from official briefing slides (`1hNbyiRuJ68t0QaU7BIxBnRqrJcAlhxMaBWYAo5hCu1c`) at Newton School of Technology (NST) · Rishihood University.  
> **Host Partners:** DigitalOcean, MLH, DEV, Gemma, WeMakeDevs.

---

## 1. Hackathon Format & Schedule
- **Duration:** 12 Hours (31 Oct 6:30 PM – 1 Nov 6:30 AM). Repos frozen strictly at 6:30 AM.
- **Team Size:** 1–4 members (Team: `pratyancha` — Anant Raj, Anshul Pandey, Vinayak Agrawal, Amrit Sagar).
- **Milestones:**
  - `8:30 PM (31 Oct)`: Repo link & init commit (`HACKATHON.md`) due.
  - `Until 12:00 AM`: Mentors available (Krishna, Neetanshu, Kushagar, Sai).
  - `2:00 AM`: Midnight refreshments (ID card required).
  - `6:30 AM (1 Nov)`: Hackathon ends. Repositories automatically frozen for automated scoring.
  - `8:30 AM`: Final panel presentations (8 panels in parallel).
  - `1:30 PM`: Results and cash prizes.

---

## 2. Four Golden Rules (Non-Negotiable)
1. **No earlier code or prototype:** Start from an empty repo.
2. **Open-Source License:** Must have an open-source license (`MIT` or `Apache-2.0`) in a public GitHub repo. *(Required for MLH Best Open-Source AI Project challenge)*.
3. **Zero Secrets / API Keys:** Never commit API keys or credentials. Automated scanners will flag leaked secrets to judges.
4. **Explain What Was Built:** Every team member must be able to explain the design and code during panel Q&A, or the project is disqualified.

---

## 3. Scoring Rubric (100 Points Total)

### A. Automated Repository Evaluation (70 Points — Frozen at 6:30 AM)
1. **Functional Correctness (30 pts):**
   - CI workflow passes on the final commit.
   - Features are really built and functional (no dummy stubs).
   - `examples/` directory demonstrates real sample inputs and real tool outputs.
2. **Open-Source AI Use (15 pts):**
   - Product must actively use open-weight models at runtime (Llama, Gemma, Qwen, Mistral, DeepSeek, SmolLM, etc.).
   - Can run locally (Ollama / llama.cpp) or on the hackathon model server.
   - ⚠️ **Zero Points & -5 Penalty:** Using closed proprietary APIs (OpenAI, Claude, Gemini API) at runtime scores 0. Claiming an open model in `HACKATHON.md` that the code doesn't actually execute incurs **0 for AI Use and −5 overall penalty**.
   - Note: AI coding assistants used to *write* code (Claude Code, Cursor, Copilot) are allowed, but must be declared in PRs.
3. **Testing & Evidence (15 pts):**
   - Comprehensive test suite (unit + integration tests).
   - High-precision evidence output (diff hunks, entropy, AST markers).
4. **Open-Source Workflow (10 pts):**
   - `HACKATHON.md` in root.
   - `main` branch is PR-only (no direct pushes after init).
   - Every change goes through a Pull Request with a passing CI check.
   - Every PR template declares: models used in the PR + AI coding assistants.

### B. Live Panel Presentation (30 Points — 8:30 AM)
- **Time Allocation:** 8 min pitch + 4 min Q&A + 2 min buffer.
- **Criteria:**
  - Design & Trade-offs Q&A (10 pts)
  - Live Demo & Usability (10 pts)
  - Problem Understanding (10 pts)

---

## 4. Problem 4 Requirements: Published Package vs Source Code Integrity Analyzer
- **Core Dilemma:** Attackers exploit the blind spot between public GitHub repositories and published tarballs on npm / PyPI (e.g., xz backdoor, ua-parser-js, event-stream).
- **Core Archetypes to Classify:**
  1. `EXPECTED` (Safe): Compiler outputs (`src/index.ts` -> `dist/index.js`), minification, source maps, `.dist-info`, `PKG-INFO`.
  2. `SUSPICIOUS` (Tampered): Manifest modifications (added `preinstall` / `postinstall` hooks in `package.json`, dynamic execution in `setup.py`).
  3. `SUSPICIOUS / COMPROMISED` (Ghost Files): Obfuscated files found nowhere in the source repo (`lib/x.min.js`, high Shannon entropy, `eval`, hex arrays, `_0x` variables).
- **Key Capability:** Watch releases, compare tarballs with source git tags, explain every discrepancy with proof, and alert on malicious releases.

---

## 5. Submission Checklist (OrganizerHQ)
- [ ] Submit before 6:30 AM on OrganizerHQ (`Challenges -> Add Submission`).
- [ ] Pick Challenge: **Best Open-Source AI Project** (mandatory for all teams on Problems 1–7).
- [ ] Add all teammates under `Your Submission -> Add Member`:
  - Anant Raj
  - Anshul Pandey
  - Vinayak Agrawal
  - Amrit Sagar
- [ ] Verify CI is green on GitHub Actions on the final commit before 6:30 AM.
