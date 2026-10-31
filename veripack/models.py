"""
Core domain models and structured data contracts for VeriPack.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional


class Verdict(str, Enum):
    """Overall verdict of package integrity inspection."""
    SAFE = "SAFE"
    TAMPERED = "TAMPERED"
    COMPROMISED = "COMPROMISED"
    INCONCLUSIVE = "INCONCLUSIVE"


class FileStatus(str, Enum):
    """Per-file classification defined in Hacktoberfest Problem 4 spec."""
    IDENTICAL = "IDENTICAL"
    DEV_ONLY_STRIPPED = "DEV_ONLY_STRIPPED"
    EXPECTED_BUILD_ARTIFACT = "EXPECTED_BUILD_ARTIFACT"
    EXPECTED_METADATA = "EXPECTED_METADATA"
    MODIFIED_SOURCE = "MODIFIED_SOURCE"
    SUSPICIOUS_MANIFEST = "SUSPICIOUS_MANIFEST"
    CAPABILITY_ESCALATION = "CAPABILITY_ESCALATION"
    UNMAPPED_GHOST_FILE = "UNMAPPED_GHOST_FILE"


class Severity(str, Enum):
    """Severity rating for security triage."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Archetype(str, Enum):
    """The 3 mandatory evaluation archetypes defined by Hacktoberfest organizers."""
    CASE_1_EXPECTED_BUILD = "CASE_1_EXPECTED_BUILD"
    CASE_2_MANIFEST_TAMPERING = "CASE_2_MANIFEST_TAMPERING"
    CASE_3_GHOST_OBFUSCATED = "CASE_3_GHOST_OBFUSCATED"
    UNCLASSIFIED = "UNCLASSIFIED"


@dataclass
class PackageMetadata:
    """Metadata of an ingested package archive."""
    name: str
    version: str
    ecosystem: str  # "npm", "pypi", or "local"
    archive_path: Path
    extracted_path: Path
    sha256: str
    tarball_url: Optional[str] = None
    git_head: Optional[str] = None
    repository_url: Optional[str] = None
    has_provenance: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["archive_path"] = str(self.archive_path)
        d["extracted_path"] = str(self.extracted_path)
        return d


@dataclass
class SourceMetadata:
    """Metadata of upstream source code tree."""
    source_path: Path
    ref_matched: str  # Tag name, commit SHA, or "local"
    exact_version_matched: bool = True
    repo_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["source_path"] = str(self.source_path)
        return d


@dataclass
class Finding:
    """Represents a single analyzed discrepancy between package and source repository."""
    file_path: str
    classification: FileStatus
    severity: Severity
    verdict: Optional[Verdict] = None
    entropy: Optional[float] = None
    evidence: List[str] = field(default_factory=list)
    diff_snippet: str = ""
    explanation: str = ""
    archetype: Archetype = Archetype.UNCLASSIFIED

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["classification"] = self.classification.value
        d["severity"] = self.severity.value
        d["archetype"] = self.archetype.value
        if self.verdict is not None:
            d["verdict"] = self.verdict.value
        return d


@dataclass
class ScanReport:
    """Complete machine-readable and human-verifiable scan report (Problem 4 spec)."""
    package_name: str
    version: str
    ecosystem: str  # "npm" | "pypi" | "local"
    source_ref: str
    archive_sha256: str
    provenance_verified: bool = False
    summary_counts: Dict[str, int] = field(default_factory=lambda: {
        "identical": 0,
        "expected_artifacts": 0,
        "stripped_dev_files": 0,
        "suspicious": 0,
        "critical": 0,
    })
    verdict: Verdict = Verdict.SAFE
    model_used: str = "qwen2.5-coder:7b (ollama)"
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "source_ref": self.source_ref,
            "archive_sha256": self.archive_sha256,
            "provenance_verified": self.provenance_verified,
            "summary_counts": self.summary_counts,
            "verdict": self.verdict.value,
            "model_used": self.model_used,
            "findings": [f.to_dict() for f in self.findings],
        }
