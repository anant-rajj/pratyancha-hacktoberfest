"""
Core domain models and structured data contracts for VeriPack.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional


class Verdict(str, Enum):
    """Overall verdict of package integrity inspection."""
    SAFE = "SAFE"
    WARNING = "WARNING"
    COMPROMISED = "COMPROMISED"


class FileStatus(str, Enum):
    """Classification of an individual file discrepancy."""
    MATCHED = "MATCHED"
    MODIFIED = "MODIFIED"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    EXPECTED_ARTIFACT = "EXPECTED_ARTIFACT"
    SUSPICIOUS_HOOK = "SUSPICIOUS_HOOK"
    GHOST_OBFUSCATED = "GHOST_OBFUSCATED"


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
class Finding:
    """Represents a single analyzed discrepancy between package and source repository."""
    file_path: str
    verdict: Verdict
    status: FileStatus
    severity: Severity
    archetype: Archetype
    title: str
    explanation: str
    diff_hunk: Optional[str] = None
    entropy: Optional[float] = None
    ast_markers: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanSummary:
    """Summary metrics of the scan."""
    total_package_files: int = 0
    total_source_files: int = 0
    matched_files: int = 0
    expected_artifacts: int = 0
    manifest_modifications: int = 0
    ghost_files: int = 0
    overall_verdict: Verdict = Verdict.SAFE
    overall_score: float = 100.0  # 100 = verified, 0 = critical compromise

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    """Complete machine-readable and human-verifiable scan report."""
    package_name: str
    package_version: str
    source_target: str
    summary: ScanSummary = field(default_factory=ScanSummary)
    findings: List[Finding] = field(default_factory=list)
    models_consulted: List[str] = field(default_factory=list)
    provenance_verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
