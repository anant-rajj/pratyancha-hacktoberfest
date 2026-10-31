"""
Core domain models and structured data contracts for VeriPack.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Archetype(str, Enum):
    CASE_1_EXPECTED_BUILD = "CASE_1_EXPECTED_BUILD"
    CASE_2_MANIFEST_TAMPERING = "CASE_2_MANIFEST_TAMPERING"
    CASE_3_GHOST_OBFUSCATED = "CASE_3_GHOST_OBFUSCATED"
    UNCLASSIFIED = "UNCLASSIFIED"


class StatusBadge(str, Enum):
    SAFE = "SAFE"
    WARNING = "WARNING"
    COMPROMISED = "COMPROMISED"


@dataclass
class Finding:
    """Represents a single analyzed discrepancy between package and source repository."""
    file_path: str
    status: StatusBadge
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
class AnalysisSummary:
    """Summary metrics of the package vs source code integrity scan."""
    total_package_files: int = 0
    total_source_files: int = 0
    matched_files: int = 0
    expected_artifacts: int = 0
    manifest_modifications: int = 0
    ghost_files: int = 0
    overall_status: StatusBadge = StatusBadge.SAFE
    overall_score: float = 100.0  # 100 = perfectly verified, 0 = critical compromise

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisReport:
    """Complete machine-readable and human-verifiable report."""
    package_name: str
    package_version: str
    source_target: str
    summary: AnalysisSummary = field(default_factory=AnalysisSummary)
    findings: List[Finding] = field(default_factory=list)
    models_consulted: List[str] = field(default_factory=list)
    provenance_verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
