"""
Schéma JSON unifié iac-guard.

Rôle : normaliser les sorties de Gitleaks, Checkov et OPA/Conftest en un
format commun. Ce module est la source de vérité du contrat pipeline -> API.
Il est volontairement autonome (aucune dépendance au backend) pour pouvoir
être copié/importé côté pipeline sans tirer tout le SaaS.

Le mapping réglementaire (CNDP / Bank Al-Maghrib) n'apparaît PAS ici :
le pipeline n'envoie que des faits techniques, l'enrichissement se fait
côté backend à partir du champ `rule_id`.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field

SCHEMA_VERSION = "1.0"


class Severity(str, Enum):
    """Sévérité normalisée, commune aux 3 outils."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    """Type de finding, utilisé pour grouper au dashboard."""

    SECRET = "secret"                      # Gitleaks
    MISCONFIGURATION = "misconfiguration"  # Checkov
    POLICY = "policy"                      # OPA/Conftest (règle métier)


class ToolName(str, Enum):
    GITLEAKS = "gitleaks"
    CHECKOV = "checkov"
    CONFTEST = "conftest"


class ToolInfo(BaseModel):
    """Un outil ayant participé au scan (nom + version)."""

    name: ToolName
    version: str | None = None


class ScanMeta(BaseModel):
    """Contexte du scan : d'où viennent les findings."""

    repo: str
    branch: str | None = None
    commit_sha: str | None = None
    created_at: datetime
    tools: list[ToolInfo] = Field(default_factory=list)


class Finding(BaseModel):
    """
    Un problème détecté, normalisé.

    `fingerprint` est calculé (déterministe) à partir de l'identité du
    finding : il permet la déduplication et le suivi dans le temps
    (un même finding qui réapparaît d'un scan à l'autre garde le même id).
    """

    source: ToolName
    category: Category
    rule_id: str                         # CKV_AWS_21, id de règle Gitleaks, nom de policy Rego
    title: str
    severity: Severity
    resource: str | None = None          # ex: aws_s3_bucket.data
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    remediation: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)  # objet brut de l'outil (audit/debug)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        """Hash stable de l'identité du finding (indépendant du contenu `raw`)."""
        parts = [
            self.source.value,
            self.rule_id,
            self.file or "",
            str(self.line_start or ""),
            self.resource or "",
        ]
        return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()


class Summary(BaseModel):
    """Compteurs agrégés, calculés à partir des findings."""

    total: int
    by_severity: dict[Severity, int]

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "Summary":
        counts = {sev: 0 for sev in Severity}
        for f in findings:
            counts[f.severity] += 1
        return cls(total=len(findings), by_severity=counts)


class ScanReport(BaseModel):
    """Racine : l'objet complet POSTé à l'API backend."""

    schema_version: str = SCHEMA_VERSION
    scan: ScanMeta
    summary: Summary
    findings: list[Finding]

    @classmethod
    def build(cls, scan: ScanMeta, findings: list[Finding]) -> "ScanReport":
        """Construit un rapport en calculant le summary automatiquement."""
        return cls(scan=scan, summary=Summary.from_findings(findings), findings=findings)
