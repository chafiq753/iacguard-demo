"""
Aggregator iac-guard.

Lit les sorties JSON brutes de Gitleaks, Checkov et OPA/Conftest, les
normalise en `Finding` (schéma unifié), construit un `ScanReport` et
le POST à l'API backend, authentifié par le token du projet.

Usage (dans le pipeline GitHub Actions) :

    python aggregator.py \
        --gitleaks gitleaks.json \
        --checkov  checkov.json \
        --conftest conftest.json \
        --repo "$GITHUB_REPOSITORY" \
        --branch "$GITHUB_REF_NAME" \
        --commit "$GITHUB_SHA" \
        --api-url "$IACGUARD_API_URL" \
        --token   "$IACGUARD_TOKEN"

En l'absence de --api-url, le rapport est imprimé sur stdout (mode debug).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from schema import (
    Category,
    Finding,
    ScanMeta,
    ScanReport,
    Severity,
    ToolInfo,
    ToolName,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

# Sévérité déclarée en toutes lettres (Checkov, metadata Rego) -> enum.
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
}


def _norm_severity(value: Any, default: Severity) -> Severity:
    """Convertit une sévérité texte en enum, avec fallback si absente/inconnue."""
    if not value:
        return default
    return _SEVERITY_MAP.get(str(value).strip().lower(), default)


def _load_json(path: str | None) -> Any:
    """Charge un fichier JSON ; retourne None si le chemin est absent/vide."""
    if not path:
        return None
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return None
    with p.open(encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Parsers : un par outil, sortie brute -> list[Finding]
# --------------------------------------------------------------------------- #


def parse_gitleaks(data: Any) -> list[Finding]:
    """
    Gitleaks (`gitleaks detect -f json`) : liste plate de secrets détectés.
    Pas de sévérité native -> un secret exposé est traité comme CRITICAL.
    """
    if not data:
        return []
    findings: list[Finding] = []
    for item in data:
        findings.append(
            Finding(
                source=ToolName.GITLEAKS,
                category=Category.SECRET,
                rule_id=item.get("RuleID", "unknown"),
                title=item.get("Description", "Secret détecté"),
                severity=Severity.CRITICAL,
                resource=None,
                file=item.get("File"),
                line_start=item.get("StartLine"),
                line_end=item.get("EndLine"),
                remediation="Retirer le secret du code, le révoquer et le stocker "
                "dans un gestionnaire de secrets (Vault, SSM, GitHub Secrets).",
                raw=item,
            )
        )
    return findings


def parse_checkov(data: Any) -> list[Finding]:
    """
    Checkov (`checkov -o json`) : objet {results: {failed_checks: [...]}}.
    Peut aussi être une liste d'objets (plusieurs frameworks) -> on gère les deux.
    Sévérité présente seulement si liée à la plateforme Prisma, sinon MEDIUM.
    """
    if not data:
        return []
    reports = data if isinstance(data, list) else [data]
    findings: list[Finding] = []
    for report in reports:
        failed = (report.get("results") or {}).get("failed_checks") or []
        for chk in failed:
            line_range = chk.get("file_line_range") or [None, None]
            findings.append(
                Finding(
                    source=ToolName.CHECKOV,
                    category=Category.MISCONFIGURATION,
                    rule_id=chk.get("check_id", "unknown"),
                    title=chk.get("check_name", "Mauvaise configuration"),
                    severity=_norm_severity(chk.get("severity"), Severity.MEDIUM),
                    resource=chk.get("resource"),
                    file=chk.get("repo_file_path") or chk.get("file_path"),
                    line_start=line_range[0],
                    line_end=line_range[1] if len(line_range) > 1 else None,
                    remediation=chk.get("guideline"),
                    raw=chk,
                )
            )
    return findings


def parse_conftest(data: Any) -> list[Finding]:
    """
    Conftest (`conftest test -o json`) : liste de résultats par fichier.
    `failures` -> findings, `warnings` -> findings de plus faible sévérité.
    La sévérité/titre/remédiation viennent de la metadata Rego quand présents ;
    sinon fallback (choix produit : la règle Rego porte sa sévérité).
    """
    if not data:
        return []
    findings: list[Finding] = []
    for block in data:
        filename = block.get("filename")
        for kind, default_sev in (("failures", Severity.HIGH), ("warnings", Severity.LOW)):
            for entry in block.get(kind) or []:
                meta = entry.get("metadata") or {}
                findings.append(
                    Finding(
                        source=ToolName.CONFTEST,
                        category=Category.POLICY,
                        rule_id=meta.get("rule_id") or block.get("namespace") or "policy",
                        title=meta.get("title") or entry.get("msg", "Violation de règle métier"),
                        severity=_norm_severity(meta.get("severity"), default_sev),
                        resource=meta.get("resource"),
                        file=filename,
                        line_start=None,
                        line_end=None,
                        remediation=meta.get("remediation"),
                        raw=entry,
                    )
                )
    return findings


# --------------------------------------------------------------------------- #
# Assemblage + envoi
# --------------------------------------------------------------------------- #


def build_report(args: argparse.Namespace) -> ScanReport:
    gitleaks_data = _load_json(args.gitleaks)
    checkov_data = _load_json(args.checkov)
    conftest_data = _load_json(args.conftest)

    findings: list[Finding] = []
    findings += parse_gitleaks(gitleaks_data)
    findings += parse_checkov(checkov_data)
    findings += parse_conftest(conftest_data)

    tools: list[ToolInfo] = []
    if gitleaks_data is not None:
        tools.append(ToolInfo(name=ToolName.GITLEAKS))
    if checkov_data is not None:
        version = (
            (checkov_data if isinstance(checkov_data, dict) else {})
            .get("summary", {})
            .get("checkov_version")
        )
        tools.append(ToolInfo(name=ToolName.CHECKOV, version=version))
    if conftest_data is not None:
        tools.append(ToolInfo(name=ToolName.CONFTEST))

    meta = ScanMeta(
        repo=args.repo,
        branch=args.branch,
        commit_sha=args.commit,
        created_at=datetime.now(timezone.utc),
        tools=tools,
    )
    return ScanReport.build(meta, findings)


def send_report(report: ScanReport, api_url: str, token: str) -> None:
    """POST du rapport à l'API. Import local pour ne pas exiger requests en debug."""
    import requests  # noqa: PLC0415

    resp = requests.post(
        api_url.rstrip("/") + "/api/scans",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=report.model_dump_json(),
        timeout=30,
    )
    resp.raise_for_status()
    print(f"[iac-guard] Rapport envoyé ({report.summary.total} findings) -> HTTP {resp.status_code}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregator iac-guard")
    parser.add_argument("--gitleaks", help="Chemin du JSON Gitleaks")
    parser.add_argument("--checkov", help="Chemin du JSON Checkov")
    parser.add_argument("--conftest", help="Chemin du JSON Conftest")
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--branch")
    parser.add_argument("--commit")
    parser.add_argument("--api-url", help="URL de base de l'API (sinon: print stdout)")
    parser.add_argument("--token", help="Token API du projet")
    args = parser.parse_args(argv)

    # Nettoie les espaces/retours à la ligne collés par erreur dans les
    # secrets CI (un \r\n invisible suffit à casser la résolution DNS).
    api_url = (args.api_url or "").strip()
    token = (args.token or "").strip()

    report = build_report(args)

    if api_url and token:
        send_report(report, api_url, token)
    else:
        print(json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
