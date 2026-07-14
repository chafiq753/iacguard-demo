# iacguard-demo

Dépôt Terraform **volontairement vulnérable** pour tester la plateforme
iac-guard de bout en bout : push → GitHub Actions → Gitleaks + Checkov →
aggregator → API iac-guard → dashboard.

Ne jamais déployer ce Terraform : il contient des mauvaises configurations
et des secrets factices, exprès.

## Configuration (une fois)

Dans GitHub : Settings → Secrets and variables → Actions

| Type     | Nom               | Valeur                                |
| -------- | ----------------- | ------------------------------------- |
| Secret   | `IACGUARD_TOKEN`  | le token du projet (`iacg_...`)       |
| Variable | `IACGUARD_API_URL`| URL publique de l'API (ex : tunnel)   |
