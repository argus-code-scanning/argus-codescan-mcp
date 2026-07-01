"""Security scanning tool runners."""

from argus.tools.ansible import (
    run_all_ansible,
    run_ansible_lint,
    run_checkov_ansible,
    run_kics_ansible,
)
from argus.tools.dast import run_all_dast, run_nikto, run_zap_baseline
from argus.tools.iac import (
    run_all_iac,
    run_checkov,
    run_terrascan,
    run_trivy_config,
    run_trivy_image,
)
from argus.tools.sast import run_all_sast, run_bandit, run_eslint_security, run_semgrep
from argus.tools.sca import run_all_sca, run_npm_audit, run_pip_audit, run_safety, run_trivy_fs
from argus.tools.secrets import run_all_secrets, run_detect_secrets, run_gitleaks, run_trufflehog
from argus.tools.terraform import (
    run_all_terraform,
    run_checkov_terraform,
    run_kics_terraform,
    run_terraform_validate,
    run_tflint,
    run_tfsec,
)

__all__ = [
    # SAST
    "run_semgrep",
    "run_bandit",
    "run_eslint_security",
    "run_all_sast",
    # SCA
    "run_trivy_fs",
    "run_safety",
    "run_pip_audit",
    "run_npm_audit",
    "run_all_sca",
    # DAST
    "run_zap_baseline",
    "run_nikto",
    "run_all_dast",
    # Secrets
    "run_gitleaks",
    "run_detect_secrets",
    "run_trufflehog",
    "run_all_secrets",
    # IaC/Container
    "run_checkov",
    "run_trivy_config",
    "run_trivy_image",
    "run_terrascan",
    "run_all_iac",
    # Terraform
    "run_tfsec",
    "run_tflint",
    "run_terraform_validate",
    "run_kics_terraform",
    "run_checkov_terraform",
    "run_all_terraform",
    # Ansible
    "run_ansible_lint",
    "run_kics_ansible",
    "run_checkov_ansible",
    "run_all_ansible",
]
