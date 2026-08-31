"""Secret remediation guidance catalog."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RemediationGuide:
    title: str
    steps: list[str]
    references: list[str]


REMEDIATION_CATALOG: dict[str, RemediationGuide] = {
    "aws": RemediationGuide(
        title="AWS Access Key",
        steps=[
            "Disable or delete the exposed IAM access key in AWS IAM console.",
            "Create a new access key and store it in a secrets manager (AWS Secrets Manager, Vault).",
            "Rotate any services that used the old key.",
            "Review CloudTrail for unauthorized API calls since the key was committed.",
            "Remove the secret from git history (git filter-repo or BFG) if it was pushed.",
        ],
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
        ],
    ),
    "aws-access-key": RemediationGuide(
        title="AWS Access Key",
        steps=[
            "Disable or delete the exposed IAM access key in AWS IAM console.",
            "Create a new access key and store it in a secrets manager.",
            "Review CloudTrail for unauthorized usage.",
            "Purge the secret from git history if pushed to a remote.",
        ],
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
        ],
    ),
    "awskeydetector": RemediationGuide(
        title="AWS Access Key",
        steps=[
            "Disable the exposed IAM access key immediately.",
            "Issue a new key via IAM and inject via environment or secrets manager.",
            "Audit CloudTrail logs for suspicious activity.",
        ],
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
        ],
    ),
    "github": RemediationGuide(
        title="GitHub Token",
        steps=[
            "Revoke the token at GitHub → Settings → Developer settings → Personal access tokens.",
            "Generate a new fine-grained token with minimum required scopes.",
            "Store the token in GitHub Actions secrets or a vault — never in source code.",
            "If leaked publicly, assume compromise and review repository audit log.",
        ],
        references=[
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation"
        ],
    ),
    "githubtokendetector": RemediationGuide(
        title="GitHub Token",
        steps=[
            "Revoke the token immediately in GitHub settings.",
            "Create a replacement with least-privilege scopes.",
            "Use GitHub Actions secrets or OIDC for CI instead of long-lived tokens.",
        ],
        references=[
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation"
        ],
    ),
    "privatekey": RemediationGuide(
        title="Private Key / SSH Key",
        steps=[
            "Treat the key as compromised — do not reuse it.",
            "Remove the public key from all authorized_keys / deploy keys.",
            "Generate a new key pair and update deployment configs.",
            "Purge the private key from git history if it was committed.",
        ],
        references=[
            "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/about-ssh"
        ],
    ),
    "privatekeydetector": RemediationGuide(
        title="Private Key",
        steps=[
            "Revoke and replace the key everywhere it is trusted.",
            "Generate a new key pair; store private keys only in secure vaults.",
            "Scrub git history if the key was pushed.",
        ],
        references=[
            "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/about-ssh"
        ],
    ),
    "stripe": RemediationGuide(
        title="Stripe API Key",
        steps=[
            "Roll the API key in Stripe Dashboard → Developers → API keys.",
            "Update applications and CI secrets with the new key.",
            "Review Stripe logs for unauthorized charges or API calls.",
        ],
        references=["https://stripe.com/docs/keys#rolling-keys"],
    ),
    "stripedetector": RemediationGuide(
        title="Stripe API Key",
        steps=[
            "Roll the key in Stripe Dashboard immediately.",
            "Update all integrations and remove the old key from code.",
        ],
        references=["https://stripe.com/docs/keys#rolling-keys"],
    ),
    "slack": RemediationGuide(
        title="Slack Token",
        steps=[
            "Revoke the token in Slack API → Your Apps → OAuth & Permissions.",
            "Reinstall the app or regenerate tokens as needed.",
            "Audit workspace for unauthorized bot activity.",
        ],
        references=["https://api.slack.com/authentication/rotation"],
    ),
    "slackdetector": RemediationGuide(
        title="Slack Token",
        steps=[
            "Revoke the token in Slack app settings.",
            "Rotate and store replacement in a secrets manager.",
        ],
        references=["https://api.slack.com/authentication/rotation"],
    ),
    "jwt": RemediationGuide(
        title="JWT Token",
        steps=[
            "If this is a signing secret, rotate the secret and invalidate existing tokens.",
            "If this is a bearer token, revoke sessions and force re-authentication.",
            "Never commit JWT secrets or long-lived tokens to source control.",
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
        ],
    ),
    "jwttokendetector": RemediationGuide(
        title="JWT Token",
        steps=[
            "Rotate signing secrets and invalidate outstanding tokens.",
            "Use short-lived tokens with refresh flow; store secrets in a vault.",
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
        ],
    ),
    "npm": RemediationGuide(
        title="NPM Token",
        steps=[
            "Revoke the token at npmjs.com → Access Tokens.",
            "Create a new automation or granular token with minimal publish scope.",
            "Use npm trusted publishing or CI OIDC where possible.",
        ],
        references=["https://docs.npmjs.com/revoking-access-tokens"],
    ),
    "npmdetector": RemediationGuide(
        title="NPM Token",
        steps=[
            "Revoke the token on npmjs.com immediately.",
            "Replace with a scoped automation token stored in CI secrets.",
        ],
        references=["https://docs.npmjs.com/revoking-access-tokens"],
    ),
    "azure": RemediationGuide(
        title="Azure Storage Key",
        steps=[
            "Regenerate storage account keys in Azure Portal.",
            "Update all applications using the old key.",
            "Prefer managed identities over account keys where possible.",
        ],
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"
        ],
    ),
    "azurestoragekeydetector": RemediationGuide(
        title="Azure Storage Key",
        steps=[
            "Regenerate keys in Azure Portal → Storage account → Access keys.",
            "Update connection strings in apps and CI secrets.",
        ],
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"
        ],
    ),
    "generic": RemediationGuide(
        title="Exposed Secret",
        steps=[
            "Assume the secret is compromised — rotate or revoke it immediately.",
            "Remove the value from source code; load from environment or a secrets manager.",
            "If pushed to a remote, purge from git history and force rotation.",
            "Add a pre-commit hook or CI secret scan to prevent recurrence.",
        ],
        references=["https://github.com/gitleaks/gitleaks"],
    ),
}


def _normalize_key(value: str) -> str:
    return value.lower().replace("_", "").replace("-", "").replace(" ", "")


def lookup_remediation(rule_id: str, title: str = "", tool: str = "") -> RemediationGuide:
    """Find remediation guidance for a secret detector or rule."""
    candidates = [_normalize_key(rule_id), _normalize_key(title)]
    if tool:
        candidates.append(_normalize_key(tool))

    for key in candidates:
        if not key:
            continue
        for catalog_key, guide in REMEDIATION_CATALOG.items():
            norm_catalog = _normalize_key(catalog_key)
            if key == norm_catalog or norm_catalog in key or key in norm_catalog:
                return guide

    combined = _normalize_key(f"{rule_id}{title}")
    for token in ("aws", "github", "privatekey", "stripe", "slack", "jwt", "npm", "azure"):
        if token in combined and token in REMEDIATION_CATALOG:
            return REMEDIATION_CATALOG[token]

    return REMEDIATION_CATALOG["generic"]


def format_fix_guidance(rule_id: str, title: str = "", tool: str = "") -> str:
    """Return markdown fix guidance for a secret finding."""
    guide = lookup_remediation(rule_id, title, tool)
    lines = [f"**{guide.title} — remediation steps:**", ""]
    for i, step in enumerate(guide.steps, 1):
        lines.append(f"{i}. {step}")
    if guide.references:
        lines.append("")
        lines.append("**References:**")
        for ref in guide.references:
            lines.append(f"- {ref}")
    return "\n".join(lines)


def remediation_to_dict(rule_id: str, title: str = "", tool: str = "") -> dict:
    """Structured remediation for MCP/JSON consumers."""
    guide = lookup_remediation(rule_id, title, tool)
    return {
        "title": guide.title,
        "steps": list(guide.steps),
        "references": list(guide.references),
        "fix_guidance": format_fix_guidance(rule_id, title, tool),
    }
