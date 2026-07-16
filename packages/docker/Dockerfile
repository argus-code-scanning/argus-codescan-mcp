# argus-scan Docker image
#
# Bundles the Argus MCP server plus open-source security scanners
# so users get everything in a single pull with no local installs.
#
# Usage (MCP server via stdio):
#   docker run --rm -i -v $(pwd):/workspace ghcr.io/okirigabriel/argus-codescan-mcp
#
# Usage (one-shot CLI scan):
#   docker run --rm -v $(pwd):/workspace ghcr.io/okirigabriel/argus-codescan-mcp \
#     scan all /workspace

FROM python:3.12-slim-bookworm AS base

ARG TARGETARCH

# ── System packages ──────────────────────────────────────────────────────────

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    unzip \
    ca-certificates \
    perl \
    libnet-ssleay-perl \
    liburi-perl \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# ── Nikto (not in Debian repos — install from source) ───────────────────────

RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# ── Trivy ────────────────────────────────────────────────────────────────────

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Gitleaks (multi-arch) ────────────────────────────────────────────────────

RUN GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
      | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && case "${TARGETARCH}" in \
         amd64) GITLEAKS_ARCH=x64 ;; \
         arm64) GITLEAKS_ARCH=arm64 ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -sSfL \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

# ── TruffleHog ───────────────────────────────────────────────────────────────

RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Terrascan (multi-arch) ───────────────────────────────────────────────────

RUN TERRASCAN_VERSION=$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest \
      | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && case "${TARGETARCH}" in \
         amd64) TERRASCAN_ARCH=x86_64 ;; \
         arm64) TERRASCAN_ARCH=arm64 ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -sSfL \
      "https://github.com/tenable/terrascan/releases/download/v${TERRASCAN_VERSION}/terrascan_${TERRASCAN_VERSION}_Linux_${TERRASCAN_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin terrascan

# ── tfsec (multi-arch) ───────────────────────────────────────────────────────

RUN TFSEC_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/tfsec/releases/latest \
      | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && case "${TARGETARCH}" in \
         amd64) TFSEC_ARCH=amd64 ;; \
         arm64) TFSEC_ARCH=arm64 ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -sSfL \
      "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec_${TFSEC_VERSION}_linux_${TFSEC_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin tfsec

# ── tflint (multi-arch) ──────────────────────────────────────────────────────

RUN TFLINT_VERSION=$(curl -s https://api.github.com/repos/terraform-linters/tflint/releases/latest \
      | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && case "${TARGETARCH}" in \
         amd64) TFLINT_ARCH=amd64 ;; \
         arm64) TFLINT_ARCH=arm64 ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -sSfL \
      "https://github.com/terraform-linters/tflint/releases/download/v${TFLINT_VERSION}/tflint_linux_${TFLINT_ARCH}.zip" \
      -o /tmp/tflint.zip \
    && unzip -q /tmp/tflint.zip -d /usr/local/bin \
    && rm /tmp/tflint.zip \
    && chmod +x /usr/local/bin/tflint

# ── KICS (multi-arch) ────────────────────────────────────────────────────────

RUN KICS_VERSION=$(curl -s https://api.github.com/repos/Checkmarx/kics/releases/latest \
      | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && case "${TARGETARCH}" in \
         amd64) KICS_ARCH=amd64 ;; \
         arm64) KICS_ARCH=arm64 ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -sSfL \
      "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics_${KICS_VERSION}_linux_${KICS_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin kics

# ── Terraform (multi-arch) ───────────────────────────────────────────────────

RUN TF_VERSION=$(curl -s https://api.github.com/repos/hashicorp/terraform/releases/latest \
      | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && case "${TARGETARCH}" in \
         amd64) TF_ARCH=amd64 ;; \
         arm64) TF_ARCH=arm64 ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -sSfL \
      "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_${TF_ARCH}.zip" \
      -o /tmp/terraform.zip \
    && unzip -q /tmp/terraform.zip -d /usr/local/bin \
    && rm /tmp/terraform.zip \
    && chmod +x /usr/local/bin/terraform

# ── Python packages (Argus + scanners) ───────────────────────────────────────

COPY packages/languages/ /tmp/argus-languages-src/
COPY packages/python/ /tmp/argus-scan-src/

RUN pip install --no-cache-dir \
    /tmp/argus-languages-src \
    /tmp/argus-scan-src \
    semgrep \
    bandit \
    flake8 \
    flake8-bandit \
    safety \
    pip-audit \
    detect-secrets \
    checkov \
    ansible-lint \
    && rm -rf /tmp/argus-languages-src /tmp/argus-scan-src

# ── Node.js tools ─────────────────────────────────────────────────────────────

RUN npm install -g --quiet eslint eslint-plugin-security \
    && npm cache clean --force

# ── Non-root user ─────────────────────────────────────────────────────────────

RUN useradd -m -s /bin/sh scanner
USER scanner
WORKDIR /workspace

# ── Entrypoint ────────────────────────────────────────────────────────────────

COPY --chmod=755 packages/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Metadata
LABEL org.opencontainers.image.title="argus-scan"
LABEL org.opencontainers.image.description="MCP server for code security testing (SAST, DAST, SCA, Secrets, IaC)"
LABEL org.opencontainers.image.source="https://github.com/OkiriGabriel/argus-codescan-mcp"
LABEL org.opencontainers.image.licenses="MIT"
