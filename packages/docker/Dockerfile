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

# ── govulncheck (pinned Go builder stage) ───────────────────────────────────

FROM golang:1.27.4-bookworm AS govulncheck-builder

RUN go install golang.org/x/vuln/cmd/govulncheck@v1.10.0

FROM python:3.12-slim-bookworm AS base

ARG TARGETARCH

# ── Go toolchain and govulncheck from the builder stage ──────────────────────

COPY --from=govulncheck-builder /usr/local/go /usr/local/go
COPY --from=govulncheck-builder /go/bin/govulncheck /usr/local/bin/govulncheck
ENV PATH="/usr/local/go/bin:${PATH}"

# ── System packages ──────────────────────────────────────────────────────────

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    unzip \
    ca-certificates \
    perl \
    php-cli \
    libnet-ssleay-perl \
    liburi-perl \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# ── Composer (pinned and checksum verified) ───────────────────────────────────

ARG COMPOSER_VERSION=2.11.3
ARG COMPOSER_SHA256=04f8b003da4e3a2459056591fbfebd02b4dc3e5adeb158616b90cf55a65113ec

RUN curl -fsSL \
      "https://getcomposer.org/download/${COMPOSER_VERSION}/composer.phar" \
      -o /usr/local/bin/composer \
    && echo "${COMPOSER_SHA256}  /usr/local/bin/composer" | sha256sum -c - \
    && chmod 755 /usr/local/bin/composer


# ── Nikto (not in Debian repos — install from source) ───────────────────────

RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# ── Trivy ────────────────────────────────────────────────────────────────────

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Gitleaks (multi-arch) ────────────────────────────────────────────────────
# Pin version: api.github.com /releases/latest is often rate-limited in CI,
# which yields an empty tag and a 404 tarball (gzip: unexpected end of file).

ARG GITLEAKS_VERSION=8.30.1

RUN case "${TARGETARCH}" in \
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
# Pinned for the same GitHub API rate-limit reason as Gitleaks.

ARG TERRASCAN_VERSION=1.19.9

RUN case "${TARGETARCH}" in \
         amd64) TERRASCAN_ARCH=x86_64 ;; \
         arm64) TERRASCAN_ARCH=arm64 ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -sSfL \
      "https://github.com/tenable/terrascan/releases/download/v${TERRASCAN_VERSION}/terrascan_${TERRASCAN_VERSION}_Linux_${TERRASCAN_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin terrascan

# ── tfsec (multi-arch) ───────────────────────────────────────────────────────

ARG TFSEC_VERSION=1.28.14

RUN case "${TARGETARCH}" in \
         amd64) TFSEC_ARCH=amd64 ;; \
         arm64) TFSEC_ARCH=arm64 ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -sSfL \
      "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec_${TFSEC_VERSION}_linux_${TFSEC_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin tfsec

# ── tflint (multi-arch) ──────────────────────────────────────────────────────

ARG TFLINT_VERSION=0.66.0

RUN case "${TARGETARCH}" in \
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
# Pin version: v2.1.21+ tags may ship without linux binaries.

ARG KICS_VERSION=2.1.20

RUN case "${TARGETARCH}" in \
         amd64) KICS_ARCH=amd64 ;; \
         arm64) KICS_ARCH=arm64 ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -sSfL \
      "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics_${KICS_VERSION}_linux_${KICS_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin kics

# ── Terraform (multi-arch) ───────────────────────────────────────────────────

ARG TF_VERSION=1.17.2

RUN case "${TARGETARCH}" in \
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
LABEL org.opencontainers.image.source="https://github.com/argus-code-scanning/argus-codescan-mcp"
LABEL org.opencontainers.image.licenses="MIT"
