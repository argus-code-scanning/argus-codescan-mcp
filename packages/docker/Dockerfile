# argus-scan Docker image
#
# Bundles the Python MCP server plus all supported open-source scanners
# so users get everything in a single pull with no local installs.
#
# Usage (MCP server via stdio):
#   docker run --rm -i -v $(pwd):/workspace ghcr.io/OkiriGabriel/argus-codescan-mcp
#
# Usage (one-shot scan):
#   docker run --rm -v $(pwd):/workspace ghcr.io/OkiriGabriel/argus-codescan-mcp \
#     argus scan sast /workspace

FROM python:3.12-slim-bookworm AS base

# ── System packages ──────────────────────────────────────────────────────────

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
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

# ── Gitleaks ─────────────────────────────────────────────────────────────────

RUN GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
      | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && curl -sSfL \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

# ── TruffleHog ───────────────────────────────────────────────────────────────

RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Terrascan ────────────────────────────────────────────────────────────────

RUN TERRASCAN_VERSION=$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest \
      | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && curl -sSfL \
      "https://github.com/tenable/terrascan/releases/download/v${TERRASCAN_VERSION}/terrascan_${TERRASCAN_VERSION}_Linux_x86_64.tar.gz" \
    | tar -xz -C /usr/local/bin terrascan

# ── Python tools ─────────────────────────────────────────────────────────────

COPY packages/python/ /tmp/argus-scan-src/

RUN pip install --no-cache-dir \
    /tmp/argus-scan-src \
    # Python security scanners
    semgrep \
    bandit \
    flake8 \
    flake8-bandit \
    safety \
    pip-audit \
    detect-secrets \
    checkov \
    && rm -rf /tmp/argus-scan-src

# ── Node.js tools ─────────────────────────────────────────────────────────────

RUN npm install -g --quiet eslint eslint-plugin-security \
    && npm cache clean --force

# ── Non-root user ─────────────────────────────────────────────────────────────

RUN useradd -m -s /bin/sh scanner
USER scanner
WORKDIR /workspace

# ── Entrypoint ────────────────────────────────────────────────────────────────

ENTRYPOINT ["python", "-m", "argus.server"]

# Metadata
LABEL org.opencontainers.image.title="argus-scan"
LABEL org.opencontainers.image.description="MCP server for code security testing (SAST, DAST, SCA, Secrets, IaC)"
LABEL org.opencontainers.image.source="https://github.com/OkiriGabriel/argus-codescan-mcp"
LABEL org.opencontainers.image.licenses="MIT"
