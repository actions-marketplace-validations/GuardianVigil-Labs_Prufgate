# syntax=docker/dockerfile:1
# PrufGate container: Python 3.14 + the engines + ast-grep, gitleaks and zizmor

# ==============================================================================
# Stage 1: Static Binary Extractor (ast-grep, gitleaks, zizmor)
# ==============================================================================
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS binary-extractor

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    unzip \
    tar \
    gzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /out/bin

# Pinned releases, each verified against its SHA-256 before it is unpacked.
ARG ZIZMOR_VERSION=1.31.1
ARG GITLEAKS_VERSION=8.30.1
ARG AST_GREP_VERSION=0.51.0

RUN ARCH="${TARGETARCH:-$(dpkg --print-architecture)}" && \
    case "${ARCH}" in \
      arm64|aarch64) \
        ZIZMOR_ARCH="aarch64-unknown-linux-gnu"; ZIZMOR_SHA="37eebbd5762a44f262d94875431b14a6d2402991e90a685113ea97b8b41be833"; \
        GITLEAKS_ARCH="linux_arm64"; GITLEAKS_SHA="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"; \
        SG_ARCH="aarch64-unknown-linux-gnu"; SG_SHA="73af0ebe5958acee012754a5b2826a186580ef83333092408a7a01096fc30b8b" ;; \
      amd64|x86_64) \
        ZIZMOR_ARCH="x86_64-unknown-linux-gnu"; ZIZMOR_SHA="d185f726bdaf92df78273217dfdd24ebcd6b0ef48cf3ce776ff5762b6e138c99"; \
        GITLEAKS_ARCH="linux_x64"; GITLEAKS_SHA="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"; \
        SG_ARCH="x86_64-unknown-linux-gnu"; SG_SHA="a7eead5552d3a8daad70f5d50d935da44bd0c138e946b5b0a96b1d38169fa639" ;; \
      *) echo "unsupported architecture: ${ARCH}" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/zizmor.tar.gz "https://github.com/zizmorcore/zizmor/releases/download/v${ZIZMOR_VERSION}/zizmor-${ZIZMOR_ARCH}.tar.gz" && \
    curl -fsSL -o /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GITLEAKS_ARCH}.tar.gz" && \
    curl -fsSL -o /tmp/sg.zip "https://github.com/ast-grep/ast-grep/releases/download/${AST_GREP_VERSION}/app-${SG_ARCH}.zip" && \
    printf '%s  %s\n' "${ZIZMOR_SHA}" /tmp/zizmor.tar.gz "${GITLEAKS_SHA}" /tmp/gitleaks.tar.gz "${SG_SHA}" /tmp/sg.zip | sha256sum -c - && \
    tar -xzf /tmp/zizmor.tar.gz -C /out/bin zizmor && \
    tar -xzf /tmp/gitleaks.tar.gz -C /out/bin gitleaks && \
    unzip -q -o /tmp/sg.zip -d /out/bin && \
    chmod +x /out/bin/zizmor /out/bin/gitleaks /out/bin/ast-grep /out/bin/sg && \
    rm -f /tmp/zizmor.tar.gz /tmp/gitleaks.tar.gz /tmp/sg.zip


# ==============================================================================
# Stage 2: runtime
# ==============================================================================
FROM python:3.14-slim-bookworm@sha256:945c2676dc2b18e0c1f16879244122c57c0ffede60006bf3df159c507a31bcae AS core

# tests/test_workflows.py keeps the version equal to prufgate.__version__.
LABEL org.opencontainers.image.title="PrufGate" \
      org.opencontainers.image.description="Checks whether code, and the tests that claim it works, are real" \
      org.opencontainers.image.version="1.2.0" \
      org.opencontainers.image.source="https://github.com/GuardianVigil-Labs/Prufgate" \
      org.opencontainers.image.url="https://github.com/GuardianVigil-Labs/Prufgate" \
      org.opencontainers.image.documentation="https://github.com/GuardianVigil-Labs/Prufgate/tree/main/docs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="GuardianVigil"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    gosu \
    && rm -rf /var/lib/apt/lists/*


COPY --from=binary-extractor /out/bin/* /usr/local/bin/
RUN ln -sf /usr/local/bin/ast-grep /usr/local/bin/sg 2>/dev/null || true

ENV HOME=/home/prufgate
ENV XDG_CACHE_HOME=/home/prufgate/.cache
ENV PATH="/usr/local/bin:$PATH"

RUN groupadd -g 1000 prufgategroup 2>/dev/null || true && \
    useradd -u 1000 -g 1000 -d /home/prufgate -s /bin/bash prufgateuser 2>/dev/null || true && \
    mkdir -p /home/prufgate/.cache /workspace /tools/prufgate && \
    chown -R 1000:0 /home/prufgate /workspace && \
    chmod -R 1775 /home/prufgate /workspace

COPY . /tools/prufgate/
# The `prufgate` and `prufgate-mcp` commands, from this checkout. PyYAML and the
# build backend come from the hash-locked requirements.txt, so nothing unpinned
# is downloaded.
RUN python3 -m pip install --no-cache-dir --require-hashes -r /tools/prufgate/requirements.txt && \
    python3 -m pip wheel --no-cache-dir --no-deps --no-build-isolation -w /tmp/wheel /tools/prufgate && \
    python3 -m pip install --no-cache-dir --no-deps /tmp/wheel/*.whl && \
    rm -rf /tmp/wheel && \
    rm -rf /tools/prufgate/build /tools/prufgate/*.egg-info && \
    chmod +x /tools/prufgate/prufgate.sh /tools/prufgate/entrypoint.sh /tools/prufgate/bin/prufgate /tools/prufgate/runners/*.sh

WORKDIR /workspace

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/tools/prufgate/bin/prufgate", "--help"]

# Entrypoint drops privileges dynamically to host workspace UID/GID via gosu
USER 0:0

ENTRYPOINT ["/tools/prufgate/entrypoint.sh"]
CMD ["fast"]
