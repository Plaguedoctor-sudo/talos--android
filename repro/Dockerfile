# SPDX-FileCopyrightText: 2026 TALOS / LibreMobile OS Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# ==============================================================================
# TALOS / LibreMobile OS — Fallback Reproducible Container Environment
# Hermetically pinned debian:bookworm-slim container image by SHA-256 digest.
# TODO(operator): Pin can be refreshed when advancing Debian toolchain baselines
# ==============================================================================

FROM debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    LC_ALL=C \
    LANG=C

# Install hermetic toolchain requirements
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    make \
    python3 \
    nodejs \
    npm \
    e2fsprogs \
    git \
    tar \
    xz-utils \
    diffutils \
    ca-certificates \
    && git config --system --add safe.directory /workspace \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy workspace
COPY . /workspace

# Build and verify reproducibility
ENTRYPOINT ["/bin/bash", "-c", "make reproducible && python3 repro/verify-attestation.py repro/attestation-$(git rev-parse HEAD).json out/a"]
