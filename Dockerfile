# ── Stage 1: builder ───────────────────────────────────────────────────────
# edition = "2024" requires rustc ≥ 1.85; the crate also uses let_chains
# and is_multiple_of which need a recent stable toolchain.
#
# NOTE: This build requires the anya-proprietary submodule to be populated
# and .cargo/config.toml to be present (path override for stubs → real crates).
# Without these, the build will fail with a "missing private scoring engine" error.
# See README.md § "Building from source" for details.
FROM rust:slim-bookworm AS builder

ARG VERSION

# Install only the libraries needed to link the binary
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Copy dependency manifests and stub/private crates ──────────────────────
# The workspace depends on anya-scoring and anya-data (path deps).
# .cargo/config.toml redirects stubs → anya-proprietary (the real code).
COPY Cargo.toml Cargo.lock ./
COPY anya-stubs ./anya-stubs
COPY anya-proprietary ./anya-proprietary
COPY .cargo ./.cargo

# The workspace Cargo.toml lists src-tauri as a member, which isn't present
# in this build context (excluded by .dockerignore). Remove it so cargo
# can resolve the workspace cleanly.
RUN sed -i 's/, "src-tauri"//' Cargo.toml && \
    sed -i 's/"src-tauri", //' Cargo.toml && \
    sed -i 's/"src-tauri"//' Cargo.toml

# ── Layer caching: compile all dependencies before touching our source ──────
# Create minimal stub sources — just enough to let cargo compile the external
# dependency graph. The stub itself may fail to compile; that's fine because
# by the time cargo reaches our code all third-party crates are compiled and
# will be cached in this Docker layer.
RUN mkdir -p src && \
    printf 'pub fn _stub() {}\n' > src/lib.rs && \
    printf 'fn main() {}\n'      > src/main.rs

RUN cargo build --release -p anya-security-core 2>/dev/null || true

# Remove stub artifacts AND cargo fingerprints so our real code is
# recompiled cleanly. Without removing .fingerprint entries, cargo
# thinks the stub binary is still valid and skips recompilation.
RUN rm -rf target/release/.fingerprint/anya-* \
           target/release/deps/anya-* \
           target/release/deps/anya_* \
           target/release/deps/libanya_* \
           target/release/anya \
           target/release/anya.d

# ── Compile the real source ─────────────────────────────────────────────────
COPY src ./src

RUN cargo build --release -p anya-security-core

# Verify the binary was produced and strip debug symbols to minimise size.
# The [[bin]] in Cargo.toml sets name = "anya", so the binary is target/release/anya.
RUN ls -lh target/release/anya && \
    strip target/release/anya


# ── Stage 2: minimal runtime image ─────────────────────────────────────────
# The binary links only libc + libgcc_s (no OpenSSL). distroless/cc has
# exactly those libs, no shell, no package manager — ~25 MB base.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

ARG VERSION

# Copy the stripped binary
COPY --from=builder /build/target/release/anya /usr/local/bin/anya

# Volumes
# /samples  — mount PE/ELF files to analyse (recommend read-only)
# /output   — analysis results written here
# /config   — optional config file override (~/.config/anya/config.toml layout)
VOLUME ["/samples", "/output", "/config"]

# distroless/cc-debian12:nonroot already runs as uid 65532 (nonroot)

LABEL org.opencontainers.image.title="Anya" \
      org.opencontainers.image.description="Privacy-first PE/ELF malware analyser" \
      org.opencontainers.image.licenses="AGPL-3.0" \
      org.opencontainers.image.source="https://github.com/elementmerc/anya" \
      org.opencontainers.image.version="${VERSION}"

ENTRYPOINT ["/usr/local/bin/anya"]
CMD ["--help"]
