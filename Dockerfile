# syntax=docker/dockerfile:1

FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS rust-chef
WORKDIR /build
# CI needs runnable tests, not debug symbols or incremental object caches.
ENV CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
RUN rustup component add rustfmt clippy
RUN apt-get update && apt-get install -y --no-install-recommends cmake libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
RUN cargo install --locked --version 0.1.78 cargo-chef

FROM rust-chef AS rust-planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
COPY build.rs ./
RUN cargo chef prepare --recipe-path recipe.json

FROM rust-chef AS rust-dependencies
COPY --from=rust-planner /build/recipe.json ./recipe.json
# Ordinary layers persist in the GHA mode=max cache, including compiled dependencies.
# Match each validation/build command so both test and release dependencies are warm.
RUN cargo chef cook --locked --clippy --all-targets --recipe-path recipe.json
RUN cargo chef cook --locked --all-targets --recipe-path recipe.json
RUN cargo chef cook --locked --release --bins --recipe-path recipe.json

FROM rust-dependencies AS rust-builder
# Restore the real manifests and build script after cargo-chef's dummy project.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
COPY build.rs ./
ENV NM_PUBLIC_CONFIG_FIELDS_FILE=src/public_config_fields.txt
COPY docker/config.example.toml ./config.toml
COPY docker/config.example.toml ./docker/config.example.toml
RUN sed -i '/^masscan_output_mode =/d; /^masscan_wait_seconds =/d; /^masscan_max_runtime_seconds =/d' config.toml


# Always validate the real sources; correctness never depends on a warm cache.
RUN cargo fmt --check
RUN cargo clippy --locked --all-targets
RUN cargo test --locked --all-targets
RUN cargo build --locked --release --bins && mkdir /out && install -m 0755 target/release/scanner-rs target/release/scanner-worker target/release/scanner-package /out/

FROM golang:1.26.8-bookworm@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107 AS tools-builder
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpcap-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /tools
# All upstream tools are unmodified and fixed to reviewed commits.
RUN git init masscan && git -C masscan remote add origin https://github.com/robertdavidgraham/masscan.git \
    && git -C masscan fetch --depth=1 origin 06902c40d1494881c17b7968ef530e1d6bbd320c \
    && git -C masscan checkout --detach FETCH_HEAD && make -C masscan \
    && mkdir -p /out/licenses/masscan && cp masscan/bin/masscan /out/masscan && cp masscan/LICENSE /out/licenses/masscan/ \
    && rm -rf /tools/masscan
RUN git init zgrab2 && git -C zgrab2 remote add origin https://github.com/zmap/zgrab2.git \
    && git -C zgrab2 fetch --depth=1 origin ea734bcf60ef2921684cb522dfb87a07a322afa6 \
    && git -C zgrab2 checkout --detach FETCH_HEAD \
    && cd zgrab2 && go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/zgrab2 ./cmd/zgrab2 \
    && mkdir -p /out/licenses/zgrab2 && cp LICENSE* /out/licenses/zgrab2/ \
    && cp conf/blocklist.conf /out/zgrab2-blocklist.conf \
    && go clean -cache -modcache && cd /tools && rm -rf zgrab2
RUN git init nuclei && git -C nuclei remote add origin https://github.com/projectdiscovery/nuclei.git \
    && git -C nuclei fetch --depth=1 origin a8c88feb4a1c8e961b7902534ce3af97e9d524a4 \
    && git -C nuclei checkout --detach FETCH_HEAD \
    && cd nuclei && go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/nuclei ./cmd/nuclei \
    && mkdir -p /out/licenses/nuclei && cp LICENSE* /out/licenses/nuclei/ \
    && go clean -cache -modcache && cd /tools && rm -rf nuclei
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 libpcap0.8 && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 /var/lib/network-mapping-scanner /var/log/network-mapping-scanner /root/.config/zgrab2
WORKDIR /opt/network-mapping-scanner
COPY --from=rust-builder /out/scanner-rs /out/scanner-worker /out/scanner-package /usr/local/bin/
COPY --from=tools-builder /out/masscan /out/zgrab2 /out/nuclei /usr/local/bin/
COPY --from=tools-builder /out/zgrab2-blocklist.conf /root/.config/zgrab2/blocklist.conf
COPY --from=tools-builder /out/licenses ./licenses
COPY LICENSE ./licenses/LICENSE
COPY docker/THIRD_PARTY.md ./licenses/THIRD_PARTY.md
ARG VERSION=development
ARG REVISION=unknown
ARG TARGETARCH
LABEL org.opencontainers.image.title="network-mapping-scanner" \
      org.opencontainers.image.source="https://github.com/wshijiang/Network-Mapping-Scanner" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$REVISION
RUN printf 'scanner-version=%s\nscanner-commit=%s\narchitecture=%s\nrust=1.98.0\ngo=1.26.8\nmasscan-commit=06902c40d1494881c17b7968ef530e1d6bbd320c\nzgrab2-commit=ea734bcf60ef2921684cb522dfb87a07a322afa6\nnuclei-commit=a8c88feb4a1c8e961b7902534ce3af97e9d524a4\n' "$VERSION" "$REVISION" "$TARGETARCH" > BUILD-INFO
# Existing shutdown handling listens for SIGINT; use the same signal in Compose.
STOPSIGNAL SIGINT
ENV XDG_CONFIG_HOME=/var/lib/network-mapping-scanner/config XDG_CACHE_HOME=/var/lib/network-mapping-scanner/cache
ENTRYPOINT ["scanner-rs"]
CMD ["--config", "/etc/network-mapping-scanner/config.toml", "--database", "/var/lib/network-mapping-scanner/scanner-state.sqlite3", "--state-file", "/var/lib/network-mapping-scanner/scanner-state.json", "--log-directory", "/var/log/network-mapping-scanner"]
