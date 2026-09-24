# One image: the API, the migration tools, and the built web app.
#
# The web build is copied in rather than served by its own container. That decision and
# its reasoning live in crates/uops-server/src/web.rs — briefly, this product is
# installed on-premise and every image is a thing to transfer, scan and patch, and a
# proxy container here would sit behind the operator's own proxy anyway.
#
# Built from the repository root:
#
#     docker build -f deploy/Dockerfile -t uops .
#
# or, more usually, by `docker compose up` from deploy/docker-compose.yml.

# --- the web app ------------------------------------------------------------------
FROM node:22-alpine AS web

WORKDIR /build
# The lockfile alone first, so a change to application source does not re-download the
# dependency tree.
COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build


# --- the server -------------------------------------------------------------------
FROM rust:1.98-alpine AS server

# musl-dev for the C toolchain rustc's linker calls.
#
# openssl-dev and pkgconfig because this workspace *does* link OpenSSL on Linux, which the
# comment here used to deny. `uops-oidc` uses `ureq` with `native-tls`, and `native-tls` is
# SChannel on Windows, Security.framework on macOS and **OpenSSL on Linux** — so a build on
# a developer's Windows machine never pulls `openssl-sys` and this image always did. The
# result was `Could not find directory of OpenSSL installation` and a failed image build on
# every push, which nobody saw because three other jobs were failing too.
#
# Dynamically linked against Alpine's OpenSSL rather than vendored: Alpine patches it, and
# vendoring would compile OpenSSL from source on every cold build to save a 3 MB runtime
# dependency the base image already carries. The musl *tarball* in `release-artefacts` is a
# different question — a static binary handed to a host with no container runtime cannot
# rely on that host having libssl, and that job has never run. See docs/packaging.md.
RUN apk add --no-cache musl-dev openssl-dev pkgconfig

WORKDIR /build

# SQLX_OFFLINE, because there is no database at build time and there must not be one.
# A build that needs to reach a live PostgreSQL to compile is a build that cannot run
# in an air-gapped CI, which is exactly where this product's customers build.
ENV SQLX_OFFLINE=true

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .sqlx/ .sqlx/
COPY crates/ crates/
# Both are read at compile time, not at run time: migrations by sqlx::migrate! in
# uops-pg-migrate, profiles by include_str! in uops-profile. Leave either out and the
# build fails here rather than the image shipping without them.
COPY migrations/ migrations/
COPY profiles/ profiles/

# --workspace --bins: every binary in this workspace ships in this image, and keeps
# shipping when one is added. Naming them individually is a list that goes stale
# silently — the image builds, and the thing you added is simply not in it.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --workspace --bins && \
    # Out of the cache mount, which does not survive this layer.
    #
    # By pattern rather than by name, because the comment above was right and the list that
    # used to be here was not: `uops-collector-flow` and `uops-runner` arrived with M7 and
    # M10 and never reached this line. The only artefact this repository has could not
    # collect a flow or execute a runbook run — and the runner is a queue with no consumer,
    # which reports nothing anywhere. `docs/packaging.md` §2.
    #
    # A glob and a delete, rather than `find` with predicates BusyBox may not have: cargo
    # writes a `.d` dependency file beside each binary, and those are the only other
    # `uops-*` in that directory. A binary added next year ships by existing.
    cp target/release/uops-* /usr/local/bin/ && \
    rm -f /usr/local/bin/*.d


# --- what actually ships ----------------------------------------------------------
FROM alpine:3.21

# ca-certificates *is* for us, which the comment here used to deny. The outbound OIDC
# client speaks TLS directly to an identity provider — `docs/security-overview.md` calls it
# "the one exception" — and validates it against the operating system's trust store, which
# is this file. Without it, SSO discovery fails on a correctly configured provider.
#
# openssl for libssl.so, since the binaries are dynamically linked against it now. libgcc is
# what a musl Rust binary needs.
RUN apk add --no-cache ca-certificates libgcc openssl

# Not root. There is nothing in this image that needs to be, and a container that runs
# as root is a finding in every procurement checklist this product will meet.
RUN addgroup -S uops && adduser -S -G uops uops

# One image, every binary. Which one runs is the entrypoint's business — see
# docker-compose.yml, where the poller is the same image with a different command. Two
# images would be two builds, two pushes and two chances for the poller to be a version
# behind the API that wrote the credentials it reads.
# The whole directory, for the same reason the `find` above exists: a list of names here
# is the same staleness one layer later.
COPY --from=server /usr/local/bin/ /usr/local/bin/
COPY --from=web /build/dist /srv/web
COPY migrations/ /srv/migrations/
COPY ch-migrations/ /srv/ch-migrations/

ENV UOPS_WEB_ROOT=/srv/web \
    UOPS_BIND=0.0.0.0:8080

USER uops
EXPOSE 8080

# No HEALTHCHECK here: compose declares it, where it can be read next to the thing that
# depends on it. Two places to look for one answer is one too many.

ENTRYPOINT ["/usr/local/bin/uops-server"]
