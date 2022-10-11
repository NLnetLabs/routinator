# This is a multi-stage Dockerfile, with a selectable first stage. With this
# approach we get:
#
#   1. Separation of dependencies needed to build our app in the 'build' stage
#      and those needed to run our app in the 'final' stage, as we don't want
#      the build-time dependencies to be included in the final Docker image.
#
#   2. Support for either building our app for the architecture of the base
#      image using MODE=build (the default) or for externally built app
#      binaries (e.g. cross-compiled) using MODE=copy.
#
# In total there are four stages consisting of:
#   - Two possible first stages: 'build' or 'copy'.
#   - A special 'source' stage which selects either 'build' or 'copy' as the
#     source of binaries to be used by ...
#   - The 'final' stage.


###
### ARG DEFINITIONS ###########################################################
###

# This section defines arguments that can be overriden on the command line
# when invoking `docker build` using the argument form:
#
#   `--build-arg <ARGNAME>=<ARGVALUE>`.

# MODE
# ====
# Supported values: build (default), copy
#
# By default this Dockerfile will build our app from sources. If the sources
# have already been (cross) compiled by some external process and you wish to
# use the resulting binaries from that process, then:
#
#   1. Create a directory on the host called 'dockerbin/$TARGETPLATFORM'
#      containing the already compiled app binaries (where $TARGETPLATFORM
#      is a special variable set by Docker BuiltKit).
#   2. Supply arguments `--build-arg MODE=copy` to `docker build`.
ARG MODE=build


# BASE_IMG
# ========
#
# Only used when MODE=build.
ARG BASE_IMG=alpine:3.16


# CARGO_ARGS
# ==========
#
# Only used when MODE=build.
#
# This ARG can be used to control the features enabled when compiling the app
# or other compilation settings as necessary.
ARG CARGO_ARGS


###
### BUILD STAGES ##############################################################
###


# -----------------------------------------------------------------------------
# Docker stage: build
# -----------------------------------------------------------------------------
#
# Builds our app binaries from sources.
FROM ${BASE_IMG} AS build
ARG CARGO_ARGS

RUN apk add --no-cache rust cargo

WORKDIR /tmp/build
COPY . .

# `CARGO_HTTP_MULTIPLEXING` forces Cargo to use HTTP/1.1 without pipelining
# instead of HTTP/2 with multiplexing. This seems to help with various
# "spurious network error" warnings when Cargo attempts to fetch from crates.io
# when building this image on Docker Hub and GitHub Actions build machines.
#
# `cargo install` is used instead of `cargo build` because it places just the
# binaries we need into a predictable output directory. We can't control this
# with arguments to cargo build as `--out-dir` is unstable and contentious and
# `--target-dir` still requires us to know which profile and target the
# binaries were built for. By using `cargo install` we can also avoid needing
# to hard-code the set of binary names to copy so that if we add or remove
# built binaries in future this will "just work". Note that `--root /tmp/out`
# actually causes the binaries to be placed in `/tmp/out/bin/`. `cargo install`
# will create the output directory for us.
RUN CARGO_HTTP_MULTIPLEXING=false cargo install \
  --locked \
  --path . \
  --root /tmp/out/ \
  ${CARGO_ARGS}


# -----------------------------------------------------------------------------
# Docker stage: copy
# -----------------------------------------------------------------------------
# Only used when MODE=copy.
#
# Copy binaries from the host directory 'dockerbin/$TARGETPLATFORM' directory
# into this build stage to the same predictable location that binaries would be
# in if MODE were 'build'.
#
# Requires that `docker build` be invoked with variable `DOCKER_BUILDKIT=1` set
# in the environment. This is necessary so that Docker will skip the unused
# 'build' stage and so that the magic $TARGETPLATFORM ARG will be set for us.
FROM ${BASE_IMG} AS copy
ARG TARGETPLATFORM
ONBUILD COPY dockerbin/$TARGETPLATFORM /tmp/out/bin/


# -----------------------------------------------------------------------------
# Docker stage: source
# -----------------------------------------------------------------------------
# This is a "magic" build stage that "labels" a chosen prior build stage as the
# one that the build stage after this one should copy application binaries
# from. It also causes the ONBUILD COPY command from the 'copy' stage to be run
# if needed. Finally, we ensure binaries have the executable flag set because
# when copied in from outside they may not have the flag set, especially if
# they were uploaded as a GH actions artifact then downloaded again which
# causes file permissions to be lost.
# See: https://github.com/actions/upload-artifact#permission-loss
FROM ${MODE} AS source
RUN chmod a+x /tmp/out/bin/*


# -----------------------------------------------------------------------------
# Docker stage: final
# -----------------------------------------------------------------------------
# Create an image containing just the binaries, configs & scripts needed to run
# our app, and not the things needed to build it.
#
# The previous build stage from which binaries are copied is controlled by the
# MODE ARG (see above).
FROM alpine:3.16 AS final

# Copy binaries from the 'source' build stage into the image we are building
COPY --from=source /tmp/out/bin/* /usr/local/bin/

# Build variables for uid and guid of user to run container
ARG RUN_USER=routinator
ARG RUN_USER_UID=1012
ARG RUN_USER_GID=1012

# Install required runtime dependencies
RUN apk add --no-cache libgcc rsync tini

RUN addgroup -g ${RUN_USER_GID} ${RUN_USER} && \
    adduser -D -u ${RUN_USER_UID} -G ${RUN_USER} ${RUN_USER}

# Create the repository and TAL directories
RUN mkdir -p /home/${RUN_USER}/.rpki-cache/repository && \
    chown -R ${RUN_USER_UID}:${RUN_USER_GID} /usr/local/bin/routinator /home/${RUN_USER}/.rpki-cache

# Switch to our applications user
USER $RUN_USER_UID

# Hint to operators the TCP port that the application in this image listens on
# (by default).
EXPOSE 3323/tcp
EXPOSE 9556/tcp

# Use Tini to ensure that our application responds to CTRL-C when run in the
# foreground without the Docker argument "--init" (which is actually another
# way of activating Tini, but cannot be enabled from inside the Docker image).
ENTRYPOINT ["/sbin/tini", "--", "routinator"]
CMD ["server", "--rtr", "0.0.0.0:3323", "--http", "0.0.0.0:9556"]
