# -- stage 0: some configuration
ARG BASE_IMG=alpine:3.16

# -- stage 1: build static routinator with musl libc for alpine
FROM ${BASE_IMG} as build

RUN apk add rust cargo

WORKDIR /tmp/routinator
COPY . .

# Force Cargo to use HTTP/1.1 without pipelining instead of HTTP/2 with
# multiplexing. This seems to help with various "spurious network error"
# warnings when Cargo attempts to fetch from crates.io when building this
# image on Docker Hub and GitHub Actions build machines. 
RUN CARGO_HTTP_MULTIPLEXING=false cargo build \
    --release \
    --locked

# -- stage 2: create alpine-based container with the static routinator
#             executable
FROM ${BASE_IMG}
COPY --from=build /tmp/routinator/target/release/routinator /usr/local/bin/

# Build variables for uid and guid of user to run container
ARG RUN_USER=routinator
ARG RUN_USER_UID=1012
ARG RUN_USER_GID=1012

# Install rsync as routinator depends on it
RUN apk add --no-cache rsync libgcc

# Use Tini to ensure that Routinator responds to CTRL-C when run in the
# foreground without the Docker argument "--init" (which is actually another
# way of activating Tini, but cannot be enabled from inside the Docker image).
RUN apk add --no-cache tini
# Tini is now available at /sbin/tini

RUN addgroup -g ${RUN_USER_GID} ${RUN_USER} && \
    adduser -D -u ${RUN_USER_UID} -G ${RUN_USER} ${RUN_USER}

# Create the repository and TAL directories
RUN mkdir -p /home/${RUN_USER}/.rpki-cache/repository /home/${RUN_USER}/.rpki-cache/tals && \
    chown -R ${RUN_USER_UID}:${RUN_USER_GID} /usr/local/bin/routinator /home/${RUN_USER}/.rpki-cache

# Due to ARIN TAL distribution terms, we can't do this here.
# An individual user, however, might want to anyway - after reviewing
# https://www.arin.net/resources/rpki/tal.html.
#
#COPY --from=build /tmp/routinator/tals/*.tal /home/${RUN_USER}/.rpki-cache/tals/

USER $RUN_USER_UID

EXPOSE 3323/tcp
EXPOSE 9556/tcp

ENTRYPOINT ["/sbin/tini", "--", "routinator"]
CMD ["server", "--rtr", "0.0.0.0:3323", "--http", "0.0.0.0:9556"]
