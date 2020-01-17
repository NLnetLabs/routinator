# -- stage 1: build static routinator with musl libc for alpine
FROM alpine:3.10.3 as build
ARG TLS=rustls-tls

RUN apk add rust cargo openssl-dev

WORKDIR /tmp/routinator
COPY . .

RUN cargo build \
    --target x86_64-alpine-linux-musl \
    --release \
    --locked \
    --features socks,${TLS}

# -- stage 2: create alpine-based container with the static routinator
#             executable
FROM alpine:3.10.3
COPY --from=build /tmp/routinator/target/x86_64-alpine-linux-musl/release/routinator /usr/local/bin/

# Build variables for uid and guid of user to run container
ARG RUN_USER=routinator
ARG RUN_USER_UID=1012
ARG RUN_USER_GID=1012

# Install rsync as routinator depends on it
RUN apk add rsync libgcc

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

ENTRYPOINT ["routinator"]
CMD ["server", "--rtr", "0.0.0.0:3323", "--http", "0.0.0.0:9556"]
