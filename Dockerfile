# -- stage 1: build static routinator with musl libc for alpine
FROM alpine:3.10.1 as build

RUN apk add rust cargo openssl-dev

WORKDIR /tmp/routinator
COPY . .

RUN cargo build --target x86_64-alpine-linux-musl --release --locked

# -- stage 2: create alpine-based container with the static routinator
#             executable
FROM alpine:3.10.1
COPY --from=build /tmp/routinator/target/x86_64-alpine-linux-musl/release/routinator /usr/local/bin/

# Install rsync as routinator depends on it
RUN apk add rsync libgcc

# Create the repository and TAL directories
RUN mkdir -p /root/.rpki-cache/repository
RUN mkdir -p /root/.rpki-cache/tals

# Due to ARIN TAL distribution terms, we can't do this here.
# An individual user, however, might want to anyway - after reviewing
# https://www.arin.net/resources/rpki/tal.html.
#
#COPY --from=build /tmp/routinator/tals/*.tal /root/.rpki-cache/tals/

EXPOSE 3323/tcp
EXPOSE 9556/tcp
ENTRYPOINT ["routinator"]
CMD ["server", "--rtr", "0.0.0.0:3323", "--http", "0.0.0.0:9556"]
