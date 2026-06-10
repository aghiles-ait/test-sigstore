FROM rust:1.96.0-alpine3.23 AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM alpine:3.23 AS runtime

RUN apk --no-cache upgrade

WORKDIR /app
COPY --from=builder /app/target/release/test-sigstore .

EXPOSE 8080
ENTRYPOINT ["/app/test-sigstore"]