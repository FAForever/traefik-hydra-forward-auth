# ----------- Build stage -----------
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY ./app .

# CGO_ENABLED=0 disables libc requirmenet (Alpine compatibility)
RUN CGO_ENABLED=0 go build -o forward-auth .

# ----------- Execution stage -----------
FROM alpine:latest

RUN adduser -D appuser

COPY --from=builder /app/forward-auth /usr/local/bin/forward-auth

USER appuser

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/forward-auth"]
