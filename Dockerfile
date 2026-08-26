# ── Stage 1: Build ──
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY server_v2/main.go server_v2/db.go ./
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /server main.go db.go

# ── Stage 2: Runtime ──
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /server .
COPY config.json .
RUN mkdir -p data downloads
EXPOSE 1301
CMD ["./server"]
