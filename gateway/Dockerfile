# ---- build ----
FROM golang:1.25.7-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN go mod tidy && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/gateway .

# ---- run ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
WORKDIR /app
COPY --from=build /out/gateway /usr/local/bin/gateway
COPY web ./web
EXPOSE 7000
ENTRYPOINT ["/usr/local/bin/gateway"]
