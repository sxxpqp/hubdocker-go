# ---- build ----
FROM golang:1.25.7-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/hubdocker .

# ---- run ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
WORKDIR /app
COPY --from=build /out/hubdocker /usr/local/bin/hubdocker
COPY web ./web
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hubdocker"]