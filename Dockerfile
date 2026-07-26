FROM golang:1.26.5-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/access-gateway ./cmd/access-gateway

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/access-gateway /access-gateway
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/access-gateway"]
