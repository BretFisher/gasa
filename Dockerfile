FROM dhi.io/golang:1-debian13-dev AS build

WORKDIR /src/app

COPY app/go.mod app/go.sum ./
RUN go mod download

COPY app/ ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$(go env GOARCH) \
    go build -trimpath -ldflags="-s -w" -o /out/gasa ./cmd/gasa

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/gasa /gasa

# run as distroless-style nonroot user/group (uid/gid 65532) in final image
USER 65532:65532

# checkov:skip=CKV_DOCKER_2: HEALTHCHECK is not applicable to a scratch-based CLI image
ENTRYPOINT ["/gasa"]
CMD ["--help"]
