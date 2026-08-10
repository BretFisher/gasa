FROM cgr.dev/chainguard/go:latest@sha256:072cb18c2146f22265a2d7862d37a92665a632060ae6fc0794750f2e7694ffe1 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$(go env GOARCH) \
    go build -trimpath -ldflags="-s -w" -o /out/gasa .

FROM cgr.dev/chainguard/static:latest@sha256:60582b2ae6074f641094af0f370d4ab241aab271858a66223dcde7eee9f51638

# chainguard/static already ships CA certificates and a nonroot user (65532)
COPY --from=build /out/gasa /gasa

# run as distroless-style nonroot user/group (uid/gid 65532) in final image
USER 65532:65532

# checkov:skip=CKV_DOCKER_2: HEALTHCHECK is not applicable to a scratch-based CLI image
ENTRYPOINT ["/gasa"]
CMD ["--help"]
