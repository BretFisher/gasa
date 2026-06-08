FROM cgr.dev/chainguard/go:latest@sha256:595c4dded734c919c724e25ca57fd11ad503d75b6eb63642d765b7437e2f546b AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$(go env GOARCH) \
    go build -trimpath -ldflags="-s -w" -o /out/gasa .

FROM cgr.dev/chainguard/static:latest@sha256:77d8b8925dc27970ec2f48243f44c7a260d52c49cd778288e4ee97566e0cb75b

# chainguard/static already ships CA certificates and a nonroot user (65532)
COPY --from=build /out/gasa /gasa

# run as distroless-style nonroot user/group (uid/gid 65532) in final image
USER 65532:65532

# checkov:skip=CKV_DOCKER_2: HEALTHCHECK is not applicable to a scratch-based CLI image
ENTRYPOINT ["/gasa"]
CMD ["--help"]
