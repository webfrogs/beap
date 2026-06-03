ARG GO_VERSION=1.26.3

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src

RUN apk add --no-cache clang make

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH
ARG GIT_HASH=unknown
ARG BUILD_TIME=unknown

RUN make ebpf

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath -ldflags "-w -s -X beap/config.GitHash=${GIT_HASH} -X beap/config.BuildTime=${BUILD_TIME}" \
	-o /out/beap .

FROM alpine:3.20
COPY --from=build /out/beap /usr/local/bin/beap
ENTRYPOINT ["/usr/local/bin/beap"]
