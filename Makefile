NAME=beap
BINDIR=build
GIT_HASH:=$(shell git rev-parse HEAD)
BUILD_TIME:=$(shell date +'%F %T %Z')
GOBUILD=CGO_ENABLED=0 go build -trimpath -ldflags '-w -s \
	-X "beap/config.GitHash=$(GIT_HASH)" \
	-X "beap/config.BuildTime=$(BUILD_TIME)" \
	'

.PHONY: all
all: linux_amd64 linux_arm64

.PHONY: run
run:
	go run *.go

.PHONY: ebpf
ebpf:
	clang -O2 -g -Wno-pointer-sign -target bpfel \
		-MD -MP \
		-nostdinc -I ./hook/kern \
		-c hook/kern/tproxy.c -o hook/kern/tproxy.o 

.PHONY: linux_amd64
linux_amd64:
	GOARCH=amd64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)_$@

.PHONY: linux_arm64
linux_arm64:
	GOARCH=arm64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)_$@
