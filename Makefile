.PHONY: all build test clean

all: build

build:
	CGO_ENABLED=0 go build -o dsocket ./cmd/dsocket

test:
	CGO_ENABLED=0 go test -v ./pkg/...

clean:
	rm -f dsocket
