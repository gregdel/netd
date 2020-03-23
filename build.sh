#!/bin/sh

set -e

go build -v -o fw cmd/fw/main.go
go build -v -o netd cmd/netd/main.go
