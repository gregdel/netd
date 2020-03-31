#!/bin/sh
set -e

GO_ENABLED=0 GOOS=linux go build -v -o netd cmd/main.go
