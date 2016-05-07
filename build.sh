#!/bin/sh
cd run
go clean
CGO_ENABLED=1 go build