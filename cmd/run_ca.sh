#!/bin/bash

# Get ct-certificate-authority top level using git
CT_CA_BASE_DIR=`git rev-parse --show-toplevel`

# Go into ct-certificate-authority dir and create binary for server.go
cd "$CT_CA_BASE_DIR/ct-certificate-authority"

# Remove previous binary if exists
rm server

# Create binary
go build server.go

# Go back to top level of the ct-certificate-authority directory and run the server
cd "$CT_CA_BASE_DIR"
ct-certificate-authority/server -logtostderr=true