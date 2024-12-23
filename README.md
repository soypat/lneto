# go-module-template
[![go.dev reference](https://pkg.go.dev/badge/github.com/soypat/go-module-template)](https://pkg.go.dev/github.com/soypat/go-module-template)
[![Go Report Card](https://goreportcard.com/badge/github.com/soypat/go-module-template)](https://goreportcard.com/report/github.com/soypat/go-module-template)
[![codecov](https://codecov.io/gh/soypat/go-module-template/branch/main/graph/badge.svg)](https://codecov.io/gh/soypat/go-module-template)
[![Go](https://github.com/soypat/go-module-template/actions/workflows/go.yml/badge.svg)](https://github.com/soypat/go-module-template/actions/workflows/go.yml)
[![sourcegraph](https://sourcegraph.com/github.com/soypat/go-module-template/-/badge.svg)](https://sourcegraph.com/github.com/soypat/go-module-template?badge)
<!--
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![stability-experimental](https://img.shields.io/badge/stability-experimental-orange.svg)](https://github.com/emersion/stability-badges#experimental)

See https://github.com/emersion/stability-badges#unstable for more stability badges.
-->

Go module template with instructions on how to make your code importable and setting up codecov CI.

How to install package with newer versions of Go (+1.16):
```sh
go mod download github.com/soypat/go-module-template@latest
```


## First steps

0. Replace LICENSE with your desired license. BSD 3 clause is included by default.

1. Fix `go.mod` file by replacing `github.com/YOURUSER/YOURREPONAME` with your corresponding project repository link.

2. Replace `soypat/go-module-template` in the badge URLs. Make sure you've replaced all of them by performing text search in the readme for `soypat` and `template`.

3. Rename `module.go` and `module_test.go` to fit your own repository needs. Below are some exemplary modules that abide by what's generally considered "good practices":
    - [`mu8` minimal machine learning library](https://github.com/soypat/mu8). Note how most interfaces and interface algorithms are defined at the root package level and how the concrete implementations live in the subdirectories.
    - Similarily [`sdf`](https://github.com/soypat/sdf) also does the same with defining interfaces top level.

## Setting up codecov CI
This instructive will allow for tests to run on pull requests and pushes to your repository.

1. Create an account on [codecov.io](https://app.codecov.io/)

2. Setup repository on codecov and obtain the CODECOV_TOKEN token, which is a string of base64 characters.

3. Open up the github repository for this project and go to `Settings -> Secrets and variables -> Actions`. Once there create a New Repository Secret. Name it `CODECOV_TOKEN` and copy paste the token obtained in the previous step in the `secret` input box. Click "Add secret".


