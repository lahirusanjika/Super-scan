# Superscan

A fast, configurable secret scanner for Git repositories and codebases.

[![Superscan Secret Scanner](https://github.com/lahirusanjika/Super-scan/actions/workflows/superscan.yml/badge.svg)](https://github.com/lahirusanjika/Super-scan/actions/workflows/superscan.yml)

## Features

- Scans for:
  - Cloud keys (AWS, Google)
  - GitHub tokens
  - Stripe keys
  - Slack / Discord / Telegram tokens
  - DB URIs (MongoDB, PostgreSQL, MySQL)
  - JWT / bearer / generic tokens
  - Password assignments
  - Email addresses
  - Private key blocks
  - High-entropy random strings
- Sensitive filename detection (e.g. `.env`, `secrets`, `id_rsa`)
- Baseline support (ignore known findings)
- JSON or text output
- CI-friendly exit codes based on severity

## Installation

```bash
go mod tidy
go build ./cmd/superscan
```

This will produce a `superscan` binary in the current directory.

## Usage

Scan the current directory:

```bash
./superscan .
```

JSON output:

```bash
./superscan --json .
```

Use a custom config:

```bash
./superscan --config config.yml .
```

Create a baseline file (ignores current findings in future runs):

```bash
./superscan --baseline superscan.baseline.json --baseline-create .
```

Then commit `superscan.baseline.json` to your repo and run:

```bash
./superscan --baseline superscan.baseline.json .
```

## CI Integration (GitHub Actions)

Add this file to your repo:

```yaml
# .github/workflows/superscan.yml
name: Superscan Secret Scanner

on:
  push:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Cache Go modules
        uses: actions/cache@v4
        with:
          path: |
            ~/go/pkg/mod
            ~/.cache/go-build
          key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
          restore-keys: |
            ${{ runner.os }}-go-

      - name: Build superscan
        run: |
          go mod tidy
          go build -o superscan ./cmd/superscan

      - name: Run superscan
        run: |
          if [ -f superscan.baseline.json ]; then
            ./superscan --baseline superscan.baseline.json --json .
          else
            ./superscan --json .
          fi
```

## Author

Developed by **Lahiru Sanjika Kulasuriya**.

