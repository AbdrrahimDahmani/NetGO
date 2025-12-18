# NetGO

A lightweight, statically compiled network scanner designed for zero-dependency reconnaissance.

## Features

- TCP port scanning with banner grabbing
- Service detection
- Concurrent scanning with configurable threads
- TLS support for HTTPS services

## Build

### Linux

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o netgo main.go
```

### Windows

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o netgo.exe main.go
```

## Usage

```bash
./netgo -target <IP/hostname> -ports <range> -threads <num> -timeout <ms>
```

### Options

| Flag       | Default   | Description                |
| ---------- | --------- | -------------------------- |
| `-target`  | 127.0.0.1 | Target IP or hostname      |
| `-ports`   | 1-1024    | Port range (e.g., 1-65535) |
| `-threads` | 100       | Concurrent workers         |
| `-timeout` | 2000      | Timeout per port (ms)      |

### Examples

```bash
# Scan common ports
./netgo -target 192.168.1.1

# Full port scan
./netgo -target 192.168.1.1 -ports 1-65535 -threads 500

# Scan specific range with custom timeout
./netgo -target 10.0.0.1 -ports 80-443 -timeout 1000
# Host Discovery (Subnet Scan): Pass a CIDR range (IP/Mask) to the target flag.
./scanner.exe -target 192.168.1.0/24
```
