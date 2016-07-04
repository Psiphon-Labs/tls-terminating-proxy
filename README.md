# TLS Terminating Proxy

### Purpose

Terminates TLS (w/ client authentication and verification), then forwards unwrapped traffic on to a destination `host:port`

### Usage

1. `go build -o tls-terminating-proxy main.go`
2. `./tls-terminating-proxy <options>`

Options:
```
--backend string
  backend address (default "localhost:9999")
--ca string
  SSL CA certificate path (default "ssl/ca.pem")
--local string
  local address (default ":44300")
--log string
  path to log file (default ""). If blank, logs are written to stdout
--server-certificate string
  SSL server certificate path (default "ssl/cert.pem")
--server-key string
  SSL server key path (default "ssl/key.pem")
```
