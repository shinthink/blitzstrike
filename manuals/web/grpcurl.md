# gRPCurl

- **Category**: Web / API gRPC Testing
- **Risk Level**: 🟡 Medium

---

## Description

Command-line gRPC client for listing services, describing methods, and invoking RPC calls. Use it to test reflection exposure, metadata authentication, and gRPC method behavior.

## Installation

```bash
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-plaintext` | Disable TLS |
| `-insecure` | Skip TLS certificate verification |
| `-cacert <file>` | File with trusted root certs for verifying the server (ignored if `-insecure`) |
| `-cert <file>` | Client certificate (public key) to present to the server (mTLS; needs `-key`) |
| `-key <file>` | Client private key to present to the server (mTLS; needs `-cert`) |
| `-proto <file>` | Proto file to use for request parsing and formatting (when reflection unavailable) |
| `-protoset <file>` | Compiled protoset file (from `protoc --descriptor_set_out`) |
| `-import-path <dir>` | Path for proto file imports |
| `-H <header>` | Add metadata/header (format: `name: value`) |
| `-rpc-header <header>` | Header used only when invoking the RPC method (excluded from reflection requests) |
| `-reflect-header <header>` | Header used only during reflection requests (excluded when invoking the RPC) |
| `-d <json>` | Request body as JSON |
| `-format <fmt>` | Format for request data: `json` (default) or `text` |
| `-emit-defaults` | Emit default values for JSON-encoded responses |
| `-authority <name>` | Authoritative server name (`:authority` pseudo-header; also TLS server name) |
| `-servername <name>` | Override server name when validating the TLS cert (prefer `-authority`) |
| `-unix` | Treat the server address as the path to a Unix domain socket |
| `-max-time <sec>` | Maximum total time for the operation in seconds (gRPC context deadline) |
| `-connect-timeout <sec>` | Maximum time in seconds to wait for the connection to establish (default 10) |
| `-keepalive-time <sec>` | Max idle time in seconds before a keepalive probe is sent |
| `-max-msg-sz <bytes>` | Maximum encoded response message size accepted (default 4 MB) |
| `-v` | Verbose output (show headers and trailers) |
| `-vv` | Very verbose (show raw bytes) |
| `list` | List services or methods |
| `describe` | Describe service or method |
| `<host:port> <method>` | Invoke method |

## Common Commands

```bash
# List services via reflection
grpcurl -plaintext <target>:50051 list

# Describe a service
grpcurl -plaintext <target>:50051 describe <service>

# Invoke method with JSON body
grpcurl -plaintext -d '{"id":"123"}' <target>:50051 <service>/<method>

# Authenticated metadata
grpcurl -H "authorization: Bearer <token>" <target>:443 list
```

## Notes & Tips

1. Reflection exposure is an information disclosure finding when it reveals internal methods or messages.
2. If reflection is disabled, provide `.proto` files with `-proto` when available.
3. Avoid invoking state-changing RPCs unless explicitly authorized.

---

## Official References

- [grpcurl GitHub](https://github.com/fullstorydev/grpcurl)

