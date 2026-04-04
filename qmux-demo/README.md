# qmux-demo

Demo client and server for QMux (QUIC over TCP+TLS).

## Building

```bash
cargo build -p qmux-demo
```

## Usage

### Server

```bash
# Basic server on port 4433
cargo run -p qmux-demo --bin qmux-server -- --listen 127.0.0.1:4433

# With datagram echo support
cargo run -p qmux-demo --bin qmux-server -- --listen 127.0.0.1:4433 --dgram-echo

# Unix socket
cargo run -p qmux-demo --bin qmux-server -- --unix-socket /tmp/qmux.sock
```

### Client

```bash
# Basic request
cargo run -p qmux-demo --bin qmux-client -- --no-verify https://127.0.0.1:4433/

# With QX_PING RTT measurement
cargo run -p qmux-demo --bin qmux-client -- --no-verify --ping https://127.0.0.1:4433/

# Send datagrams
cargo run -p qmux-demo --bin qmux-client -- --no-verify --dgram-count 5 --dgram-data "hello" https://127.0.0.1:4433/

# Unix socket
cargo run -p qmux-demo --bin qmux-client -- --unix-socket /tmp/qmux.sock --no-verify https://localhost/
```

## Options

### Client

| Option | Description |
|--------|-------------|
| `--no-verify` | Skip TLS certificate verification |
| `--ping` | Send QX_PING and measure RTT |
| `--dgram-count N` | Send N datagrams |
| `--dgram-data STR` | Data to send in datagrams (default: "quack") |
| `--unix-socket PATH` | Connect via Unix socket |
| `--requests N` | Number of requests to send (default: 1) |
| `--http-version` | Protocol version: h3 or http09 (default: h3) |

### Server

| Option | Description |
|--------|-------------|
| `--listen ADDR` | Listen address (default: 127.0.0.1:4433) |
| `--cert PATH` | TLS certificate file |
| `--key PATH` | TLS private key file |
| `--root DIR` | Document root for file serving |
| `--dgram-echo` | Echo received datagrams back |
| `--unix-socket PATH` | Listen on Unix socket |

## Endpoints

The server supports:

- Static file serving from `--root` directory
- `/stream-bytes/N` - Returns N bytes of data
