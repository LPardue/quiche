#!/usr/bin/env bash
#
# qmux-self-test-and-pcap.sh - Run qmux-server and qmux-client with TLS key
#              logging and parallel pcap capture for Wireshark analysis.
#
# Usage:
#   ./qmux-self-test-and-pcap.sh [URL]
#
# Default URL: https://localhost:4433/index.html
#
# Output files (in ./capture-<timestamp>/):
#   sslkeys.log  - TLS key material (NSS SSLKEYLOGFILE format)
#   qmux.pcap    - Packet capture of the traffic
#   server.log   - Server stderr/stdout
#   client.log   - Client stderr/stdout
#
# Wireshark usage:
#   1. Open capture.pcap in Wireshark
#   2. Edit -> Preferences -> Protocols -> TLS
#   3. Set "(Pre)-Master-Secret log filename" to the sslkeys.log path
#   4. Apply - TLS traffic is now decrypted
#
set -euo pipefail

URL="${1:-https://localhost:4433/index.html}"
PORT="${QMUX_PORT:-4433}"
LISTEN="${QMUX_LISTEN:-127.0.0.1:${PORT}}"
IFACE="${QMUX_IFACE:-lo}"

# Parse host from listen address for tcpdump filter.
LISTEN_HOST="${LISTEN%%:*}"

# Create output directory.
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="./capture-${TIMESTAMP}"
mkdir -p "${OUTDIR}"

SSLKEYLOG="${OUTDIR}/sslkeys.log"
PCAP="${OUTDIR}/qmux.pcap"
SERVER_LOG="${OUTDIR}/server.log"
CLIENT_LOG="${OUTDIR}/client.log"

# Ensure we have the binaries built.
echo "==> Building qmux-demo..."
cargo build -p qmux-demo 2>&1

# Resolve binary paths.
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-./target}"
SERVER_BIN="${CARGO_TARGET_DIR}/debug/qmux-server"
CLIENT_BIN="${CARGO_TARGET_DIR}/debug/qmux-client"

if [[ ! -x "${SERVER_BIN}" ]] || [[ ! -x "${CLIENT_BIN}" ]]; then
    echo "ERROR: Binaries not found. Expected:"
    echo "  ${SERVER_BIN}"
    echo "  ${CLIENT_BIN}"
    exit 1
fi

# Cleanup function to stop background processes.
cleanup() {
    echo ""
    echo "==> Cleaning up..."
    # Stop server.
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
        echo "    Stopped server (PID ${SERVER_PID})"
    fi
    # Stop packet capture.
    if [[ -n "${CAPTURE_PID:-}" ]] && kill -0 "${CAPTURE_PID}" 2>/dev/null; then
        # Give capture tool a moment to flush.
        sleep 0.5
        kill "${CAPTURE_PID}" 2>/dev/null || true
        wait "${CAPTURE_PID}" 2>/dev/null || true
        echo "    Stopped capture (PID ${CAPTURE_PID})"
    fi
}
trap cleanup EXIT

# Touch the keylog file so both processes can append.
touch "${SSLKEYLOG}"

echo "==> Starting packet capture on ${IFACE} port ${PORT}..."
# Prefer dumpcap (works without root if user is in wireshark group and
# dumpcap has cap_net_raw), then tshark, then tcpdump with sudo.
CAPTURE_PID=""
if command -v dumpcap &>/dev/null; then
    dumpcap -i "${IFACE}" -f "tcp port ${PORT}" -w "${PCAP}" -q &
    CAPTURE_PID=$!
    echo "    Using dumpcap (PID ${CAPTURE_PID})"
elif command -v tshark &>/dev/null; then
    tshark -i "${IFACE}" -f "tcp port ${PORT}" -w "${PCAP}" -q &
    CAPTURE_PID=$!
    echo "    Using tshark (PID ${CAPTURE_PID})"
elif command -v tcpdump &>/dev/null; then
    if [[ "$(id -u)" -ne 0 ]]; then
        sudo tcpdump -i "${IFACE}" -w "${PCAP}" -s 0 "tcp port ${PORT}" &
    else
        tcpdump -i "${IFACE}" -w "${PCAP}" -s 0 "tcp port ${PORT}" &
    fi
    CAPTURE_PID=$!
    echo "    Using tcpdump (PID ${CAPTURE_PID})"
else
    echo "WARNING: No capture tool found (dumpcap, tshark, or tcpdump)."
    echo "         Continuing without pcap -- only sslkeys.log will be generated."
fi
# Give capture tool time to start.
sleep 1

echo "==> Starting qmux-server on ${LISTEN} (dgram-echo enabled)..."
SSLKEYLOGFILE="${SSLKEYLOG}" RUST_LOG=info \
    "${SERVER_BIN}" --listen "${LISTEN}" --dgram-echo \
    ${QMUX_SERVER_ARGS:-} \
    > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
# Give the server time to bind.
sleep 1

# Verify the server is still running.
if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "ERROR: Server failed to start. Check ${SERVER_LOG}"
    cat "${SERVER_LOG}"
    exit 1
fi
echo "    Server running (PID ${SERVER_PID})"

echo "==> Running qmux-client: ${URL} (with 3 datagrams)"
SSLKEYLOGFILE="${SSLKEYLOG}" RUST_LOG=info \
    "${CLIENT_BIN}" --no-verify "${URL}" \
    --dgram-count 3 --dgram-data "hello-datagram" \
    ${QMUX_CLIENT_ARGS:-} \
    > "${CLIENT_LOG}" 2>&1 || true
echo "    Client finished"

# Give a moment for final packets to arrive.
sleep 1

echo ""
echo "==> Results in ${OUTDIR}/:"
echo "    sslkeys.log  - $(wc -l < "${SSLKEYLOG}") key lines"
if [[ -f "${PCAP}" ]]; then
    echo "    capture.pcap  - $(du -h "${PCAP}" | cut -f1) captured"
else
    echo "    capture.pcap  - (not captured)"
fi
echo "    server.log    - server output"
echo "    client.log    - client output"
echo ""
if [[ -f "${PCAP}" ]]; then
    echo "To view in Wireshark:"
    echo "  wireshark -o tls.keylog_file:$(realpath "${SSLKEYLOG}") $(realpath "${PCAP}")"
fi
