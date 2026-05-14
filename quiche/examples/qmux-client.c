// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// QMux HTTP/3 client example using quiche C FFI, BoringSSL, and libev.
//
// Usage: qmux-client <host> <port> [path]
//
// Mirrors the structure of http3-client.c but uses TCP+TLS (QMux) instead
// of UDP (QUIC).

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <ev.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <quiche.h>

#define BUF_SIZE 65536

struct conn_io {
    ev_timer timer;

    const char *host;
    const char *path;

    int sock;
    SSL *ssl;

    quiche_conn *conn;
    quiche_h3_conn *http3;

    bool req_sent;
    bool settings_received;
};

static void debug_log(const char *line, void *argp) {
    fprintf(stderr, "%s\n", line);
}

static int for_each_setting(uint64_t identifier, uint64_t value,
                            void *argp) {
    fprintf(stderr, "got HTTP/3 SETTING: %" PRIu64 "=%" PRIu64 "\n",
            identifier, value);
    return 0;
}

static int for_each_header(uint8_t *name, size_t name_len,
                           uint8_t *value, size_t value_len,
                           void *argp) {
    fprintf(stderr, "got HTTP header: %.*s=%.*s\n",
            (int) name_len, name, (int) value_len, value);
    return 0;
}

// Write all pending quiche output to TLS.
static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[BUF_SIZE];

    while (1) {
        quiche_send_info send_info;
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out),
                                           &send_info);

        if (written == QUICHE_ERR_DONE) {
            break;
        }

        if (written < 0) {
            fprintf(stderr, "failed to create QMux record: %zd\n", written);
            return;
        }

        // Write the QMux record(s) to TLS.
        const uint8_t *p = out;
        ssize_t remaining = written;
        while (remaining > 0) {
            int n = SSL_write(conn_io->ssl, p, (int) remaining);
            if (n <= 0) {
                int err = SSL_get_error(conn_io->ssl, n);
                if (err == SSL_ERROR_WANT_WRITE ||
                    err == SSL_ERROR_WANT_READ) {
                    // Would block, try again later.
                    break;
                }
                fprintf(stderr, "SSL_write failed: %d\n", err);
                return;
            }
            p += n;
            remaining -= n;
        }

        fprintf(stderr, "sent %zd bytes\n", written);
    }

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);
}

static void recv_cb(EV_P_ ev_io *w, int revents) {
    struct conn_io *conn_io = w->data;

    static uint8_t buf[BUF_SIZE];

    // Dummy RecvInfo for QMux (ignored internally).
    struct sockaddr_in dummy_addr;
    memset(&dummy_addr, 0, sizeof(dummy_addr));
    dummy_addr.sin_family = AF_INET;

    quiche_recv_info recv_info = {
        (struct sockaddr *) &dummy_addr, sizeof(dummy_addr),
        (struct sockaddr *) &dummy_addr, sizeof(dummy_addr),
    };

    // Read from TLS and feed to quiche.
    while (1) {
        int n = SSL_read(conn_io->ssl, buf, sizeof(buf));

        if (n <= 0) {
            int err = SSL_get_error(conn_io->ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                break;
            }
            if (err == SSL_ERROR_ZERO_RETURN) {
                fprintf(stderr, "TLS connection closed by peer\n");
            } else {
                fprintf(stderr, "SSL_read error: %d\n", err);
            }
            ev_break(EV_A_ EVBREAK_ONE);
            return;
        }

        fprintf(stderr, "recv %d bytes\n", n);

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, n, &recv_info);

        if (done < 0) {
            fprintf(stderr, "failed to process data: %zd\n", done);
            continue;
        }
    }

    fprintf(stderr, "done reading\n");

    if (quiche_conn_is_closed(conn_io->conn)) {
        fprintf(stderr, "connection closed\n");
        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    if (quiche_conn_is_established(conn_io->conn) && !conn_io->req_sent) {
        const uint8_t *app_proto;
        size_t app_proto_len;

        quiche_conn_application_proto(conn_io->conn, &app_proto,
                                      &app_proto_len);

        fprintf(stderr, "QMux connection established: %.*s\n",
                (int) app_proto_len, app_proto);

        quiche_h3_config *config = quiche_h3_config_new();
        if (config == NULL) {
            fprintf(stderr, "failed to create HTTP/3 config\n");
            return;
        }

        conn_io->http3 = quiche_h3_conn_new_with_transport(conn_io->conn,
                                                            config);
        if (conn_io->http3 == NULL) {
            fprintf(stderr, "failed to create HTTP/3 connection\n");
            return;
        }

        quiche_h3_config_free(config);

        quiche_h3_header headers[] = {
            {
                .name = (const uint8_t *) ":method",
                .name_len = sizeof(":method") - 1,

                .value = (const uint8_t *) "GET",
                .value_len = sizeof("GET") - 1,
            },

            {
                .name = (const uint8_t *) ":scheme",
                .name_len = sizeof(":scheme") - 1,

                .value = (const uint8_t *) "https",
                .value_len = sizeof("https") - 1,
            },

            {
                .name = (const uint8_t *) ":authority",
                .name_len = sizeof(":authority") - 1,

                .value = (const uint8_t *) conn_io->host,
                .value_len = strlen(conn_io->host),
            },

            {
                .name = (const uint8_t *) ":path",
                .name_len = sizeof(":path") - 1,

                .value = (const uint8_t *) conn_io->path,
                .value_len = strlen(conn_io->path),
            },

            {
                .name = (const uint8_t *) "user-agent",
                .name_len = sizeof("user-agent") - 1,

                .value = (const uint8_t *) "quiche-qmux-c",
                .value_len = sizeof("quiche-qmux-c") - 1,
            },
        };

        int64_t stream_id = quiche_h3_send_request(conn_io->http3,
                                                    conn_io->conn,
                                                    headers, 5, true);

        fprintf(stderr, "sent HTTP request %" PRId64 "\n", stream_id);

        conn_io->req_sent = true;
    }

    if (quiche_conn_is_established(conn_io->conn) &&
        conn_io->http3 != NULL) {
        quiche_h3_event *ev;

        while (1) {
            int64_t s = quiche_h3_conn_poll(conn_io->http3,
                                            conn_io->conn,
                                            &ev);

            if (s < 0) {
                break;
            }

            if (!conn_io->settings_received) {
                int rc = quiche_h3_for_each_setting(conn_io->http3,
                                                    for_each_setting,
                                                    NULL);
                if (rc == 0) {
                    conn_io->settings_received = true;
                }
            }

            switch (quiche_h3_event_type(ev)) {
                case QUICHE_H3_EVENT_HEADERS: {
                    int rc = quiche_h3_event_for_each_header(ev,
                                                             for_each_header,
                                                             NULL);
                    if (rc != 0) {
                        fprintf(stderr, "failed to process headers\n");
                    }

                    break;
                }

                case QUICHE_H3_EVENT_DATA: {
                    for (;;) {
                        ssize_t len = quiche_h3_recv_body(conn_io->http3,
                                                          conn_io->conn, s,
                                                          buf, sizeof(buf));
                        if (len <= 0) {
                            break;
                        }

                        printf("%.*s", (int) len, buf);
                    }

                    break;
                }

                case QUICHE_H3_EVENT_FINISHED:
                    fprintf(stderr, "request finished\n");
                    if (quiche_conn_close(conn_io->conn, true, 0,
                                          NULL, 0) < 0) {
                        fprintf(stderr, "failed to close connection\n");
                    }
                    break;

                case QUICHE_H3_EVENT_RESET:
                    fprintf(stderr, "request was reset\n");
                    if (quiche_conn_close(conn_io->conn, true, 0,
                                          NULL, 0) < 0) {
                        fprintf(stderr, "failed to close connection\n");
                    }
                    break;

                case QUICHE_H3_EVENT_PRIORITY_UPDATE:
                    break;

                case QUICHE_H3_EVENT_GOAWAY:
                    fprintf(stderr, "got GOAWAY\n");
                    break;
            }

            quiche_h3_event_free(ev);
        }
    }

    flush_egress(loop, conn_io);
}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    quiche_conn_on_timeout(conn_io->conn);

    fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        fprintf(stderr, "connection closed (timeout)\n");
        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <host> <port> [path]\n", argv[0]);
        return -1;
    }

    const char *host = argv[1];
    const char *port = argv[2];
    const char *path = argc > 3 ? argv[3] : "/";

    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };

    quiche_enable_debug_logging(debug_log, NULL);

    struct addrinfo *peer;
    if (getaddrinfo(host, port, &hints, &peer) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    int sock = socket(peer->ai_family, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    // Connect (blocking).
    if (connect(sock, peer->ai_addr, peer->ai_addrlen) != 0) {
        perror("failed to connect");
        return -1;
    }

    fprintf(stderr, "TCP connected to %s:%s\n", host, port);

    // --- TLS handshake (blocking, before going non-blocking) ---

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        fprintf(stderr, "failed to create SSL_CTX\n");
        return -1;
    }

    // Set ALPN to h3qx-01.
    // Note: certificate verification is not configured in this example.
    // In production, use SSL_CTX_set_default_verify_paths() and
    // SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL).
    static const uint8_t alpn[] = "\x07h3qx-01";
    SSL_CTX_set_alpn_protos(ssl_ctx, alpn, sizeof(alpn) - 1);

    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        fprintf(stderr, "failed to create SSL\n");
        return -1;
    }

    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_connect_state(ssl);

    int ret = SSL_do_handshake(ssl);
    if (ret != 1) {
        fprintf(stderr, "TLS handshake failed: %d\n",
                SSL_get_error(ssl, ret));
        ERR_print_errors_fp(stderr);
        return -1;
    }

    const uint8_t *negotiated_alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &negotiated_alpn, &alpn_len);
    fprintf(stderr, "TLS complete, ALPN: %.*s\n",
            (int) alpn_len, negotiated_alpn);

    // Make socket non-blocking for the event loop.
    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    // --- quiche QMux setup ---

    quiche_config *config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_enable_qmux(config, true);

    quiche_config_set_application_protos(config,
        (uint8_t *) QUICHE_H3_OVER_QMUX_APPLICATION_PROTOCOL,
        sizeof(QUICHE_H3_OVER_QMUX_APPLICATION_PROTOCOL) - 1);

    quiche_config_set_max_idle_timeout(config, 5000);
    quiche_config_set_initial_max_data(config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    quiche_config_set_initial_max_stream_data_uni(config, 1000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_initial_max_streams_uni(config, 100);
    quiche_config_verify_peer(config, false);

    if (getenv("SSLKEYLOGFILE")) {
        quiche_config_log_keys(config);
    }

    // Dummy addresses for quiche_connect (not used in QMux mode).
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;

    uint8_t scid[16] = {0};

    quiche_conn *conn = quiche_connect(host,
                                       scid, sizeof(scid),
                                       (struct sockaddr *) &local_addr,
                                       sizeof(local_addr),
                                       peer->ai_addr, peer->ai_addrlen,
                                       config);

    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return -1;
    }

    fprintf(stderr, "QMux connection created\n");

    struct conn_io *conn_io = malloc(sizeof(*conn_io));
    if (conn_io == NULL) {
        fprintf(stderr, "failed to allocate connection IO\n");
        return -1;
    }

    conn_io->sock = sock;
    conn_io->ssl = ssl;
    conn_io->conn = conn;
    conn_io->http3 = NULL;
    conn_io->host = host;
    conn_io->path = path;
    conn_io->req_sent = false;
    conn_io->settings_received = false;

    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0);

    ev_io_init(&watcher, recv_cb, conn_io->sock, EV_READ);
    ev_io_start(loop, &watcher);
    watcher.data = conn_io;

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;

    // Send initial QMux transport parameters.
    flush_egress(loop, conn_io);

    ev_loop(loop, 0);

    freeaddrinfo(peer);

    if (conn_io->http3) {
        quiche_h3_conn_free(conn_io->http3);
    }

    quiche_conn_free(conn);
    quiche_config_free(config);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sock);

    free(conn_io);

    return 0;
}
