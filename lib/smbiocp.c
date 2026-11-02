/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Artiom Morozov <amorozov@resilio.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
/*
 * SMB2 over TCP with overlapped I/O on an I/O completion port of the caller
 * (Windows), see smb2_iocp_attach().
 *
 * libsmb2 itself is readiness driven: it reads and writes its socket when
 * told it can. Here it never touches the socket. One overlapped receive is
 * kept in flight into a receive buffer, which smb2_iocp_readv() serves;
 * smb2_iocp_writev() copies into a send buffer, which is sent with one
 * overlapped send at a time. Every completion is then followed by the same
 * read/write pass over the context that a poll event would trigger, see the
 * IOCP branch of smb2_service_fd().
 *
 * The copy into the send buffer is not optional: smb2_write_to_socket()
 * passes stack memory (the SPL) and buffers it may free once the write
 * returns.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

#ifdef HAVE_SMB2_IOCP

#include <mswsock.h>

/*
 * Buffers are per connection, so with thousands of connections they have
 * to stay small. That costs little: an overlapped send completes once the
 * data is in the socket's kernel send buffer, not when it is acknowledged,
 * and a receive returns what has arrived so far.
 */

/* One receive of up to this much is kept in flight. libsmb2 drains the
 * buffer completely on every completion, so it is free again by the time
 * the next receive is posted. */
#define IOCP_RX_SIZE (64 * 1024)

/* smb2_write_to_socket() copes with partial writes, so a PDU larger than
 * this is copied in pieces as the sends complete. */
#define IOCP_TX_SIZE (64 * 1024)

enum iocp_op_kind {
        IOCP_OP_CONNECT,
        IOCP_OP_RECV,
        IOCP_OP_SEND,
};

struct smb2_iocp_op {
        OVERLAPPED ov;                  /* first: OVERLAPPED * is the op */
        struct smb2_iocp_sock *sock;
        enum iocp_op_kind kind;
        int pending;
};

/*
 * A socket and its buffers. Closing the socket aborts its operations still
 * in flight, but their completions are still delivered, later, and refer to
 * this. So the context holds one reference and each operation in flight one
 * more, and whichever goes last frees it.
 */
struct smb2_iocp_sock {
        struct smb2_iocp_sock *next;    /* in smb2->iocp_socks */
        SOCKET s;
        struct smb2_context *smb2;      /* NULL once the context let go */
        LONG refs;

        struct smb2_iocp_op connect_op;
        struct smb2_iocp_op recv_op;
        struct smb2_iocp_op send_op;

        int connect_finished;           /* ConnectEx completed ... */
        DWORD connect_err;              /* ... with this error */
        int connected;

        uint8_t *rx_buf;                /* [rx_pos, rx_len) not read yet */
        size_t rx_pos;
        size_t rx_len;
        int rx_eof;
        DWORD rx_err;

        uint8_t *tx_buf;                /* [0, tx_len) queued, of which */
        size_t tx_len;                  /* [0, tx_sending) is in flight */
        size_t tx_sending;
        DWORD tx_err;
};

static void
sock_ref(struct smb2_iocp_sock *sk)
{
        InterlockedIncrement(&sk->refs);
}

static void
sock_unref(struct smb2_iocp_sock *sk)
{
        if (InterlockedDecrement(&sk->refs) != 0) {
                return;
        }
        free(sk->rx_buf);
        free(sk->tx_buf);
        free(sk);
}

/* The connected socket, NULL while connecting */
static struct smb2_iocp_sock *
connected_sock(struct smb2_context *smb2)
{
        struct smb2_iocp_sock *sk;

        if (!SMB2_VALID_SOCKET(smb2->fd)) {
                return NULL;
        }
        for (sk = smb2->iocp_socks; sk; sk = sk->next) {
                if (sk->s == smb2->fd) {
                        return sk->connected ? sk : NULL;
                }
        }
        return NULL;
}

static void
op_init(struct smb2_iocp_sock *sk, struct smb2_iocp_op *op,
        enum iocp_op_kind kind)
{
        op->sock = sk;
        op->kind = kind;
        op->pending = 0;
}

/* Prepare op for a new overlapped call. Undo with op_failed() if the call
 * fails right away, as then no completion will be delivered for it. */
static void
op_start(struct smb2_iocp_op *op)
{
        memset(&op->ov, 0, sizeof(op->ov));
        op->pending = 1;
        sock_ref(op->sock);
}

static void
op_failed(struct smb2_iocp_op *op)
{
        op->pending = 0;
        sock_unref(op->sock);
}

/* Win32/Winsock errors of a failed connect, as the errno values the
 * connect callback is called with */
static int
connect_errno(DWORD err)
{
        switch (err) {
        case ERROR_CONNECTION_REFUSED:
        case WSAECONNREFUSED:
                return ECONNREFUSED;
        case ERROR_SEM_TIMEOUT:
        case WSAETIMEDOUT:
                return ETIMEDOUT;
        case ERROR_NETWORK_UNREACHABLE:
        case WSAENETUNREACH:
                return ENETUNREACH;
        case ERROR_HOST_UNREACHABLE:
        case WSAEHOSTUNREACH:
                return EHOSTUNREACH;
        default:
                return EIO;
        }
}

static int
start_send(struct smb2_iocp_sock *sk)
{
        WSABUF buf;
        int err;

        buf.buf = (char *)sk->tx_buf;
        buf.len = (ULONG)sk->tx_len;
        sk->tx_sending = sk->tx_len;

        op_start(&sk->send_op);
        if (WSASend(sk->s, &buf, 1, NULL, 0, &sk->send_op.ov, NULL) == 0) {
                return 0;
        }
        err = WSAGetLastError();
        if (err == WSA_IO_PENDING) {
                return 0;
        }
        op_failed(&sk->send_op);
        sk->tx_sending = 0;
        sk->tx_err = err;
        return -1;
}

static int
post_recv(struct smb2_iocp_sock *sk)
{
        WSABUF buf;
        DWORD flags = 0;
        int err;

        if (sk->recv_op.pending || sk->rx_eof || sk->rx_err) {
                return 0;
        }
        if (sk->rx_pos == sk->rx_len) {
                sk->rx_pos = sk->rx_len = 0;
        } else if (sk->rx_pos > 0) {
                memmove(sk->rx_buf, &sk->rx_buf[sk->rx_pos],
                        sk->rx_len - sk->rx_pos);
                sk->rx_len -= sk->rx_pos;
                sk->rx_pos = 0;
        }
        if (sk->rx_len == IOCP_RX_SIZE) {
                /* libsmb2 has not consumed what we have yet: wait for it,
                 * which also pushes back on the server through TCP. */
                return 0;
        }

        buf.buf = (char *)&sk->rx_buf[sk->rx_len];
        buf.len = (ULONG)(IOCP_RX_SIZE - sk->rx_len);

        op_start(&sk->recv_op);
        if (WSARecv(sk->s, &buf, 1, NULL, &flags, &sk->recv_op.ov,
                    NULL) == 0) {
                return 0;
        }
        err = WSAGetLastError();
        if (err == WSA_IO_PENDING) {
                return 0;
        }
        op_failed(&sk->recv_op);
        sk->rx_err = err;
        return -1;
}

int
smb2_iocp_connect(struct smb2_context *smb2, const struct addrinfo *ai,
                  t_socket *fd_out)
{
        GUID guid = WSAID_CONNECTEX;
        LPFN_CONNECTEX connect_ex = NULL;
        struct sockaddr_storage local;
        struct smb2_iocp_sock *sk;
        DWORD len;
        int one = 1;
        int err;

        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
                smb2_set_error(smb2, "Unknown address family :%d. "
                               "Only IPv4/IPv6 supported so far.",
                               ai->ai_family);
                return -EINVAL;
        }

        sk = calloc(1, sizeof(*sk));
        if (sk == NULL) {
                smb2_set_error(smb2, "iocp: out of memory");
                return -ENOMEM;
        }
        sk->refs = 1;
        sk->s = INVALID_SOCKET;
        op_init(sk, &sk->connect_op, IOCP_OP_CONNECT);
        op_init(sk, &sk->recv_op, IOCP_OP_RECV);
        op_init(sk, &sk->send_op, IOCP_OP_SEND);
        sk->rx_buf = malloc(IOCP_RX_SIZE);
        sk->tx_buf = malloc(IOCP_TX_SIZE);
        if (sk->rx_buf == NULL || sk->tx_buf == NULL) {
                smb2_set_error(smb2, "iocp: out of memory");
                sock_unref(sk);
                return -ENOMEM;
        }

        sk->s = WSASocketW(ai->ai_family, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                           WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
        if (sk->s == INVALID_SOCKET) {
                smb2_set_error(smb2, "iocp: failed to open socket: %d",
                               WSAGetLastError());
                sock_unref(sk);
                return -EIO;
        }
        setsockopt(sk->s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one,
                   sizeof(one));

        /* ConnectEx needs a bound socket */
        memset(&local, 0, sizeof(local));
        local.ss_family = (ADDRESS_FAMILY)ai->ai_family;
        if (bind(sk->s, (struct sockaddr *)&local,
                 ai->ai_family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                           : sizeof(struct sockaddr_in)) != 0) {
                smb2_set_error(smb2, "iocp: bind failed: %d",
                               WSAGetLastError());
                goto failed;
        }
        if (CreateIoCompletionPort((HANDLE)sk->s, (HANDLE)smb2->iocp_port,
                                   (ULONG_PTR)smb2->iocp_key, 0) == NULL) {
                smb2_set_error(smb2, "iocp: failed to associate the socket "
                               "with the completion port: %lu",
                               GetLastError());
                goto failed;
        }
        if (WSAIoctl(sk->s, SIO_GET_EXTENSION_FUNCTION_POINTER,
                     &guid, sizeof(guid), &connect_ex, sizeof(connect_ex),
                     &len, NULL, NULL) != 0) {
                smb2_set_error(smb2, "iocp: ConnectEx is not available: %d",
                               WSAGetLastError());
                goto failed;
        }

        op_start(&sk->connect_op);
        if (!connect_ex(sk->s, ai->ai_addr, (int)ai->ai_addrlen,
                        NULL, 0, NULL, &sk->connect_op.ov)) {
                err = WSAGetLastError();
                if (err != ERROR_IO_PENDING) {
                        op_failed(&sk->connect_op);
                        smb2_set_error(smb2, "Connect failed with error "
                                       ": %d", err);
                        goto failed;
                }
        }

        sk->smb2 = smb2;
        SMB2_LIST_ADD(&smb2->iocp_socks, sk);
        *fd_out = sk->s;
        return 0;

 failed:
        closesocket(sk->s);
        sk->s = INVALID_SOCKET;
        sock_unref(sk);
        return -EIO;
}

void
smb2_iocp_close(struct smb2_context *smb2, t_socket fd)
{
        struct smb2_iocp_sock *sk;

        for (sk = smb2->iocp_socks; sk; sk = sk->next) {
                if (sk->s == fd) {
                        break;
                }
        }
        if (sk == NULL) {
                /* not one of ours, nothing can be in flight on it */
                closesocket(fd);
                return;
        }
        SMB2_LIST_REMOVE(&smb2->iocp_socks, sk);
        sk->smb2 = NULL;
        /* aborts what is in flight, the completions arrive later */
        closesocket(sk->s);
        sk->s = INVALID_SOCKET;
        sock_unref(sk);
}

/*
 * Report what changed since the last call, for smb2_service_fd():
 * SMB2_IOCP_CONNECTED or SMB2_IOCP_CONNECT_FAILED (with the socket in *fd
 * and, on failure, the errno value in *err), -1 if a send failed, else 0.
 * A failed receive is reported by smb2_iocp_readv().
 */
int
smb2_iocp_service(struct smb2_context *smb2, t_socket *fd, int *err)
{
        struct smb2_iocp_sock *sk;

        /* each completion is serviced right away, so at most one connect
         * has finished since the last call */
        for (sk = smb2->iocp_socks; sk; sk = sk->next) {
                if (sk->connected || !sk->connect_finished) {
                        continue;
                }
                sk->connect_finished = 0;
                *fd = sk->s;
                if (sk->connect_err) {
                        *err = connect_errno(sk->connect_err);
                        return SMB2_IOCP_CONNECT_FAILED;
                }
                /* make getpeername(), shutdown() etc. work on it */
                setsockopt(sk->s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT,
                           NULL, 0);
                sk->connected = 1;
                return SMB2_IOCP_CONNECTED;
        }
        sk = connected_sock(smb2);
        if (sk != NULL && sk->tx_err) {
                smb2_set_error(smb2, "Error when writing to socket: %lu",
                               sk->tx_err);
                return -1;
        }
        return 0;
}

/* Start sending what was queued, and keep a receive in flight */
int
smb2_iocp_flush(struct smb2_context *smb2)
{
        struct smb2_iocp_sock *sk = connected_sock(smb2);

        if (sk == NULL) {
                return 0;
        }
        if (sk->tx_len && !sk->send_op.pending && start_send(sk) < 0) {
                smb2_set_error(smb2, "Error when writing to socket: %lu",
                               sk->tx_err);
                return -1;
        }
        if (post_recv(sk) < 0) {
                smb2_set_error(smb2, "Error when reading from socket: %lu",
                               sk->rx_err);
                return -1;
        }
        return 0;
}

ssize_t
smb2_iocp_writev(struct smb2_context *smb2, const struct iovec *iov,
                 int iovcnt)
{
        struct smb2_iocp_sock *sk = connected_sock(smb2);
        size_t space, len;
        ssize_t count = 0;
        int i;

        if (sk == NULL || sk->tx_err) {
                errno = EPIPE;
                return -1;
        }
        space = IOCP_TX_SIZE - sk->tx_len;
        if (space == 0) {
                /* resumed when the send in flight completes */
                errno = EAGAIN;
                return -1;
        }
        for (i = 0; i < iovcnt && space > 0; i++) {
                len = iov[i].iov_len;
                if (len > space) {
                        len = space;
                }
                memcpy(&sk->tx_buf[sk->tx_len], iov[i].iov_base, len);
                sk->tx_len += len;
                space -= len;
                count += (ssize_t)len;
        }
        if (!sk->send_op.pending && start_send(sk) < 0) {
                errno = EPIPE;
                return -1;
        }
        return count;
}

ssize_t
smb2_iocp_readv(struct smb2_context *smb2, const struct iovec *iov,
                int iovcnt)
{
        struct smb2_iocp_sock *sk = connected_sock(smb2);
        size_t len;
        ssize_t count = 0;
        int i;

        /* smb2_read_data() looks at WSAGetLastError() on windows */
        if (sk == NULL) {
                WSASetLastError(WSAENOTCONN);
                return -1;
        }
        if (sk->rx_pos == sk->rx_len) {
                if (sk->rx_err) {
                        WSASetLastError((int)sk->rx_err);
                        return -1;
                }
                if (sk->rx_eof) {
                        return 0;
                }
                WSASetLastError(WSAEWOULDBLOCK);
                return -1;
        }
        for (i = 0; i < iovcnt && sk->rx_pos < sk->rx_len; i++) {
                len = iov[i].iov_len;
                if (len > sk->rx_len - sk->rx_pos) {
                        len = sk->rx_len - sk->rx_pos;
                }
                memcpy(iov[i].iov_base, &sk->rx_buf[sk->rx_pos], len);
                sk->rx_pos += len;
                count += (ssize_t)len;
        }
        return count;
}

int
smb2_iocp_attach(struct smb2_context *smb2, void *iocp, uintptr_t key)
{
        if (iocp == NULL) {
                smb2_set_error(smb2, "iocp: no completion port");
                return -1;
        }
        if (SMB2_VALID_SOCKET(smb2->fd) || smb2->connecting_fds_count > 0) {
                smb2_set_error(smb2, "iocp: attach before connecting");
                return -1;
        }
        smb2->iocp_port = iocp;
        smb2->iocp_key = key;
        return 0;
}

int
smb2_iocp_complete(void *overlapped, unsigned long bytes,
                   unsigned long error, struct smb2_context **smb2_out)
{
        struct smb2_iocp_op *op = overlapped;
        struct smb2_iocp_sock *sk = op->sock;
        struct smb2_context *smb2 = sk->smb2;
        int ret = 0;

        op->pending = 0;
        if (smb2_out) {
                *smb2_out = smb2;
        }
        if (smb2 == NULL) {
                /* aborted when the socket was closed */
                sock_unref(sk);
                return 0;
        }

        switch (op->kind) {
        case IOCP_OP_CONNECT:
                sk->connect_finished = 1;
                sk->connect_err = error;
                break;
        case IOCP_OP_RECV:
                if (error) {
                        sk->rx_err = error;
                } else if (bytes == 0) {
                        sk->rx_eof = 1;
                } else {
                        sk->rx_len += bytes;
                }
                break;
        case IOCP_OP_SEND:
                if (error) {
                        sk->tx_err = error;
                } else {
                        memmove(sk->tx_buf, &sk->tx_buf[bytes],
                                sk->tx_len - bytes);
                        sk->tx_len -= bytes;
                }
                sk->tx_sending = 0;
                break;
        }

        /* The op's reference keeps sk alive through this, even if the
         * context closes the socket from one of its callbacks. */
        ret = smb2_service(smb2, 0);
        sock_unref(sk);
        return ret;
}

#else /* HAVE_SMB2_IOCP */

int
smb2_iocp_attach(struct smb2_context *smb2, void *iocp _U_, uintptr_t key _U_)
{
        smb2_set_error(smb2, "iocp: built without IOCP support");
        return -1;
}

int
smb2_iocp_complete(void *overlapped _U_, unsigned long bytes _U_,
                   unsigned long error _U_, struct smb2_context **smb2)
{
        if (smb2) {
                *smb2 = NULL;
        }
        return -1;
}

#endif /* HAVE_SMB2_IOCP */
