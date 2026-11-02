/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Artiom Morozov <amorozov@resilio.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
 * Print a file to stdout, with libsmb2 driven by an I/O completion port
 * (Windows), see smb2_iocp_attach().
 *
 *   smb2-cat-iocp smb://[domain;][user@]server[:port]/share/path
 *
 * The password comes from the file named by NTLM_USER_FILE, as with the
 * other examples; without one the session is anonymous.
 */
#include <winsock2.h>
#include <windows.h>

#include <fcntl.h>
#include <io.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "smb2.h"
#include "libsmb2.h"

/* completion key of libsmb2's sockets on our port */
#define SMB2_KEY ((ULONG_PTR)0x534d4232)

#define READ_SIZE (64 * 1024)

struct cat {
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct smb2fh *fh;
        uint8_t buf[READ_SIZE];
        uint64_t pos;
        int done;
        int failed;
        LARGE_INTEGER freq, last;
};

/* milliseconds since the previous mark */
static double
lap(struct cat *c)
{
        LARGE_INTEGER now;
        double ms;

        QueryPerformanceCounter(&now);
        ms = (double)(now.QuadPart - c->last.QuadPart) * 1000.0 /
                (double)c->freq.QuadPart;
        c->last = now;
        return ms;
}

static void
fail(struct cat *c, const char *what, int status)
{
        fprintf(stderr, "%s failed: %s (%d)\n", what,
                smb2_get_error(c->smb2), status);
        c->failed = 1;
        c->done = 1;
}

static void
disconnect_cb(struct smb2_context *smb2, int status,
              void *command_data, void *private_data)
{
        struct cat *c = private_data;

        fprintf(stderr, "disconnect: %.2f ms\n", lap(c));
        c->done = 1;
}

static void
close_cb(struct smb2_context *smb2, int status,
         void *command_data, void *private_data)
{
        struct cat *c = private_data;

        if (status) {
                fail(c, "close", status);
                return;
        }
        fprintf(stderr, "close: %.2f ms\n", lap(c));
        if (smb2_disconnect_share_async(smb2, disconnect_cb, c) < 0) {
                fail(c, "smb2_disconnect_share_async", 0);
        }
}

static void
read_cb(struct smb2_context *smb2, int status,
        void *command_data, void *private_data)
{
        struct cat *c = private_data;

        if (status < 0) {
                fail(c, "read", status);
                return;
        }
        if (status == 0) {
                fprintf(stderr, "read %llu bytes: %.2f ms\n",
                        (unsigned long long)c->pos, lap(c));
                if (smb2_close_async(smb2, c->fh, close_cb, c) < 0) {
                        fail(c, "smb2_close_async", 0);
                }
                return;
        }
        fwrite(c->buf, 1, (size_t)status, stdout);
        c->pos += (uint64_t)status;
        if (smb2_pread_async(smb2, c->fh, c->buf, READ_SIZE, c->pos,
                             read_cb, c) < 0) {
                fail(c, "smb2_pread_async", 0);
        }
}

static void
open_cb(struct smb2_context *smb2, int status,
        void *command_data, void *private_data)
{
        struct cat *c = private_data;

        if (status) {
                fail(c, "open", status);
                return;
        }
        fprintf(stderr, "open: %.2f ms\n", lap(c));
        c->fh = command_data;
        if (smb2_pread_async(smb2, c->fh, c->buf, READ_SIZE, 0,
                             read_cb, c) < 0) {
                fail(c, "smb2_pread_async", 0);
        }
}

static void
connect_cb(struct smb2_context *smb2, int status,
           void *command_data, void *private_data)
{
        struct cat *c = private_data;

        if (status) {
                fail(c, "connect", status);
                return;
        }
        fprintf(stderr, "connect (tcp, negotiate, session setup, tree "
                "connect): %.2f ms\n", lap(c));
        if (smb2_open_async(smb2, c->url->path, O_RDONLY, open_cb, c) < 0) {
                fail(c, "smb2_open_async", 0);
        }
}

int
main(int argc, char *argv[])
{
        static struct cat c;
        WSADATA wsa;
        HANDLE port;
        int released = 0;

        if (argc < 2) {
                fprintf(stderr, "usage: %s smb://[domain;][user@]server"
                        "[:port]/share/path\n", argv[0]);
                return 1;
        }
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
                fprintf(stderr, "WSAStartup failed\n");
                return 1;
        }
        _setmode(_fileno(stdout), _O_BINARY);
        QueryPerformanceFrequency(&c.freq);

        port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
        if (port == NULL) {
                fprintf(stderr, "CreateIoCompletionPort failed: %lu\n",
                        GetLastError());
                return 1;
        }

        c.smb2 = smb2_init_context();
        if (c.smb2 == NULL) {
                fprintf(stderr, "smb2_init_context failed\n");
                return 1;
        }
        c.url = smb2_parse_url(c.smb2, argv[1]);
        if (c.url == NULL || c.url->path == NULL) {
                fprintf(stderr, "bad URL: %s\n", smb2_get_error(c.smb2));
                return 1;
        }
        if (c.url->domain) {
                smb2_set_domain(c.smb2, c.url->domain);
        }
        smb2_set_security_mode(c.smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);

        if (smb2_iocp_attach(c.smb2, port, SMB2_KEY) < 0) {
                fprintf(stderr, "smb2_iocp_attach: %s\n",
                        smb2_get_error(c.smb2));
                return 1;
        }

        QueryPerformanceCounter(&c.last);
        if (smb2_connect_share_async(c.smb2, c.url->server, c.url->share,
                                     c.url->user, connect_cb, &c) != 0) {
                fprintf(stderr, "smb2_connect_share_async: %s\n",
                        smb2_get_error(c.smb2));
                return 1;
        }

        while (!c.done) {
                DWORD bytes = 0;
                ULONG_PTR key = 0;
                OVERLAPPED *ov = NULL;
                struct smb2_context *ctx;
                BOOL ok;

                ok = GetQueuedCompletionStatus(port, &bytes, &key, &ov, 1000);
                if (ov == NULL) {
                        if (GetLastError() == WAIT_TIMEOUT) {
                                /* expires timed out commands */
                                smb2_service(c.smb2, 0);
                                continue;
                        }
                        fprintf(stderr, "GetQueuedCompletionStatus: %lu\n",
                                GetLastError());
                        c.failed = 1;
                        break;
                }
                if (key != SMB2_KEY) {
                        continue;
                }
                if (smb2_iocp_complete(ov, bytes, ok ? 0 : GetLastError(),
                                       &ctx) < 0) {
                        fprintf(stderr, "connection failed: %s\n",
                                smb2_get_error(ctx));
                        c.failed = 1;
                        break;
                }
        }

        smb2_destroy_url(c.url);
        smb2_destroy_context(c.smb2);

        /* Operations still in flight when the socket closed complete now,
         * aborted. Hand them over so their memory is released. */
        for (;;) {
                DWORD bytes = 0;
                ULONG_PTR key = 0;
                OVERLAPPED *ov = NULL;
                struct smb2_context *ctx;
                BOOL ok;

                ok = GetQueuedCompletionStatus(port, &bytes, &key, &ov, 200);
                if (ov == NULL) {
                        break;
                }
                if (key == SMB2_KEY) {
                        smb2_iocp_complete(ov, bytes, ok ? 0 : GetLastError(),
                                           &ctx);
                        released++;
                }
        }
        fprintf(stderr, "released %d aborted operation(s)\n", released);

        CloseHandle(port);
        WSACleanup();
        return c.failed ? 1 : 0;
}
