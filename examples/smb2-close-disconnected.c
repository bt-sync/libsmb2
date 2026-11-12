/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Close struct smb2fh handles on a context whose connection is gone, and
 * check that libsmb2 neither hangs nor touches freed memory, and frees
 * every handle exactly once.
 *
 *   smb2-close-disconnected <scenario> smb://[user@]server[:port]/share/path
 *
 * The password is taken from SMB2_PASSWORD. path names a directory on the
 * share in which close-disc-*.tmp files are created (and left for the
 * caller to remove: the connection is dead by the time we would).
 *
 * Build in Debug with the debug CRT: the debug heap fills freed blocks
 * with 0xDD, keeps them (_CRTDBG_DELAY_FREE_MEM_DF) and checks the whole
 * heap on every call, so writes after free and double frees are caught.
 * Run with PAGEHEAP=1 under gflags /p /full to catch reads after free.
 *
 * On Linux, build with -fsanitize=address instead, and run as root (it
 * signals the smbd child serving the connection, which runs locally).
 *
 * Scenarios, a- drives the context through an I/O completion port the way
 * sync-core does on Windows, or through epoll with smb2_fd_event_callbacks()
 * and smb2_service_fd(-1, 0) as the 1 s tick on Linux; s- uses the
 * synchronous API on a polled context:
 *   a-healthy  s-healthy        close on a healthy session
 *   a-shutdown s-shutdown       shutdown() of the socket, then close
 *   a-closesocket s-closesocket closesocket() behind libsmb2's back
 *   a-kill     s-kill           kill -9 of the smbd child, then close
 *   a-kill-timeout              a-kill with smb2_set_timeout(3)
 *   a-inflight-queued           close queued (not yet sent), then shutdown
 *   a-inflight-sent             smbd child stopped, close sent, kill -9
 *   a-inflight-sent-client      smbd child stopped, close sent, shutdown
 *   a-destroy-queued            close queued on a healthy session, destroy
 *   a-destroy-sent              close sent, no reply yet, destroy
 *   a-destroy-dead              smbd child killed, close queued, destroy
 *   a-destroy-open              destroy with the handles never closed
 *   a-silent-then-close         smbd child stopped, client shutdown, then
 *                               close (NOTICK=1 disables the 1 s tick)
 *   a-destroy-kick              smbd child killed, close issued on the
 *                               broken socket, destroy before the
 *                               completion that services it is dequeued
 *   a-double-close              fh[0] closed twice on a dead session
 *                               (caller misuse, shows what it costs)
 *
 * The s- scenarios that drop the connection also call smb2_open() and
 * smb2_opendir() on the dead session before closing.
 *
 * With RAWFH=1 in the environment the a- scenarios open the files as
 * sync-core does: a raw CREATE, then smb2_fh_from_file_id().
 */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <crtdbg.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
/* only to look at the queues of the context */
#ifdef _WIN32
typedef SSIZE_T ssize_t;
struct iovec;
#endif
#include "libsmb2-private.h"

#ifdef _WIN32
#pragma comment(lib, "ntdll.lib")
ULONG WINAPI RtlNtStatusToDosError(LONG status);

#define SMB2_KEY ((ULONG_PTR)4)
#define AS_ROOT "wsl.exe -u root -e "
#define SHUT_RDWR SD_BOTH
#define popen _popen
#define pclose _pclose
#define getpid GetCurrentProcessId
#define sleep_ms Sleep
#define now_ms GetTickCount64
#else
#define AS_ROOT ""
#define closesocket close
#define WSAGetLastError() errno
#define TRUE 1
typedef unsigned long DWORD;
typedef long LONG;
typedef unsigned long long ULONGLONG;

static ULONGLONG
now_ms(void)
{
        struct timespec ts;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (ULONGLONG)ts.tv_sec * 1000 + (ULONGLONG)ts.tv_nsec / 1000000;
}

static void
sleep_ms(DWORD ms)
{
        usleep(ms * 1000);
}
#endif

#define NFH 3
#define TICK_MS 1000
#define WAIT_MS 10000

struct fhrec {
        struct smb2fh *fh;
        int open_done;
        int open_status;
        int close_rc;
        int cb_fired;
        int cb_status;
        const char *cb_ctx_error;
        volatile LONG freed;
};

static struct fhrec g_fh[NFH];
static volatile LONG g_ctx_freed;
static struct smb2_context *g_smb2;

#ifdef _WIN32
static HANDLE g_port;
#else
static int g_epfd = -1;
#endif
static int g_async;
static int g_iocp_fail;
static int g_service_fail;
static int g_completions;
static int g_released_after_destroy;
static ULONGLONG g_last_tick;
static const char *g_scenario;
static int g_in_close_call;
static int g_cb_inside_close_call;

static volatile const char *g_step = "start";
static volatile ULONGLONG g_step_deadline;

static void
note_free(const volatile void *data)
{
        int i;

        if (data == NULL) {
                return;
        }
        for (i = 0; i < NFH; i++) {
                if ((const volatile void *)g_fh[i].fh == data) {
                        g_fh[i].freed++;
                }
        }
        if (g_smb2 != NULL && (const volatile void *)g_smb2 == data) {
                g_ctx_freed++;
        }
}

#ifdef _WIN32
static int
alloc_hook(int type, void *data, size_t size, int block_type, long request,
           const unsigned char *file, int line)
{
        (void)size; (void)block_type; (void)request; (void)file; (void)line;
        if (type == _HOOK_FREE) {
                note_free(data);
        }
        return TRUE;
}

static DWORD WINAPI
watchdog(void *arg)
{
        (void)arg;
        for (;;) {
                Sleep(200);
                if (g_step_deadline && now_ms() > g_step_deadline) {
                        fprintf(stderr, "WATCHDOG: HUNG in step '%s'\n",
                                (const char *)g_step);
                        fflush(stderr);
                        if (IsDebuggerPresent()) {
                                DebugBreak();
                        }
                        TerminateProcess(GetCurrentProcess(), 3);
                }
        }
}
#else
#ifdef __SANITIZE_ADDRESS__
void __sanitizer_free_hook(const volatile void *ptr);

void
__sanitizer_free_hook(const volatile void *ptr)
{
        note_free(ptr);
}
#else
void __libc_free(void *ptr);

void
free(void *ptr)
{
        note_free(ptr);
        __libc_free(ptr);
}
#endif

static void *
watchdog(void *arg)
{
        (void)arg;
        for (;;) {
                sleep_ms(200);
                if (g_step_deadline && now_ms() > g_step_deadline) {
                        fprintf(stderr, "WATCHDOG: HUNG in step '%s'\n",
                                (const char *)g_step);
                        fflush(stderr);
                        _exit(3);
                }
        }
        return NULL;
}
#endif

static void
step(const char *name, int seconds)
{
        g_step = name;
        g_step_deadline = seconds ? now_ms() + seconds * 1000ULL : 0;
        fprintf(stderr, "--- %s\n", name);
}

static int
list_len(struct smb2_pdu *p)
{
        int n = 0;

        for (; p; p = p->next) {
                n++;
        }
        return n;
}

static void
dump_state(const char *when)
{
        int i;

        fprintf(stderr, "[%s] ", when);
        if (g_smb2 != NULL && !g_ctx_freed) {
                fprintf(stderr, "fd=%lld outqueue=%d waitqueue=%d pdu=%p "
                        "err='%s' ", (long long)g_smb2->fd,
                        list_len(g_smb2->outqueue),
                        list_len(g_smb2->waitqueue), (void *)g_smb2->pdu,
                        smb2_get_error(g_smb2));
        }
        fprintf(stderr, "dispatch<0=%d tick<0=%d completions=%d "
                "cb_inside_close_call=%d\n", g_iocp_fail, g_service_fail,
                g_completions, g_cb_inside_close_call);
        for (i = 0; i < NFH; i++) {
                fprintf(stderr, "    fh[%d]=%p close_rc=%d cb_fired=%d "
                        "cb_status=%d freed=%ld\n", i, (void *)g_fh[i].fh,
                        g_fh[i].close_rc, g_fh[i].cb_fired,
                        g_fh[i].cb_status, g_fh[i].freed);
        }
}

#ifdef _WIN32
static void
dispatch(OVERLAPPED_ENTRY *e)
{
        struct smb2_context *ctx = NULL;
        DWORD err = RtlNtStatusToDosError((LONG)e->Internal);
        int rc;

        if (e->lpCompletionKey != SMB2_KEY) {
                return;
        }
        g_completions++;
        rc = smb2_iocp_complete(e->lpOverlapped,
                                e->dwNumberOfBytesTransferred, err, &ctx);
        if (ctx == NULL) {
                g_released_after_destroy++;
        }
        if (rc < 0) {
                if (g_iocp_fail++ < 3) {
                        fprintf(stderr, "  smb2_iocp_complete rc=%d bytes=%lu "
                                "err=%lu: %s\n", rc,
                                e->dwNumberOfBytesTransferred, err,
                                ctx ? smb2_get_error(ctx) : "(no ctx)");
                }
        }
}

/* One round of the sync-core fiber loop: completions, then the 1 s tick */
static void
pump_once(DWORD timeout)
{
        OVERLAPPED_ENTRY entries[64];
        ULONG count = 0, i;
        ULONGLONG now;

        if (GetQueuedCompletionStatusEx(g_port, entries, 64, &count, timeout,
                                        FALSE)) {
                for (i = 0; i < count; i++) {
                        dispatch(&entries[i]);
                }
        }
        now = now_ms();
        if (g_smb2 != NULL && now - g_last_tick >= TICK_MS &&
            getenv("NOTICK") == NULL) {
                g_last_tick = now;
                if (smb2_service(g_smb2, 0) < 0) {
                        if (g_service_fail++ < 3) {
                                fprintf(stderr, "  tick smb2_service < 0: "
                                        "%s\n", smb2_get_error(g_smb2));
                        }
                }
        }
}
#else
static void
change_fd_cb(struct smb2_context *smb2, t_socket fd, int cmd)
{
        struct epoll_event ev;

        (void)smb2;
        memset(&ev, 0, sizeof(ev));
        ev.data.fd = fd;
        if (epoll_ctl(g_epfd, cmd == SMB2_ADD_FD ? EPOLL_CTL_ADD :
                      EPOLL_CTL_DEL, fd, &ev) != 0) {
                fprintf(stderr, "  epoll_ctl(%s, %d): %s\n",
                        cmd == SMB2_ADD_FD ? "ADD" : "DEL", fd,
                        strerror(errno));
        }
}

static void
change_events_cb(struct smb2_context *smb2, t_socket fd, int events)
{
        struct epoll_event ev;

        (void)smb2;
        memset(&ev, 0, sizeof(ev));
        ev.data.fd = fd;
        ev.events = (events & POLLIN ? EPOLLIN : 0) |
                (events & POLLOUT ? EPOLLOUT : 0);
        if (epoll_ctl(g_epfd, EPOLL_CTL_MOD, fd, &ev) != 0) {
                fprintf(stderr, "  epoll_ctl(MOD, %d, %d): %s\n", fd, events,
                        strerror(errno));
        }
}

/* One round of the sync-core epoll loop: events, then the 1 s tick */
static void
pump_once(DWORD timeout)
{
        struct epoll_event ev[8];
        ULONGLONG now;
        int n, i, rc;

        n = epoll_wait(g_epfd, ev, 8, (int)timeout);
        for (i = 0; i < n && g_smb2 != NULL; i++) {
                g_completions++;
                rc = smb2_service_fd(g_smb2, ev[i].data.fd,
                                     (int)ev[i].events);
                if (rc < 0 && g_iocp_fail++ < 3) {
                        fprintf(stderr, "  smb2_service_fd(%d, 0x%x) rc=%d: "
                                "%s\n", ev[i].data.fd, ev[i].events, rc,
                                smb2_get_error(g_smb2));
                }
        }
        now = now_ms();
        if (g_smb2 != NULL && now - g_last_tick >= TICK_MS &&
            getenv("NOTICK") == NULL) {
                g_last_tick = now;
                if (smb2_service_fd(g_smb2, -1, 0) < 0) {
                        if (g_service_fail++ < 3) {
                                fprintf(stderr, "  tick smb2_service_fd < 0: "
                                        "%s\n", smb2_get_error(g_smb2));
                        }
                }
        }
}
#endif

/* Pump until *flag (or all of flags[n]) is set; 0 if done, -1 on timeout */
static int
pump_until(volatile int *flags, int n, int stride, DWORD ms)
{
        ULONGLONG end = now_ms() + ms;
        int i, done;

        for (;;) {
                done = 1;
                for (i = 0; i < n; i++) {
                        if (!*(volatile int *)((char *)flags + i * stride)) {
                                done = 0;
                        }
                }
                if (done) {
                        return 0;
                }
                if (now_ms() >= end) {
                        return -1;
                }
                pump_once(100);
        }
}

static void
pump_for(DWORD ms)
{
        ULONGLONG end = now_ms() + ms;

        while (now_ms() < end) {
                pump_once(50);
        }
}

static void
drain_after_destroy(void)
{
        ULONGLONG end = now_ms() + 1000;

        while (now_ms() < end) {
                pump_once(100);
        }
}

/* ------------------------------------------------------------------ */

static int g_connected, g_connect_status;

static void
connect_cb(struct smb2_context *smb2, int status, void *cd, void *pd)
{
        (void)smb2; (void)cd; (void)pd;
        g_connect_status = status;
        g_connected = 1;
}

static void
create_cb(struct smb2_context *smb2, int status, void *cd, void *pd)
{
        struct fhrec *r = pd;

        r->open_status = status;
        if (status == 0) {
                r->fh = smb2_fh_from_file_id(smb2, &((struct smb2_create_reply *)cd)->file_id);
        }
        r->open_done = 1;
}

static int
raw_open_async(const char *path, struct fhrec *r)
{
        struct smb2_create_request req;
        struct smb2_pdu *pdu;

        memset(&req, 0, sizeof(req));
        req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        req.desired_access = SMB2_FILE_READ_DATA | SMB2_FILE_WRITE_DATA |
                SMB2_FILE_READ_ATTRIBUTES | SMB2_FILE_WRITE_ATTRIBUTES;
        req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE |
                SMB2_FILE_SHARE_DELETE;
        req.create_disposition = SMB2_FILE_OPEN_IF;
        req.name = path;
        pdu = smb2_cmd_create_async(g_smb2, &req, create_cb, r);
        if (pdu == NULL) {
                return -1;
        }
        smb2_queue_pdu(g_smb2, pdu);
        return 0;
}

static void
open_cb(struct smb2_context *smb2, int status, void *cd, void *pd)
{
        struct fhrec *r = pd;

        (void)smb2;
        r->open_status = status;
        if (status == 0) {
                r->fh = cd;
        }
        r->open_done = 1;
}

static void
close_cb(struct smb2_context *smb2, int status, void *cd, void *pd)
{
        struct fhrec *r = pd;

        r->cb_fired++;
        if (g_in_close_call) {
                g_cb_inside_close_call++;
        }
        r->cb_status = status;
        /* touch the context from the callback, as a real caller would */
        r->cb_ctx_error = smb2_get_error(smb2);
        fprintf(stderr, "  close_cb fh[%d] status=%d (%s) cd=%p ctx_err='%s'\n",
                (int)(r - g_fh), status, status ? strerror(-status) : "ok",
                cd, r->cb_ctx_error);
}

/* ------------------------------------------------------------------ */

static int
local_port(void)
{
        struct sockaddr_storage ss;
        socklen_t len = sizeof(ss);
        t_socket fd = smb2_get_fd(g_smb2);

        if (getsockname(fd, (struct sockaddr *)&ss, &len) != 0) {
                return -1;
        }
        if (ss.ss_family == AF_INET) {
                return ntohs(((struct sockaddr_in *)&ss)->sin_port);
        }
        return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
}

static int
collect_pids(const char *cmd, int *pids, int max)
{
        char line[1024];
        FILE *p = popen(cmd, "r");
        int n = 0, i, pid, dup;
        char *s;

        if (p == NULL) {
                return -1;
        }
        while (fgets(line, sizeof(line), p)) {
                fprintf(stderr, "    ss: %s", line);
                for (s = strstr(line, "pid="); s; s = strstr(s + 4, "pid=")) {
                        pid = atoi(s + 4);
                        dup = 0;
                        for (i = 0; i < n; i++) {
                                dup |= pids[i] == pid;
                        }
                        if (!dup && n < max) {
                                pids[n++] = pid;
                        }
                }
        }
        pclose(p);
        return n;
}

static int g_smbd_pid;

/* The smbd child serving our connection, never the listener */
static int
find_smbd_child(int port, int server_port)
{
        char cmd[512];
        int conn[8], lst[8], nc, nl, i;

        snprintf(cmd, sizeof(cmd), AS_ROOT "ss -tnpH state "
                 "established \"( sport = :%d and dport = :%d )\"",
                 server_port, port);
        nc = collect_pids(cmd, conn, 8);
        snprintf(cmd, sizeof(cmd), AS_ROOT "ss -tlnpH "
                 "\"( sport = :%d )\"", server_port);
        nl = collect_pids(cmd, lst, 8);
        if (nc != 1) {
                fprintf(stderr, "expected one smbd pid for port %d, got %d\n",
                        port, nc);
                return -1;
        }
        for (i = 0; i < nl; i++) {
                if (lst[i] == conn[0]) {
                        fprintf(stderr, "pid %d is the listener, refusing\n",
                                conn[0]);
                        return -1;
                }
        }
        return conn[0];
}

static int
signal_smbd(const char *sig)
{
        char cmd[128];
        int rc;

        snprintf(cmd, sizeof(cmd), AS_ROOT "kill -%s %d", sig,
                 g_smbd_pid);
        rc = system(cmd);
        fprintf(stderr, "  kill -%s %d: rc=%d\n", sig, g_smbd_pid, rc);
        return rc;
}

/* ------------------------------------------------------------------ */

static struct smb2_url *g_url;
static int g_server_port = 445;

static int
setup(int async, int timeout)
{
        char path[256];
        int i;
        const char *pw = getenv("SMB2_PASSWORD");
        const char *colon;

        g_smb2 = smb2_init_context();
        g_url = smb2_parse_url(g_smb2, getenv("SMB2_URL"));
        if (g_url == NULL) {
                fprintf(stderr, "bad url: %s\n", smb2_get_error(g_smb2));
                return -1;
        }
        colon = strchr(g_url->server, ':');
        if (colon) {
                g_server_port = atoi(colon + 1);
        }
        if (g_url->user) {
                smb2_set_user(g_smb2, g_url->user);
        }
        if (pw) {
                smb2_set_password(g_smb2, pw);
        }
        smb2_set_security_mode(g_smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
        if (timeout) {
                smb2_set_timeout(g_smb2, timeout);
        }

        step("connect", 30);
        if (async) {
#ifdef _WIN32
                if (smb2_iocp_attach(g_smb2, g_port, SMB2_KEY) < 0) {
                        fprintf(stderr, "attach: %s\n", smb2_get_error(g_smb2));
                        return -1;
                }
#else
                smb2_fd_event_callbacks(g_smb2, change_fd_cb,
                                        change_events_cb);
#endif
                if (smb2_connect_share_async(g_smb2, g_url->server,
                                             g_url->share, g_url->user,
                                             connect_cb, NULL) != 0 ||
                    pump_until(&g_connected, 1, 0, WAIT_MS) < 0 ||
                    g_connect_status != 0) {
                        fprintf(stderr, "connect failed: %d %s\n",
                                g_connect_status, smb2_get_error(g_smb2));
                        return -1;
                }
        } else if (smb2_connect_share(g_smb2, g_url->server, g_url->share,
                                      g_url->user) < 0) {
                fprintf(stderr, "connect failed: %s\n", smb2_get_error(g_smb2));
                return -1;
        }

        step("open", 30);
        for (i = 0; i < NFH; i++) {
                snprintf(path, sizeof(path), "%s%sclose-disc-%s-%d-%lu.tmp",
                         g_url->path ? g_url->path : "",
                         g_url->path && *g_url->path ? "/" : "",
                         g_scenario, i, (unsigned long)getpid());
                if (async) {
                        if ((getenv("RAWFH") ?
                             raw_open_async(path, &g_fh[i]) :
                             smb2_open_async(g_smb2, path,
                                             O_CREAT | O_RDWR, open_cb,
                                             &g_fh[i])) != 0 ||
                            pump_until(&g_fh[i].open_done, 1, 0,
                                       WAIT_MS) < 0 ||
                            g_fh[i].open_status != 0) {
                                fprintf(stderr, "open %s failed: %s\n", path,
                                        smb2_get_error(g_smb2));
                                return -1;
                        }
                } else {
                        g_fh[i].fh = smb2_open(g_smb2, path, O_CREAT | O_RDWR);
                        if (g_fh[i].fh == NULL) {
                                fprintf(stderr, "open %s failed: %s\n", path,
                                        smb2_get_error(g_smb2));
                                return -1;
                        }
                }
                if (!async && smb2_pwrite(g_smb2, g_fh[i].fh,
                                          (const uint8_t *)"x", 1, 0) != 1) {
                        fprintf(stderr, "write failed: %s\n",
                                smb2_get_error(g_smb2));
                }
        }
        fprintf(stderr, "connected, local port %d, server port %d\n",
                local_port(), g_server_port);
        return 0;
}

static void
close_all_async(void)
{
        int i;

        for (i = 0; i < NFH; i++) {
                g_in_close_call = 1;
                g_fh[i].close_rc = smb2_close_async(g_smb2, g_fh[i].fh,
                                                    close_cb, &g_fh[i]);
                g_in_close_call = 0;
                fprintf(stderr, "  smb2_close_async fh[%d] rc=%d\n", i,
                        g_fh[i].close_rc);
        }
}

static void
close_all_sync(void)
{
        int i;

        for (i = 0; i < NFH; i++) {
                ULONGLONG t0 = now_ms();

                g_fh[i].close_rc = smb2_close(g_smb2, g_fh[i].fh);
                fprintf(stderr, "  smb2_close fh[%d] rc=%d (%llu ms) err='%s'"
                        "\n", i, g_fh[i].close_rc, now_ms() - t0,
                        smb2_get_error(g_smb2));
        }
}

/* the sync calls that own their PDU (caller_frees_pdu) */
static void
sync_on_dead_session(void)
{
        struct smb2fh *fh;
        struct smb2dir *dir;

        fh = smb2_open(g_smb2, "close-disc-dead.tmp", O_RDONLY);
        fprintf(stderr, "  smb2_open on the dead session: %p err='%s'\n",
                (void *)fh, smb2_get_error(g_smb2));
        dir = smb2_opendir(g_smb2, "");
        fprintf(stderr, "  smb2_opendir on the dead session: %p err='%s'\n",
                (void *)dir, smb2_get_error(g_smb2));
}

static int
wait_close_cbs(DWORD ms)
{
        int rc = pump_until(&g_fh[0].cb_fired, NFH, sizeof(struct fhrec), ms);

        fprintf(stderr, "  wait for close callbacks: %s\n",
                rc == 0 ? "all fired" : "TIMED OUT");
        return rc;
}

static void
drop_client(int how)
{
        t_socket fd = smb2_get_fd(g_smb2);
        int rc;

        if (how == 0) {
                rc = shutdown(fd, SHUT_RDWR);
                fprintf(stderr, "  shutdown(%lld, both)=%d (%d)\n",
                        (long long)fd, rc, rc ? WSAGetLastError() : 0);
        } else {
                rc = closesocket(fd);
                fprintf(stderr, "  closesocket(%lld)=%d (%d)\n",
                        (long long)fd, rc, rc ? WSAGetLastError() : 0);
        }
}

static void
destroy(void)
{
        ULONGLONG t0;

        step("destroy", 30);
        dump_state("before destroy");
        t0 = now_ms();
        smb2_destroy_url(g_url);
        g_url = NULL;
        smb2_destroy_context(g_smb2);
        fprintf(stderr, "  smb2_destroy_context took %llu ms, ctx freed=%ld\n",
                now_ms() - t0, g_ctx_freed);
        g_smb2 = NULL;
        if (g_async) {
                drain_after_destroy();
                fprintf(stderr, "  completions released after destroy: %d\n",
                        g_released_after_destroy);
        }
        dump_state("after destroy");
}

static int
kill_server(int sigstop_first)
{
        g_smbd_pid = find_smbd_child(local_port(), g_server_port);
        if (g_smbd_pid <= 0) {
                return -1;
        }
        fprintf(stderr, "  smbd child for our connection: %d\n", g_smbd_pid);
        if (sigstop_first) {
                return signal_smbd("STOP");
        }
        return signal_smbd("9");
}

static int
run(const char *sc)
{
        int async = sc[0] == 'a';
        int timeout = strcmp(sc, "a-kill-timeout") == 0 ? 3 : 0;

        g_async = async;
        if (setup(async, timeout) < 0) {
                return 2;
        }

        if (!strcmp(sc, "a-healthy") || !strcmp(sc, "s-healthy")) {
                step("close", 30);
                if (async) {
                        close_all_async();
                        wait_close_cbs(WAIT_MS);
                } else {
                        close_all_sync();
                }
        } else if (!strcmp(sc, "a-shutdown") || !strcmp(sc, "s-shutdown") ||
                   !strcmp(sc, "a-closesocket") ||
                   !strcmp(sc, "s-closesocket") ||
                   !strcmp(sc, "a-kill") || !strcmp(sc, "s-kill") ||
                   !strcmp(sc, "a-kill-timeout")) {
                step("drop", 30);
                if (strstr(sc, "kill")) {
                        if (kill_server(0) < 0) {
                                return 2;
                        }
                } else {
                        drop_client(strstr(sc, "closesocket") ? 1 : 0);
                }
                if (async) {
                        /* let the transport see the drop, as an idle
                         * session would before the next close */
                        pump_for(2500);
                        dump_state("after drop");
                        step("close", 60);
                        close_all_async();
                        dump_state("after close_async");
                        wait_close_cbs(timeout ? 8000 : WAIT_MS);
                } else {
                        sleep_ms(1000);
                        step("close", 60);
                        sync_on_dead_session();
                        close_all_sync();
                }
        } else if (!strcmp(sc, "a-inflight-queued")) {
                step("close", 60);
                close_all_async();
                dump_state("queued");
                drop_client(0);
                wait_close_cbs(WAIT_MS);
        } else if (!strcmp(sc, "a-inflight-sent") ||
                   !strcmp(sc, "a-inflight-sent-client")) {
                step("stop server", 30);
                if (kill_server(1) < 0) {
                        return 2;
                }
                step("close", 60);
                close_all_async();
                smb2_service(g_smb2, 0);
                pump_for(500);
                dump_state("sent, no reply");
                if (!strcmp(sc, "a-inflight-sent")) {
                        signal_smbd("9");
                } else {
                        drop_client(0);
                }
                wait_close_cbs(WAIT_MS);
                if (strcmp(sc, "a-inflight-sent") != 0) {
                        signal_smbd("CONT");
                }
        } else if (!strcmp(sc, "a-destroy-queued")) {
                step("close", 30);
                close_all_async();
                dump_state("queued");
        } else if (!strcmp(sc, "a-destroy-sent")) {
                step("stop server", 30);
                if (kill_server(1) < 0) {
                        return 2;
                }
                step("close", 30);
                close_all_async();
                smb2_service(g_smb2, 0);
                pump_for(500);
                dump_state("sent, no reply");
        } else if (!strcmp(sc, "a-destroy-open")) {
                dump_state("open, not closed");
        } else if (!strcmp(sc, "a-double-close")) {
                step("drop", 30);
                if (kill_server(0) < 0) {
                        return 2;
                }
                pump_for(2500);
                step("close", 30);
                close_all_async();
                fprintf(stderr, "  second smb2_close_async fh[0] rc=%d\n",
                        smb2_close_async(g_smb2, g_fh[0].fh, close_cb,
                                         &g_fh[0]));
                pump_for(1500);
        } else if (!strcmp(sc, "a-silent-then-close")) {
                ULONGLONG t0;

                step("stop server", 30);
                if (kill_server(1) < 0) {
                        return 2;
                }
                drop_client(0);
                pump_for(1500);
                dump_state("silent, before close");
                step("close", 60);
                t0 = now_ms();
                close_all_async();
                dump_state("after close_async");
                wait_close_cbs(WAIT_MS);
                fprintf(stderr, "  close callbacks after %llu ms\n",
                        now_ms() - t0);
                signal_smbd("CONT");
        } else if (!strcmp(sc, "a-destroy-kick")) {
                step("drop", 30);
                if (kill_server(0) < 0) {
                        return 2;
                }
                pump_for(2500);
                step("close", 30);
                close_all_async();
                dump_state("issued, not pumped");
        } else if (!strcmp(sc, "a-destroy-dead")) {
                step("drop", 30);
                if (kill_server(0) < 0) {
                        return 2;
                }
                pump_for(2500);
                step("close", 30);
                close_all_async();
                pump_for(2500);
        } else {
                fprintf(stderr, "unknown scenario %s\n", sc);
                return 1;
        }

        dump_state("before destroy (pre-step)");
        destroy();
        if (!strcmp(sc, "a-destroy-sent")) {
                signal_smbd("CONT");
        }
        return 0;
}

int
main(int argc, char *argv[])
{
#ifdef _WIN32
        _CrtMemState before, after, diff;
        WSADATA wsa;
        int flags;
#else
        pthread_t wd;
#endif
        int rc, i, bad = 0;

        if (argc != 2) {
                fprintf(stderr, "usage: %s <scenario>, SMB2_URL and "
                        "SMB2_PASSWORD in the environment\n", argv[0]);
                return 1;
        }
        g_scenario = argv[1];
        setvbuf(stderr, NULL, _IONBF, 0);

#ifdef _WIN32
        flags = _CRTDBG_ALLOC_MEM_DF | _CRTDBG_CHECK_ALWAYS_DF |
                _CRTDBG_LEAK_CHECK_DF;
        if (getenv("PAGEHEAP") == NULL) {
                flags |= _CRTDBG_DELAY_FREE_MEM_DF;
        }
        _CrtSetDbgFlag(flags);
        for (i = _CRT_WARN; i <= _CRT_ASSERT; i++) {
                _CrtSetReportMode(i, _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG);
                _CrtSetReportFile(i, _CRTDBG_FILE_STDERR);
        }
        _CrtSetAllocHook(alloc_hook);
        CreateThread(NULL, 0, watchdog, NULL, 0, NULL);

        WSAStartup(MAKEWORD(2, 2), &wsa);
        g_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
        fprintf(stderr, "scenario %s (%s heap)\n", g_scenario,
                getenv("PAGEHEAP") ? "page" : "debug CRT, delayed free");
        _CrtMemCheckpoint(&before);
#else
        signal(SIGPIPE, SIG_IGN);
        pthread_create(&wd, NULL, watchdog, NULL);
        g_epfd = epoll_create1(EPOLL_CLOEXEC);
        fprintf(stderr, "scenario %s (%s)\n", g_scenario,
#ifdef __SANITIZE_ADDRESS__
                "AddressSanitizer"
#else
                "glibc heap"
#endif
                );
#endif
        g_last_tick = now_ms();

        rc = run(g_scenario);
        if (rc == 0) {
                step("final checks", 30);
                for (i = 0; i < NFH; i++) {
                        if (g_fh[i].freed != 1 || g_fh[i].cb_fired > 1) {
                                bad = 1;
                        }
                }
                if (g_ctx_freed != 1) {
                        bad = 1;
                }
#ifdef _WIN32
                fprintf(stderr, "_CrtCheckMemory: %s\n",
                        _CrtCheckMemory() ? "ok" : "CORRUPT");
                _CrtMemCheckpoint(&after);
                if (_CrtMemDifference(&diff, &before, &after)) {
                        fprintf(stderr, "heap delta: normal blocks %zu "
                                "(%zu bytes), crt blocks %zu, free blocks "
                                "%zu\n", diff.lCounts[_NORMAL_BLOCK],
                                diff.lSizes[_NORMAL_BLOCK],
                                diff.lCounts[_CRT_BLOCK],
                                diff.lCounts[_FREE_BLOCK]);
                } else {
                        fprintf(stderr, "heap delta: none\n");
                }
#endif
                fprintf(stderr, "RESULT %s: %s\n", g_scenario,
                        bad ? "fh or context NOT freed exactly once" :
                        "every fh and the context freed exactly once");
        }
        step("exit", 0);
#ifdef _WIN32
        CloseHandle(g_port);
        WSACleanup();
#else
        close(g_epfd);
#endif
        return rc ? rc : bad;
}
