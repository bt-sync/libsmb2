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
 * Client authentication through Windows SSPI, see sspi-wrapper.h.
 *
 * The Negotiate package is used: SPNEGO with Kerberos, falling back to
 * NTLM inside SSPI. Its tokens go into the session setup security buffer
 * as they are, like the GSS-API tokens of krb5-wrapper.c, and the SMB
 * session key is the context's session key (of which libsmb2 uses the
 * first 16 bytes).
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"

#ifdef HAVE_SSPI
#define SECURITY_WIN32
#include <security.h>
#endif

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"
#include "sspi-wrapper.h"

#ifdef HAVE_SSPI

#define SSPI_PACKAGE L"Negotiate"

/* the same as krb5-wrapper.c asks GSS-API for */
#define SSPI_ISC_FLAGS (ISC_REQ_MUTUAL_AUTH | ISC_REQ_REPLAY_DETECT | \
                        ISC_REQ_SEQUENCE_DETECT | ISC_REQ_ALLOCATE_MEMORY)

/* smb2_context keeps the CredHandle of smb2_set_sspi_cred() without
 * depending on the SSPI headers */
typedef char sspi_cred_fits[sizeof(CredHandle) ==
                            sizeof(((struct smb2_context *)0)->sspi_cred) ?
                            1 : -1];

struct sspi_auth_data {
        CredHandle cred;
        int own_cred;           /* acquired here, not smb2_set_sspi_cred() */
        CtxtHandle ctx;
        int have_ctx;
        int done;               /* InitializeSecurityContext returned OK */
        wchar_t *target;        /* cifs/<server> */
        void *out;              /* allocated by SSPI */
        unsigned long out_len;
};

static void
set_sspi_error(struct smb2_context *smb2, const char *func,
               SECURITY_STATUS status)
{
        char msg[256] = "";
        DWORD n;

        n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                           (DWORD)status, 0, msg, sizeof(msg), NULL);
        while (n > 0 && (msg[n - 1] == '\r' || msg[n - 1] == '\n' ||
                         msg[n - 1] == ' ' || msg[n - 1] == '.')) {
                msg[--n] = '\0';
        }
        smb2_set_error(smb2, "%s failed: 0x%08lx %s", func,
                       (unsigned long)status, msg);
}

static wchar_t *
utf8_to_wide(const char *s)
{
        wchar_t *w;
        int n;

        if (s == NULL) {
                return NULL;
        }
        n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
        if (n <= 0) {
                return NULL;
        }
        w = malloc((size_t)n * sizeof(wchar_t));
        if (w != NULL && MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) <= 0) {
                free(w);
                w = NULL;
        }
        return w;
}

static void
free_wide(wchar_t *w, int secret)
{
        if (w != NULL && secret) {
                SecureZeroMemory(w, wcslen(w) * sizeof(wchar_t));
        }
        free(w);
}

/* cifs/<host>, from a server string that may carry a port, and [] around
 * an IPv6 address */
static wchar_t *
target_name(const char *server)
{
        char spn[1024];
        const char *end;
        size_t len;

        if (server[0] == '[') {
                server++;
                end = strchr(server, ']');
        } else {
                end = strchr(server, ':');
        }
        len = end ? (size_t)(end - server) : strlen(server);
        if (len + sizeof("cifs/") > sizeof(spn)) {
                return NULL;
        }
        memcpy(spn, "cifs/", 5);
        memcpy(spn + 5, server, len);
        spn[5 + len] = '\0';
        return utf8_to_wide(spn);
}

static void
free_output(struct sspi_auth_data *auth_data)
{
        if (auth_data->out != NULL) {
                FreeContextBuffer(auth_data->out);
                auth_data->out = NULL;
        }
        auth_data->out_len = 0;
}

/* One InitializeSecurityContext round, with the server's token if any */
static int
sspi_step(struct smb2_context *smb2, struct sspi_auth_data *auth_data,
          unsigned char *buf, int len)
{
        SecBuffer in_buf, out_buf;
        SecBufferDesc in_desc, out_desc;
        SECURITY_STATUS status;
        TimeStamp expiry;
        ULONG attrs = 0;

        free_output(auth_data);

        in_buf.BufferType = SECBUFFER_TOKEN;
        in_buf.cbBuffer = (unsigned long)len;
        in_buf.pvBuffer = buf;
        in_desc.ulVersion = SECBUFFER_VERSION;
        in_desc.cBuffers = 1;
        in_desc.pBuffers = &in_buf;

        out_buf.BufferType = SECBUFFER_TOKEN;
        out_buf.cbBuffer = 0;
        out_buf.pvBuffer = NULL;
        out_desc.ulVersion = SECBUFFER_VERSION;
        out_desc.cBuffers = 1;
        out_desc.pBuffers = &out_buf;

        status = InitializeSecurityContextW(&auth_data->cred,
                        auth_data->have_ctx ? &auth_data->ctx : NULL,
                        auth_data->target, SSPI_ISC_FLAGS, 0,
                        SECURITY_NATIVE_DREP, buf ? &in_desc : NULL, 0,
                        &auth_data->ctx, &out_desc, &attrs, &expiry);
        if (status == SEC_I_COMPLETE_NEEDED ||
            status == SEC_I_COMPLETE_AND_CONTINUE) {
                SECURITY_STATUS complete;

                auth_data->have_ctx = 1;
                complete = CompleteAuthToken(&auth_data->ctx, &out_desc);
                if (complete != SEC_E_OK) {
                        if (out_buf.pvBuffer != NULL) {
                                FreeContextBuffer(out_buf.pvBuffer);
                        }
                        set_sspi_error(smb2, "CompleteAuthToken", complete);
                        return -1;
                }
                status = status == SEC_I_COMPLETE_NEEDED ?
                        SEC_E_OK : SEC_I_CONTINUE_NEEDED;
        }
        if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
                if (out_buf.pvBuffer != NULL) {
                        FreeContextBuffer(out_buf.pvBuffer);
                }
                set_sspi_error(smb2, "InitializeSecurityContext", status);
                return -1;
        }
        auth_data->have_ctx = 1;
        auth_data->out = out_buf.pvBuffer;
        auth_data->out_len = out_buf.cbBuffer;
        if (status == SEC_E_OK) {
                auth_data->done = 1;
        }
        return 0;
}

struct sspi_auth_data *
sspi_negotiate_reply(struct smb2_context *smb2,
                     const char *server,
                     const char *domain,
                     const char *user,
                     const char *password)
{
        struct sspi_auth_data *auth_data;
        SECURITY_STATUS status;
        TimeStamp expiry;

        auth_data = calloc(1, sizeof(*auth_data));
        if (auth_data == NULL) {
                smb2_set_error(smb2, "sspi: out of memory");
                return NULL;
        }
        auth_data->target = target_name(server);
        if (auth_data->target == NULL) {
                smb2_set_error(smb2, "sspi: bad server name %s", server);
                goto failed;
        }

        if (smb2->sspi_cred_set) {
                memcpy(&auth_data->cred, smb2->sspi_cred,
                       sizeof(auth_data->cred));
        } else {
                SEC_WINNT_AUTH_IDENTITY_W id;
                void *auth = NULL;
                wchar_t *w_user = NULL, *w_domain = NULL, *w_password = NULL;

                if (password != NULL) {
                        /* smb2_set_password() takes "ntlm:<NT hash>" too,
                         * which only libsmb2's own NTLMSSP can use */
                        if (strncmp(password, "ntlm:", 5) == 0) {
                                smb2_set_error(smb2, "sspi: can not use an "
                                               "NT hash, only a password");
                                goto failed;
                        }
                        w_user = utf8_to_wide(user ? user : "");
                        w_domain = utf8_to_wide(domain ? domain : "");
                        w_password = utf8_to_wide(password);
                        if (w_user == NULL || w_domain == NULL ||
                            w_password == NULL) {
                                free_wide(w_user, 0);
                                free_wide(w_domain, 0);
                                free_wide(w_password, 1);
                                smb2_set_error(smb2, "sspi: bad user, domain "
                                               "or password");
                                goto failed;
                        }
                        memset(&id, 0, sizeof(id));
                        id.User = (unsigned short *)w_user;
                        id.UserLength = (unsigned long)wcslen(w_user);
                        id.Domain = (unsigned short *)w_domain;
                        id.DomainLength = (unsigned long)wcslen(w_domain);
                        id.Password = (unsigned short *)w_password;
                        id.PasswordLength = (unsigned long)wcslen(w_password);
                        id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
                        auth = &id;
                }
                /* without a password: the logon session of the thread */
                status = AcquireCredentialsHandleW(NULL, SSPI_PACKAGE,
                                                   SECPKG_CRED_OUTBOUND,
                                                   NULL, auth, NULL, NULL,
                                                   &auth_data->cred, &expiry);
                free_wide(w_user, 0);
                free_wide(w_domain, 0);
                free_wide(w_password, 1);
                if (status != SEC_E_OK) {
                        set_sspi_error(smb2, "AcquireCredentialsHandle",
                                       status);
                        goto failed;
                }
                auth_data->own_cred = 1;
        }

        if (sspi_step(smb2, auth_data, NULL, 0) < 0) {
                goto failed;
        }
        return auth_data;

 failed:
        sspi_free_auth_data(auth_data);
        return NULL;
}

int
sspi_session_request(struct smb2_context *smb2,
                     struct sspi_auth_data *auth_data,
                     unsigned char *buf, int len)
{
        if (buf == NULL) {
                /* the first token, from sspi_negotiate_reply() */
                return 0;
        }
        if (auth_data->done) {
                /* nothing more expected, e.g. the final leg after a
                 * context that completed without mutual authentication */
                free_output(auth_data);
                return 0;
        }
        return sspi_step(smb2, auth_data, buf, len);
}

unsigned char *
sspi_get_output_token_buffer(struct sspi_auth_data *auth_data)
{
        return auth_data->out;
}

int
sspi_get_output_token_length(struct sspi_auth_data *auth_data)
{
        return (int)auth_data->out_len;
}

int
sspi_session_get_session_key(struct smb2_context *smb2,
                             struct sspi_auth_data *auth_data)
{
        SecPkgContext_SessionKey key;
        SECURITY_STATUS status;

        if (!auth_data->have_ctx) {
                smb2_set_error(smb2, "sspi: no security context");
                return -1;
        }
        status = QueryContextAttributesW(&auth_data->ctx,
                                         SECPKG_ATTR_SESSION_KEY, &key);
        if (status != SEC_E_OK) {
                set_sspi_error(smb2, "QueryContextAttributes(SESSION_KEY)",
                               status);
                return -1;
        }
        if (key.SessionKeyLength == 0 || key.SessionKeyLength > 255) {
                FreeContextBuffer(key.SessionKey);
                smb2_set_error(smb2, "sspi: invalid session key");
                return -1;
        }
        free(smb2->session_key);
        smb2->session_key = malloc(key.SessionKeyLength);
        if (smb2->session_key == NULL) {
                smb2->session_key_size = 0;
                SecureZeroMemory(key.SessionKey, key.SessionKeyLength);
                FreeContextBuffer(key.SessionKey);
                smb2_set_error(smb2, "sspi: out of memory");
                return -1;
        }
        memcpy(smb2->session_key, key.SessionKey, key.SessionKeyLength);
        smb2->session_key_size = (uint8_t)key.SessionKeyLength;
        SecureZeroMemory(key.SessionKey, key.SessionKeyLength);
        FreeContextBuffer(key.SessionKey);
        return 0;
}

void
sspi_free_auth_data(struct sspi_auth_data *auth_data)
{
        if (auth_data == NULL) {
                return;
        }
        free_output(auth_data);
        if (auth_data->have_ctx) {
                DeleteSecurityContext(&auth_data->ctx);
        }
        if (auth_data->own_cred) {
                FreeCredentialsHandle(&auth_data->cred);
        }
        free(auth_data->target);
        free(auth_data);
}

int
smb2_set_sspi_cred(struct smb2_context *smb2, const void *cred)
{
        if (cred == NULL) {
                smb2->sspi_cred_set = 0;
                return 0;
        }
        memcpy(smb2->sspi_cred, cred, sizeof(smb2->sspi_cred));
        smb2->sspi_cred_set = 1;
        /* a credential is only of use to the SSPI path */
        if (smb2->sec == SMB2_SEC_UNDEFINED) {
                smb2->sec = SMB2_SEC_KRB5;
        }
        return 0;
}

#else /* HAVE_SSPI */

int
smb2_set_sspi_cred(struct smb2_context *smb2, const void *cred _U_)
{
        smb2_set_error(smb2, "sspi: built without SSPI support");
        return -1;
}

#endif /* HAVE_SSPI */
