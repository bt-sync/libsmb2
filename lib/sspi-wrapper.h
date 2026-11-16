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

#ifndef _SSPI_WRAPPER_H_
#define _SSPI_WRAPPER_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Client authentication through Windows SSPI (the Negotiate package:
 * Kerberos, falling back to NTLM inside SSPI), the counterpart of
 * krb5-wrapper.c. Used for SMB2_SEC_KRB5 when built with HAVE_SSPI.
 */
struct sspi_auth_data;

/*
 * Set up the security context for cifs/<server>, and produce the first
 * token, so that a failure (no KDC, no credentials, ...) shows here, where
 * the caller can still fall back to libsmb2's own NTLMSSP.
 * Credentials: smb2_set_sspi_cred() if set, else user/domain/password if
 * a password is set, else those of the calling thread's logon session.
 */
struct sspi_auth_data *
sspi_negotiate_reply(struct smb2_context *smb2,
                     const char *server,
                     const char *domain,
                     const char *user,
                     const char *password);

/*
 * Feed the server's token (buf/len) into the context, producing the next
 * token to send. With buf NULL, the first token from sspi_negotiate_reply().
 */
int
sspi_session_request(struct smb2_context *smb2,
                     struct sspi_auth_data *auth_data,
                     unsigned char *buf, int len);

unsigned char *
sspi_get_output_token_buffer(struct sspi_auth_data *auth_data);

int
sspi_get_output_token_length(struct sspi_auth_data *auth_data);

/* Copy the session key into smb2->session_key */
int
sspi_session_get_session_key(struct smb2_context *smb2,
                             struct sspi_auth_data *auth_data);

void
sspi_free_auth_data(struct sspi_auth_data *auth_data);

#ifdef __cplusplus
}
#endif

#endif /* !_SSPI_WRAPPER_H_ */
