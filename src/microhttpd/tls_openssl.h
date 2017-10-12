/*
  This file is part of libmicrohttpd
  Copyright (C) 2007-2017 Daniel Pittman and Christian Grothoff

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

/**
 * @file microhttpd/tls_openssl.h
 * @brief OpenSSL-based TLS engine
 */

#ifndef TLS_OPENSSL_H
#define TLS_OPENSSL_H

#include <openssl/ssl.h>
#include <openssl/x509.h>

struct MHD_OpenSSL_Context
{
  /**
   * @brief OpenSSL context.
   */
  SSL_CTX *context;
};

struct MHD_OpenSSL_Session
{
  /**
   * @brief OpenSSL session.
   */
  SSL *session;
};

extern const struct MHD_TLS_Engine tls_engine_openssl;

void
MHD_TLS_openssl_init (void);

void
MHD_TLS_openssl_deinit (void);

#endif
