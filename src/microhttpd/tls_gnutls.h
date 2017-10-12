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
 * @file microhttpd/tls_gnutls.h
 * @brief GnuTLS-based TLS engine
 */

#ifndef TLS_GNUTLS_H
#define TLS_GNUTLS_H

#include <gnutls/gnutls.h>
#if GNUTLS_VERSION_MAJOR >= 3
#include <gnutls/abstract.h>
#endif

struct MHD_GnuTLS_Context
{
  /**
   * @brief Desired cipher algorithms.
   */
  gnutls_priority_t priority_cache;

  /**
   * @brief Server x509 credentials.
   */
  gnutls_certificate_credentials_t x509_cred;

  /**
   * @brief Client certificate mode.
   */
  enum MHD_TLS_ClientCertificateMode client_cert_mode;
};

struct MHD_GnuTLS_Session
{
  /**
   * @brief GnuTLS session.
   */
  gnutls_session_t session;
};

extern const struct MHD_TLS_Engine tls_engine_gnutls;

void
MHD_TLS_gnutls_init (void);

void
MHD_TLS_gnutls_deinit (void);

#endif
