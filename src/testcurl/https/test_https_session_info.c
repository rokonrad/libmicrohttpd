/*
 This file is part of libmicrohttpd
 Copyright (C) 2007, 2016 Christian Grothoff

 libmicrohttpd is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published
 by the Free Software Foundation; either version 2, or (at your
 option) any later version.

 libmicrohttpd is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with libmicrohttpd; see the file COPYING.  If not, write to the
 Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 Boston, MA 02110-1301, USA.
 */

/**
 * @file mhds_session_info_test.c
 * @brief  Testcase for libmicrohttpd HTTPS connection querying operations
 * @author Sagie Amir
 */

#include "platform.h"
#include "microhttpd.h"
#include <curl/curl.h>
#ifdef GNUTLS_REQUIRE_GCRYPT
#include <gcrypt.h>
#endif /* GNUTLS_REQUIRE_GCRYPT */
#include "tls_test_common.h"

extern int curl_check_version (const char *req_version, ...);
extern const char srv_key_pem[];
extern const char srv_self_signed_cert_pem[];

struct MHD_Daemon *d;

static const struct
{
  enum MHD_TLS_EngineType type;
  const char *priorities;
} priorities_by_engine[MHD_TLS_ENGINE_TYPE_MAX] =
{
  { MHD_TLS_ENGINE_TYPE_GNUTLS, "NORMAL:+ARCFOUR-128" },
  { MHD_TLS_ENGINE_TYPE_OPENSSL, "DEFAULT:RC4" }
};

/*
 * HTTP access handler call back
 * used to query negotiated security parameters
 */
static int
query_session_ahc (void *cls, struct MHD_Connection *connection,
                   const char *url, const char *method,
                   const char *upload_data, const char *version,
                   size_t *upload_data_size, void **ptr)
{
  struct MHD_Response *response;
  int ret;

  if (NULL == *ptr)
    {
      *ptr = &query_session_ahc;
      return MHD_YES;
    }

  if (MHD_TLS_PROTOCOL_VERSION_TLS_V1_1 !=
      (ret = MHD_get_connection_info
       (connection,
	MHD_CONNECTION_INFO_TLS_PROTOCOL_VERSION)->tls_protocol_version))
    {
      if (MHD_TLS_PROTOCOL_VERSION_TLS_V1_2 == ret)
      {
        /* as usual, TLS implementations sometimes don't
           quite do what was asked, just mildly complain... */
        fprintf (stderr,
                 "Warning: requested TLS 1.1, got TLS 1.2\n");
      }
      else
      {
        /* really different version... */
        fprintf (stderr,
                 "Error: requested protocol mismatch (wanted %d, got %d)\n",
                 MHD_TLS_PROTOCOL_VERSION_TLS_V1_1,
                 ret);
        return -1;
      }
    }

  response = MHD_create_response_from_buffer (strlen (EMPTY_PAGE),
					      (void *) EMPTY_PAGE,
					      MHD_RESPMEM_PERSISTENT);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  return ret;
}


/**
 * negotiate a secure connection with server & query negotiated security parameters
 */
#if LIBCURL_VERSION_NUM >= 0x072200
static int
test_query_session (enum MHD_TLS_EngineType tls_engine_type,
                    const char *tls_engine_name)
{
  CURL *c;
  struct CBC cbc;
  CURLcode errornum;
  char url[256];
  int port;
  const char *priorities;
  int i;

  if (MHD_NO != MHD_is_feature_supported (MHD_FEATURE_AUTODETECT_BIND_PORT))
    port = 0;
  else
    port = 3060;

  for (i = 0; i < MHD_TLS_ENGINE_TYPE_MAX; ++i)
    if (priorities_by_engine[i].type == tls_engine_type)
      break;
  if (i >= MHD_TLS_ENGINE_TYPE_MAX)
    {
      fprintf (stderr,
               "No definition of HTTPS priorities for TLS engine %s\n",
               tls_engine_name);
      return -1;
    }
  priorities = priorities_by_engine[i].priorities;

  if (NULL == (cbc.buf = malloc (sizeof (char) * 255)))
    return 16;
  cbc.size = 255;
  cbc.pos = 0;

  /* setup test */
  d = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_TLS |
                        MHD_USE_ERROR_LOG, port,
                        NULL, NULL, &query_session_ahc, NULL,
                        MHD_OPTION_TLS_ENGINE_TYPE, tls_engine_type,
                        MHD_OPTION_HTTPS_PRIORITIES, priorities,
                        MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
                        MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
                        MHD_OPTION_END);

  if (d == NULL)
    {
      free (cbc.buf);
      return 2;
    }
  if (0 == port)
    {
      const union MHD_DaemonInfo *dinfo;
      dinfo = MHD_get_daemon_info (d, MHD_DAEMON_INFO_BIND_PORT);
      if (NULL == dinfo || 0 == dinfo->port)
        { MHD_stop_daemon (d); return 32; }
      port = (int)dinfo->port;
    }

  const char *aes256_sha = "AES256-SHA";
  if (curl_uses_nss_ssl() == 0)
    {
      aes256_sha = "rsa_aes_256_sha";
    }

  gen_test_file_url (url,
                     sizeof (url),
                     port);
  c = curl_easy_init ();
#if DEBUG_HTTPS_TEST
  curl_easy_setopt (c, CURLOPT_VERBOSE, 1);
#endif
  curl_easy_setopt (c, CURLOPT_URL, url);
  curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  curl_easy_setopt (c, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt (c, CURLOPT_WRITEFUNCTION, &copyBuffer);
  curl_easy_setopt (c, CURLOPT_FILE, &cbc);
  /* TLS options */
  curl_easy_setopt (c, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_1);
  curl_easy_setopt (c, CURLOPT_SSL_CIPHER_LIST, aes256_sha);
  /* currently skip any peer authentication */
  curl_easy_setopt (c, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt (c, CURLOPT_SSL_VERIFYHOST, 0);
  curl_easy_setopt (c, CURLOPT_FAILONERROR, 1);

  // NOTE: use of CONNECTTIMEOUT without also
  //   setting NOSIGNAL results in really weird
  //   crashes on my system!
  curl_easy_setopt (c, CURLOPT_NOSIGNAL, 1);
  if (CURLE_OK != (errornum = curl_easy_perform (c)))
    {
      fprintf (stderr, "curl_easy_perform failed: `%s'\n",
               curl_easy_strerror (errornum));

      MHD_stop_daemon (d);
      curl_easy_cleanup (c);
      free (cbc.buf);
      return -1;
    }

  curl_easy_cleanup (c);
  MHD_stop_daemon (d);
  free (cbc.buf);
  return 0;
}
#endif

int
main (int argc, char *const *argv)
{
#if LIBCURL_VERSION_NUM >= 0x072200
  unsigned int errorCount = 0;
  int tls_engine_index;
  enum MHD_TLS_EngineType tls_engine_type;
  const char *tls_engine_name;
  const char *ssl_version;

#ifdef GNUTLS_REQUIRE_GCRYPT
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
#ifdef GCRYCTL_INITIALIZATION_FINISHED
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif
#endif /* GNUTLS_REQUIRE_GCRYPT */
  if (0 != curl_global_init (CURL_GLOBAL_ALL))
    {
      fprintf (stderr, "Error (code: %u)\n", errorCount);
      return 99;
    }

  ssl_version = curl_version_info (CURLVERSION_NOW)->ssl_version;
  if (NULL == ssl_version)
  {
    fprintf (stderr, "Curl does not support SSL.  Cannot run the test.\n");
    curl_global_cleanup ();
    return 77;
  }
  if (0 != strncmp (ssl_version, "GnuTLS", 6))
  {
    fprintf (stderr, "This test can be run only with libcurl-gnutls.\n");
    curl_global_cleanup ();
    return 77;
  }
  tls_engine_index = 0;
  while (0 <= (tls_engine_index = iterate_over_available_tls_engines (tls_engine_index,
                                                                      &tls_engine_type,
                                                                      &tls_engine_name)))
    {
      errorCount += test_query_session (tls_engine_type, tls_engine_name);
    }
  print_test_result (errorCount, argv[0]);
  curl_global_cleanup ();
  return errorCount != 0 ? 1 : 0;
#else  /* LIBCURL_VERSION_NUM < 0x072200 */
  return 77;
#endif /* LIBCURL_VERSION_NUM < 0x072200 */
}
