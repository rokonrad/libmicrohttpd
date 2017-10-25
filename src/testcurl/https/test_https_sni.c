/*
  This file is part of libmicrohttpd
  Copyright (C) 2013, 2016 Christian Grothoff

  libmicrohttpd is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
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
 * @file test_https_sni.c
 * @brief  Testcase for libmicrohttpd HTTPS with SNI operations
 * @author Christian Grothoff
 */
#include "platform.h"
#include "microhttpd.h"
#include <limits.h>
#include <sys/stat.h>
#include <curl/curl.h>
#ifdef GNUTLS_REQUIRE_GCRYPT
#include <gcrypt.h>
#endif /* GNUTLS_REQUIRE_GCRYPT */
#include "tls_test_common.h"
#ifdef ENABLE_GNUTLS
#include <gnutls/gnutls.h>
#if GNUTLS_VERSION_MAJOR >= 3
#include <gnutls/abstract.h>
#endif /* GNUTLS_VERSION_MAJOR >= 3 */
#endif /* ENABLE_GNUTLS */
#ifdef ENABLE_OPENSSL
#include <openssl/ssl.h>
#endif /* ENABLE_OPENSSL */

#ifdef ENABLE_GNUTLS
/**
 * A hostname, server key and certificate.
 */
struct GnuTLS_Hosts
{
  struct GnuTLS_Hosts *next;
  const char *hostname;
  gnutls_pcert_st pcrt;
  gnutls_privkey_t key;
};


/**
 * Linked list of supported TLDs and respective certificates.
 */
static struct GnuTLS_Hosts *gnutls_hosts;

/* Load the certificate and the private key.
 * (This code is largely taken from GnuTLS).
 */
static void
gnutls_load_keys(const char *hostname,
                 const char *CERT_FILE,
                 const char *KEY_FILE)
{
  int ret;
  gnutls_datum_t data;
  struct GnuTLS_Hosts *host;

  host = malloc (sizeof (struct GnuTLS_Hosts));
  if (NULL == host)
    abort ();
  host->hostname = hostname;
  host->next = gnutls_hosts;
  gnutls_hosts = host;

  ret = gnutls_load_file (CERT_FILE, &data);
  if (ret < 0)
    {
      fprintf (stderr,
               "*** Error loading certificate file %s.\n",
               CERT_FILE);
      exit (1);
    }
  ret =
    gnutls_pcert_import_x509_raw (&host->pcrt, &data, GNUTLS_X509_FMT_PEM,
                                  0);
  if (ret < 0)
    {
      fprintf (stderr,
               "*** Error loading certificate file: %s\n",
               gnutls_strerror (ret));
      exit (1);
    }
  gnutls_free (data.data);

  ret = gnutls_load_file (KEY_FILE, &data);
  if (ret < 0)
    {
      fprintf (stderr,
               "*** Error loading key file %s.\n",
               KEY_FILE);
      exit (1);
    }

  gnutls_privkey_init (&host->key);
  ret =
    gnutls_privkey_import_x509_raw (host->key,
                                    &data, GNUTLS_X509_FMT_PEM,
                                    NULL, 0);
  if (ret < 0)
    {
      fprintf (stderr,
               "*** Error loading key file: %s\n",
               gnutls_strerror (ret));
      exit (1);
    }
  gnutls_free (data.data);
}


/**
 * @param session the session we are giving a cert for
 * @param req_ca_dn NULL on server side
 * @param nreqs length of req_ca_dn, and thus 0 on server side
 * @param pk_algos NULL on server side
 * @param pk_algos_length 0 on server side
 * @param pcert list of certificates (to be set)
 * @param pcert_length length of pcert (to be set)
 * @param pkey the private key (to be set)
 */
static int
gnutls_sni_callback (gnutls_session_t session,
                     const gnutls_datum_t* req_ca_dn,
                     int nreqs,
                     const gnutls_pk_algorithm_t* pk_algos,
                     int pk_algos_length,
                     gnutls_pcert_st** pcert,
                     unsigned int *pcert_length,
                     gnutls_privkey_t * pkey)
{
  char name[256];
  size_t name_len;
  struct GnuTLS_Hosts *host;
  unsigned int type;

  if (NULL == gnutls_hosts)
    {
      gnutls_load_keys ("host1", ABS_SRCDIR "/host1.crt", ABS_SRCDIR "/host1.key");
      gnutls_load_keys ("host2", ABS_SRCDIR "/host2.crt", ABS_SRCDIR "/host2.key");
    }

  name_len = sizeof (name);
  if (GNUTLS_E_SUCCESS !=
      gnutls_server_name_get (session,
                              name,
                              &name_len,
                              &type,
                              0 /* index */))
    return -1;
  for (host = gnutls_hosts; NULL != host; host = host->next)
    if (0 == strncmp (name, host->hostname, name_len))
      break;
  if (NULL == host)
    {
      fprintf (stderr,
               "Need certificate for %.*s\n",
               (int) name_len,
               name);
      return -1;
    }
#if 0
  fprintf (stderr,
           "Returning certificate for %.*s\n",
           (int) name_len,
           name);
#endif
  *pkey = host->key;
  *pcert_length = 1;
  *pcert = &host->pcrt;
  return 0;
}
#endif /* ENABLE_GNUTLS */

#ifdef ENABLE_OPENSSL
/**
 * @param ssl the session we are giving a cert for
 * @param arg @c NULL
 */
static int
openssl_sni_callback (SSL *ssl, void *arg)
{
  const char *name;
  char file[512];

  /* Loading files on each connection is not efficient but enough for testing. */
  name = SSL_get_servername (ssl, TLSEXT_NAMETYPE_host_name);
  if (NULL == name)
    {
      fprintf (stderr,
               "OpenSSL: cannot get SNI\n");
      return 0;
    }

  snprintf (file, sizeof (file),  "%s/%s.crt", ABS_SRCDIR, name);
  if (1 != SSL_use_certificate_file (ssl, file, SSL_FILETYPE_PEM))
    return 0;

  snprintf (file, sizeof (file),  "%s/%s.key", ABS_SRCDIR, name);
  if (1 != SSL_use_PrivateKey_file (ssl, file, SSL_FILETYPE_PEM))
    return 0;

  return 1;
}
#endif /* ENABLE_OPENSSL */

/* perform a HTTP GET request via SSL/TLS */
static int
do_get (const char *url, int port)
{
  CURL *c;
  struct CBC cbc;
  CURLcode errornum;
  size_t len;
  struct curl_slist *dns_info;
  char buf[256];

  len = strlen (test_data);
  if (NULL == (cbc.buf = malloc (sizeof (char) * len)))
    {
      fprintf (stderr, MHD_E_MEM);
      return -1;
    }
  cbc.size = len;
  cbc.pos = 0;

  c = curl_easy_init ();
#if DEBUG_HTTPS_TEST
  curl_easy_setopt (c, CURLOPT_VERBOSE, 1);
#endif
  curl_easy_setopt (c, CURLOPT_URL, url);
  curl_easy_setopt (c, CURLOPT_PORT, (long)port);
  curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
  curl_easy_setopt (c, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt (c, CURLOPT_WRITEFUNCTION, &copyBuffer);
  curl_easy_setopt (c, CURLOPT_FILE, &cbc);

  /* perform peer authentication */
  /* TODO merge into send_curl_req */
  curl_easy_setopt (c, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt (c, CURLOPT_SSL_VERIFYHOST, 2);
  sprintf(buf, "host1:%d:127.0.0.1", port);
  dns_info = curl_slist_append (NULL, buf);
  sprintf(buf, "host2:%d:127.0.0.1", port);
  dns_info = curl_slist_append (dns_info, buf);
  sprintf(buf, "host3:%d:127.0.0.1", port);
  dns_info = curl_slist_append (dns_info, buf);
  curl_easy_setopt (c, CURLOPT_RESOLVE, dns_info);
  curl_easy_setopt (c, CURLOPT_FAILONERROR, 1);

  /* NOTE: use of CONNECTTIMEOUT without also
     setting NOSIGNAL results in really weird
     crashes on my system! */
  curl_easy_setopt (c, CURLOPT_NOSIGNAL, 1);
  if (CURLE_OK != (errornum = curl_easy_perform (c)))
    {
      fprintf (stderr, "curl_easy_perform failed: `%s'\n",
               curl_easy_strerror (errornum));
      curl_easy_cleanup (c);
      free (cbc.buf);
      curl_slist_free_all (dns_info);
      return errornum;
    }

  curl_easy_cleanup (c);
  curl_slist_free_all (dns_info);
  if (memcmp (cbc.buf, test_data, len) != 0)
    {
      fprintf (stderr, "Error: local file & received file differ.\n");
      free (cbc.buf);
      return -1;
    }

  free (cbc.buf);
  return 0;
}


int
main (int argc, char *const *argv)
{
  unsigned int error_count = 0;
  int tls_engine_index;
  enum MHD_TLS_EngineType tls_engine_type;
  const char *tls_engine_name;
  struct MHD_Daemon *d;
  int port;
  const struct
  {
    enum MHD_TLS_EngineType type;
    int (*cb) ();
  } cb_by_engine[MHD_TLS_ENGINE_TYPE_MAX] =
  {
#ifdef ENABLE_GNUTLS
    { MHD_TLS_ENGINE_TYPE_GNUTLS, (int (*) ()) gnutls_sni_callback },
#endif
#ifdef ENABLE_OPENSSL
    { MHD_TLS_ENGINE_TYPE_OPENSSL, (int (*) ()) openssl_sni_callback },
#endif
  };

  if (MHD_NO != MHD_is_feature_supported (MHD_FEATURE_AUTODETECT_BIND_PORT))
    port = 0;
  else
    port = 3060;

#ifdef GNUTLS_REQUIRE_GCRYPT
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
#ifdef GCRYCTL_INITIALIZATION_FINISHED
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif
#endif /* GNUTLS_REQUIRE_GCRYPT */
  if (0 != curl_global_init (CURL_GLOBAL_ALL))
    {
      fprintf (stderr, "Error: %s\n", strerror (errno));
      return 99;
    }
  if (NULL == curl_version_info (CURLVERSION_NOW)->ssl_version)
    {
      fprintf (stderr, "Curl does not support SSL.  Cannot run the test.\n");
      curl_global_cleanup ();
      return 77;
    }

  tls_engine_index = 0;
  while (0 <= (tls_engine_index = iterate_over_available_tls_engines (tls_engine_index,
                                                                      &tls_engine_type,
                                                                      &tls_engine_name)))
    {
      int i;

      if (MHD_NO == MHD_TLS_is_feature_supported (tls_engine_type,
                                                  MHD_TLS_FEATURE_CERT_CALLBACK))
        {
          fprintf (stderr,
                   "TLS engine %s does not support feature MHD_TLS_FEATURE_CERT_CALLBACK\n",
                   tls_engine_name);
          continue;
        }

      for (i = 0; i < MHD_TLS_ENGINE_TYPE_MAX; ++i)
        if (cb_by_engine[i].type == tls_engine_type)
          break;
      if (i >= MHD_TLS_ENGINE_TYPE_MAX)
        {
          fprintf (stderr,
                   "No certificate callback for TLS engine %s\n",
                   tls_engine_name);
          error_count++;
          continue;
        }

      d = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_TLS | MHD_USE_ERROR_LOG,
                            port,
                            NULL, NULL,
                            &http_ahc, NULL,
                            MHD_OPTION_TLS_ENGINE_TYPE, tls_engine_type,
                            MHD_OPTION_TLS_CERT_CALLBACK, cb_by_engine[i].cb,
                            MHD_OPTION_END);
      if (d == NULL)
        {
          fprintf (stderr, MHD_E_SERVER_INIT);
          return -1;
        }
      if (0 == port)
        {
          const union MHD_DaemonInfo *dinfo;
          dinfo = MHD_get_daemon_info (d, MHD_DAEMON_INFO_BIND_PORT);
          if (NULL == dinfo || 0 == dinfo->port)
            { MHD_stop_daemon (d); return -1; }
          port = (int)dinfo->port;
        }
      if (0 != do_get ("https://host1/", port))
        error_count++;
      if (0 != do_get ("https://host2:4233/", port))
        error_count++;
      if (0 == do_get ("https://host3:4233/", port))
        error_count++;

      MHD_stop_daemon (d);
    }
  curl_global_cleanup ();
  if (error_count != 0)
    fprintf (stderr, "Failed test: %s, error: %u.\n", argv[0], error_count);
  return (0 != error_count) ? 1 : 0;
}
