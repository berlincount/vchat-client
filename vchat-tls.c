/*
 * vchat-client - beta version
 * vchat-tls.c - handling of SSL connection and X509 certificate
 * verification
 *
 * Copyright (C) 2007 Thorsten Schroeder <ths@berlin.ccc.de>
 *
 * This program is free software. It can be redistributed and/or modified,
 * provided that this copyright notice is kept intact. This program is
 * distributed in the hope that it will be useful, but without any warranty;
 * without even the implied warranty of merchantability or fitness for a
 * particular purpose. In no event shall the copyright holder be liable for
 * any direct, indirect, incidental or special damages arising in any way out
 * of the use of this software.
 *
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <readline/readline.h>

#include "vchat-tls.h"
#include "vchat.h"

const char *vchat_tls_version =
    "vchat-tls.c      $Id$";

/* Helpers to work with vc_x509store_t used by all tls libs */
void vc_cleanup_x509store(vc_x509store_t *store) {
  free(store->cafile);
  free(store->capath);
  free(store->crlfile);
  free(store->certfile);
  free(store->keyfile);
  memset(store, 0, sizeof(vc_x509store_t));
}

void vc_x509store_setflags(vc_x509store_t *store, int flags) {
  store->flags |= flags;
}
void vc_x509store_clearflags(vc_x509store_t *store, int flags) {
  store->flags &= ~flags;
}
void vc_x509store_set_pkeycb(vc_x509store_t *store, vc_askpass_cb_t callback) {
  store->askpass_callback = callback;
}

void vc_x509store_setcafile(vc_x509store_t *store, char *file) {
  free(store->cafile);
  store->cafile = (file ? strdup(file) : 0);
  store->flags |= VC_X509S_USE_CAFILE;
}

void vc_x509store_setcapath(vc_x509store_t *store, char *path) {
  free(store->capath);
  store->capath = (path ? strdup(path) : 0);
}

void vc_x509store_setcrlfile(vc_x509store_t *store, char *file) {
  free(store->crlfile);
  store->crlfile = (file ? strdup(file) : 0);
}

void vc_x509store_setkeyfile(vc_x509store_t *store, char *file) {
  free(store->keyfile);
  store->keyfile = (file ? strdup(file) : 0);
}

void vc_x509store_setcertfile(vc_x509store_t *store, char *file) {
  free(store->certfile);
  store->certfile = (file ? strdup(file) : 0);
  store->flags |= VC_X509S_USE_CERTIFICATE;
}

static int verify_or_store_fingerprint(const char *fingerprint) {
  char *fingerprint_file_path = tilde_expand(getstroption(CF_FINGERPRINT));
  if (!fingerprint_file_path) {
    writecf(FS_ERR, "Error: The CF_FINGERPRINT path is not set but "
                    "CF_PINFINGER was requested.");
    return -1;
  }

  FILE *fingerprint_file = fopen(fingerprint_file_path, "r");
  if (fingerprint_file) {
    /* Read fingerprint from file */
    char old_fingerprint[128];
    char *r = fgets(old_fingerprint, sizeof(old_fingerprint), fingerprint_file);
    fclose(fingerprint_file);

    if (r) {
      /* chomp */
      char *nl = strchr(r, '\n');
      if (nl)
        *nl = 0;

      /* verify fingerprint matches stored version */
      if (!strcmp(fingerprint, old_fingerprint)) {
        writecf(FS_SERV, "[FINGERPRINT MATCH   ]");
        goto cleanup_happy;
      }
    }

    snprintf(tmpstr, TMPSTRSIZE,
             "Error: Found pinned fingerprint (in %s) %s but expected %s",
             r ? old_fingerprint : "<FILE READ ERROR>",
             getstroption(CF_FINGERPRINT), fingerprint);
    writecf(FS_ERR, tmpstr);
    writecf(FS_ERR, "Error: Fingerprint mismatch! Server cert updated?");
    free(fingerprint_file_path);
    return 1;
  } else
    writecf(FS_ERR,
            "Warning: No pinned fingerprint found, writing the current one.");

  fingerprint_file = fopen(fingerprint_file_path, "w");
  if (!fingerprint_file) {
    snprintf(tmpstr, TMPSTRSIZE, "Warning: Can't write fingerprint file, %s.",
             strerror(errno));
    writecf(FS_ERR, tmpstr);
  } else {
    fputs(fingerprint, fingerprint_file);
    fclose(fingerprint_file);
    writecf(FS_SERV, "[FINGERPRINT STORED  ]");
  }
cleanup_happy:
  free(fingerprint_file_path);
  return 0;
}

#ifdef TLS_LIB_OPENSSL

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

char *vc_openssl_version() {
  snprintf(tmpstr, sizeof(tmpstr), "OpenSSL %s with %s",
           SSLeay_version(SSLEAY_VERSION), SSLeay_version(SSLEAY_CFLAGS));
  return strdup(tmpstr);
}

void vc_openssl_init_x509store(vc_x509store_t *store) {
  static int sslinit;
  if (!sslinit++) {
    SSL_library_init();
    SSL_load_error_strings();
  }
  memset(store, 0, sizeof(vc_x509store_t));

  /* We want to make verifying the peer the default */
  store->flags |= VC_X509S_SSL_VERIFY_PEER;
}

/* connection BIO for openssl */
static BIO *server_conn = NULL;

static SSL_CTX *vc_create_sslctx(vc_x509store_t *vc_store);
static int vc_verify_callback(int, X509_STORE_CTX *);
static X509_STORE *vc_x509store_create(vc_x509store_t *);

static SSL_CTX *vc_create_sslctx(vc_x509store_t *vc_store) {
  int flags = 0;

  /* Explicitly use TLSv1 (or maybe later) */
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  X509_STORE *store = vc_x509store_create(vc_store);

  if (!ctx || !store) {
    snprintf(tmpstr, sizeof(tmpstr), "CREATE CTX: %s",
             ERR_error_string(ERR_get_error(), NULL));
    writecf(FS_ERR, tmpstr);
    if (store)
      X509_STORE_free(store);
    if (ctx)
      SSL_CTX_free(ctx);
    return NULL;
  }

  SSL_CTX_set_cert_store(ctx, store);

  /* Disable some insecure protocols explicitly */
  SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
  if (getstroption(CF_CIPHERSUITE))
    SSL_CTX_set_cipher_list(ctx, getstroption(CF_CIPHERSUITE));
  else
    SSL_CTX_set_cipher_list(ctx,
                            "ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA");

  SSL_CTX_set_verify_depth(ctx, getintoption(CF_VERIFYSSL));

  if (!(vc_store->flags & VC_X509S_SSL_VERIFY_MASK)) {
    writecf(FS_DBG, tmpstr);
    flags = SSL_VERIFY_NONE;
  } else {
    if (vc_store->flags & VC_X509S_SSL_VERIFY_PEER)
      flags |= SSL_VERIFY_PEER;
    if (vc_store->flags & VC_X509S_SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
      flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    if (vc_store->flags & VC_X509S_SSL_VERIFY_CLIENT_ONCE)
      flags |= SSL_VERIFY_CLIENT_ONCE;
  }

  SSL_CTX_set_verify(ctx, flags, vc_verify_callback);

  if (vc_store->flags & VC_X509S_USE_CERTIFICATE) {
    int r = 0;
    if (vc_store->certfile)
      SSL_CTX_use_certificate_chain_file(ctx, vc_store->certfile);

    SSL_CTX_set_default_passwd_cb(ctx, vc_store->askpass_callback);

    if (vc_store->keyfile)
      r = SSL_CTX_use_PrivateKey_file(ctx, vc_store->keyfile, SSL_FILETYPE_PEM);

    if (r != 1 || !SSL_CTX_check_private_key(ctx)) {
      snprintf(tmpstr, sizeof(tmpstr), "CREATE CTX: Load private key failed");
      writecf(FS_ERR, tmpstr);
      SSL_CTX_free(ctx);
      return NULL;
    }
  }

  SSL_CTX_set_app_data(ctx, vc_store);
  return (ctx);
}

int vc_openssl_connect(int serverfd, vc_x509store_t *vc_store) {
  SSL_CTX *ctx = vc_create_sslctx(vc_store);
  X509 *peercert = NULL;
  BIO *ssl_conn = NULL;
  const SSL *sslp = NULL;
  const SSL_CIPHER *cipher = NULL;

  server_conn = BIO_new_socket(serverfd, 1);

  /* To display and check server fingerprint */
  char fingerprint[EVP_MAX_MD_SIZE * 4];
  unsigned char fingerprint_bin[EVP_MAX_MD_SIZE];
  unsigned int fingerprint_len;

  char *fp = fingerprint;

  long j;

  writecf(FS_SERV, "[SOCKET CONNECTED    ]");
  writecf(FS_SERV, "[UPGRADING TO TLS    ]");
  writecf(FS_SERV, "[TLS ENGINE OPENSSL  ]");

  if (!ctx)
    goto all_errors;

  ssl_conn = BIO_new_ssl(ctx, 1);
  SSL_CTX_free(ctx);

  if (!ssl_conn)
    goto ssl_error;

  BIO_push(ssl_conn, server_conn);
  server_conn = ssl_conn;
  fflush(stdout);

  if (BIO_do_handshake(server_conn) <= 0)
    goto ssl_error;

  /* Show information about cipher used */
  /* Get cipher object */
  BIO_get_ssl(ssl_conn, &sslp);
  if (!sslp)
    goto ssl_error;

  cipher = SSL_get_current_cipher(sslp);
  if (cipher) {
    char cipher_desc[TMPSTRSIZE];
    snprintf(tmpstr, TMPSTRSIZE, "[SSL CIPHER          ] %s",
             SSL_CIPHER_description(cipher, cipher_desc, TMPSTRSIZE));
    writecf(FS_SERV, tmpstr);
  } else {
    snprintf(tmpstr, TMPSTRSIZE,
             "[SSL ERROR           ] Cipher not known / SSL object can't be "
             "queried!");
    writecf(FS_ERR, tmpstr);
  }

  /* Accept being connected, _if_ verification passed */
  peercert = SSL_get_peer_certificate(sslp);
  if (!peercert)
    goto ssl_error;

  /* show basic information about peer cert */
  snprintf(tmpstr, TMPSTRSIZE, "[SSL SUBJECT         ] %s",
           X509_NAME_oneline(X509_get_subject_name(peercert), 0, 0));
  writecf(FS_SERV, tmpstr);
  snprintf(tmpstr, TMPSTRSIZE, "[SSL ISSUER          ] %s",
           X509_NAME_oneline(X509_get_issuer_name(peercert), 0, 0));
  writecf(FS_SERV, tmpstr);

  /* calculate fingerprint */
  if (!X509_digest(peercert, EVP_sha1(), fingerprint_bin, &fingerprint_len))
    goto ssl_error;

  assert((fingerprint_len > 1) && (fingerprint_len <= EVP_MAX_MD_SIZE));
  for (j = 0; j < (int)fingerprint_len; j++)
    fp += sprintf(fp, "%02X:", fingerprint_bin[j]);
  assert(fp > fingerprint);
  fp[-1] = 0;
  snprintf(tmpstr, TMPSTRSIZE, "[SSL FINGERPRINT     ] %s (from server)",
           fingerprint);
  writecf(FS_SERV, tmpstr);

  /* we don't need the peercert anymore */
  X509_free(peercert);

  if (getintoption(CF_PINFINGER) && verify_or_store_fingerprint(fingerprint))
    return 1;

  /* If verify of x509 chain was requested, do the check here */
  if (X509_V_OK == SSL_get_verify_result(sslp))
    return 0;

  if (getintoption(CF_IGNSSL)) {
    writecf(FS_ERR, "[SSL VERIFY ERROR    ] FAILURE IGNORED!!!");
    return 0;
  }

ssl_error:
  snprintf(tmpstr, TMPSTRSIZE, "[SSL CONNECT ERROR   ] %s",
           ERR_error_string(ERR_get_error(), NULL));
  writecf(FS_ERR, tmpstr);
all_errors:
  BIO_free_all(server_conn);
  server_conn = NULL;
  return 1;
}

#define VC_STORE_ERR_EXIT(s)                                                   \
  do {                                                                         \
    fprintf(stderr, "[E] SSL_STORE: %s\n",                                     \
            ERR_error_string(ERR_get_error(), NULL));                          \
    if (s)                                                                     \
      X509_STORE_free(s);                                                      \
    return (0);                                                                \
  } while (0)

X509_STORE *vc_x509store_create(vc_x509store_t *vc_store) {
  X509_STORE *store = NULL;
  X509_LOOKUP *lookup = NULL;

  store = X509_STORE_new();
  if (!store) {
    fprintf(stderr, "[E] SSL_STORE: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  X509_STORE_set_verify_cb_func(store, vc_verify_callback);

  if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())))
    VC_STORE_ERR_EXIT(store);

  if (!vc_store->cafile) {
    if (!(vc_store->flags & VC_X509S_USE_CAFILE))
      X509_LOOKUP_load_file(lookup, 0, X509_FILETYPE_DEFAULT);
  } else if (!X509_LOOKUP_load_file(lookup, vc_store->cafile,
                                    X509_FILETYPE_PEM))
    VC_STORE_ERR_EXIT(store);

  if (vc_store->crlfile) {
    if (!X509_load_crl_file(lookup, vc_store->crlfile, X509_FILETYPE_PEM))
      VC_STORE_ERR_EXIT(store);

    X509_STORE_set_flags(store,
                         X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
  }

  if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir())))
    VC_STORE_ERR_EXIT(store);

  if (!vc_store->capath) {
    if (!(vc_store->flags & VC_X509S_USE_CAPATH))
      X509_LOOKUP_add_dir(lookup, 0, X509_FILETYPE_DEFAULT);
  } else if (!X509_LOOKUP_add_dir(lookup, vc_store->capath, X509_FILETYPE_PEM))
    VC_STORE_ERR_EXIT(store);

  return (store);
}

int vc_verify_callback(int ok, X509_STORE_CTX *store) {
  if (!ok) {
    snprintf(tmpstr, TMPSTRSIZE, "[SSL VERIFY ERROR    ] %s",
             X509_verify_cert_error_string(X509_STORE_CTX_get_error(store)));
    writecf(FS_ERR, tmpstr);
  }
  return (ok | getintoption(CF_IGNSSL));
}

ssize_t vc_openssl_sendmessage(const void *buf, size_t size) {
  return BIO_write(server_conn, buf, size);
}

ssize_t vc_openssl_receivemessage(void *buf, size_t size) {
  ssize_t received = (ssize_t)BIO_read(server_conn, buf, size);
  if (received != 0)
    return received;
  if (BIO_should_retry(server_conn))
    return -2;
  return 0;
}

void vc_openssl_cleanup() {
  BIO_free_all(server_conn);
  server_conn = NULL;
}
#endif

#ifdef TLS_LIB_MBEDTLS

#include "mbedtls/error.h"
#include "mbedtls/version.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>

#include <sys/socket.h>

const char *DRBG_PERS = "mbed TLS vchat client";
#define MAX_SUITES 512
typedef struct {
  mbedtls_entropy_context _entropy;
  mbedtls_ctr_drbg_context _ctr_drbg;
  mbedtls_x509_crt _cacert;
  mbedtls_x509_crt _cert;
  mbedtls_pk_context _key;
  mbedtls_ssl_context _ssl;
  mbedtls_ssl_config _conf;
  int ciphersuits[MAX_SUITES];
} mbedstate;
static mbedstate _mbedtls_state;

char *vc_mbedtls_version() {
  snprintf(tmpstr, sizeof(tmpstr), "%s", MBEDTLS_VERSION_STRING_FULL);
  return strdup(tmpstr);
}

static int static_tcp_recv(void *ctx, unsigned char *buf, size_t len) {
  return recv((int)(intptr_t)ctx, buf, len, 0);
}
static int static_tcp_send(void *ctx, const unsigned char *buf, size_t len) {
  return send((int)(intptr_t)ctx, buf, len, 0);
}
static int map_openssl_suite(char *openssl_name);
void vc_mbedtls_init_x509store(vc_x509store_t *store) {
  mbedtls_entropy_init(&_mbedtls_state._entropy);
  mbedtls_ctr_drbg_init(&_mbedtls_state._ctr_drbg);

  mbedtls_ctr_drbg_seed(&_mbedtls_state._ctr_drbg, mbedtls_entropy_func,
                        &_mbedtls_state._entropy,
                        (const unsigned char *)DRBG_PERS, sizeof(DRBG_PERS));
  memset(store, 0, sizeof(vc_x509store_t));

  /* We want to make verifying the peer the default */
  store->flags |= VC_X509S_SSL_VERIFY_PEER;
}

static void vc_tls_report_error(int error, char *message) {
  size_t used = snprintf(tmpstr, sizeof(tmpstr), "Error: %s", message);
  mbedtls_strerror(error, tmpstr + used, sizeof(tmpstr) - used);
  writecf(FS_ERR, tmpstr);
}

int vc_mbedtls_connect(const char *servername, int serverfd, vc_x509store_t *vc_store) {
  /* Some aliases for shorter references */
  mbedstate *s = &_mbedtls_state;
  mbedtls_ssl_config *conf = &_mbedtls_state._conf;
  mbedtls_ssl_context *ssl = &_mbedtls_state._ssl;
  int ret, suitecount = 0;
  char fingerprint[128], *token;
  uint8_t digest[20];

  mbedtls_x509_crt_init(&s->_cacert);
  mbedtls_x509_crt_init(&s->_cert);
  mbedtls_pk_init(&s->_key);
  mbedtls_ssl_init(ssl);
  mbedtls_ssl_config_init(conf);

  writecf(FS_SERV, "[SOCKET CONNECTED    ]");
  writecf(FS_SERV, "[UPGRADING TO TLS    ]");
  writecf(FS_SERV, "[TLS ENGINE MBEDTLS  ]");

  if ((ret = mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    vc_tls_report_error(ret,
                        "Can not initialise tls parameters, mbedtls reports: ");
    return -1;
  }

  /* TODO: Always verify peer */
  mbedtls_ssl_conf_authmode(conf, getintoption(CF_IGNSSL)
                                      ? MBEDTLS_SSL_VERIFY_OPTIONAL
                                      : MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, &s->_ctr_drbg);

  char *ciphers = getstroption(CF_CIPHERSUITE);
  if (!ciphers)
    ciphers = "TLS1-3-AES-256-GCM-SHA384:TLS1-3-AES-128-GCM-SHA256:TLS1-3-AES-128-CCM-SHA256:TLS1-3-AES-128-CCM-8-SHA256:TLS1-3-CHACHA20-POLY1305-SHA256:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA";
  ciphers = strdup(ciphers);
  for (token = strtok(ciphers, ":"); token && suitecount < MAX_SUITES - 1;
       token = strtok(NULL, ":")) {
    int suite = mbedtls_ssl_get_ciphersuite_id(token);
    if (!suite)
      suite = map_openssl_suite(token);
    if (suite)
      s->ciphersuits[suitecount++] = suite;
  }
  s->ciphersuits[suitecount++] = 0;
  free(ciphers);

  mbedtls_ssl_conf_ciphersuites(conf, s->ciphersuits);

  if (vc_store->cafile) {
    if ((ret = mbedtls_x509_crt_parse_file(&s->_cacert, vc_store->cafile)) !=
        0) {
      vc_tls_report_error(ret, "Can not load CA cert, mbedtls reports: ");
      return -1;
    }
    mbedtls_ssl_conf_ca_chain(conf, &s->_cacert, NULL);
    writecf(FS_SERV, "[CA CERT LOADED      ]");
  }

  if (vc_store->flags & VC_X509S_USE_CERTIFICATE) {
    char *password = NULL;
    char password_buf[1024];

    if ((ret = mbedtls_x509_crt_parse_file(&s->_cert, vc_store->certfile)) !=
        0) {
      vc_tls_report_error(ret, "Can not load client cert, mbedtls reports: ");
      return -1;
    }
    writecf(FS_SERV, "[CLIENT CERT LOADED  ]");

    while (1) {
      if ((ret = mbedtls_pk_parse_keyfile(&s->_key, vc_store->keyfile, password
#if MBEDTLS_VERSION_MAJOR >= 3
                                          ,
                                          mbedtls_ctr_drbg_random, &s->_ctr_drbg
#endif
                                          )) == 0)
        break;
      if (ret != MBEDTLS_ERR_PK_PASSWORD_REQUIRED &&
          ret != MBEDTLS_ERR_PK_PASSWORD_MISMATCH) {
        vc_tls_report_error(ret, "Can not load client key, mbedtls reports: ");
        return -1;
      }
      if (ret == MBEDTLS_ERR_PK_PASSWORD_MISMATCH)
        vc_tls_report_error(ret, "Wrong passphrase, mbedtls reports: ");
      vc_store->askpass_callback(password_buf, sizeof(password_buf), 0, NULL);
      password = password_buf;
    }
#if defined(__linux__) || defined(__OpenBSD__)
    explicit_bzero(password_buf, sizeof(password_buf));
#else
    memset_s(password_buf, sizeof(password_buf), 0, sizeof(password_buf));
#endif
    writecf(FS_SERV, "[CLIENT KEY LOADED   ]");

#if MBEDTLS_VERSION_MAJOR == 3 && MBEDTLS_VERSION_MINOR == 0
    mbedtls_pk_context *pubkey = &(s->_cert.MBEDTLS_PRIVATE(pk));
#else
    mbedtls_pk_context *pubkey = &(s->_cert.pk);
#endif

    if ((ret = mbedtls_pk_check_pair(pubkey, &s->_key
#if MBEDTLS_VERSION_MAJOR >= 3
                                     ,
                                     mbedtls_ctr_drbg_random, &s->_ctr_drbg
#endif
                                     )) != 0) {
      vc_tls_report_error(ret, "Cert and key mismatch, mbedtls reports: ");
      return 1;
    }

    if ((ret = mbedtls_ssl_conf_own_cert(conf, &s->_cert, &s->_key)) != 0) {
      vc_tls_report_error(
          ret, "Setting key and cert to tls session fails, mbedtls reports: ");
      return -1;
    }
  }

  /* Config constructed, pass to ssl */
  /* Init ssl and config structs and configure ssl ctx */
  if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0) {
    vc_tls_report_error(
        ret, "Can not configure parameters on tls context, mbedtls reports: ");
    return -1;
  }
  mbedtls_ssl_set_hostname(ssl, strdup(servername));

  mbedtls_ssl_set_bio(ssl, (void *)(intptr_t)serverfd, static_tcp_send,
                      static_tcp_recv, NULL);

  while ((ret = mbedtls_ssl_handshake(ssl)) != 0)
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      vc_tls_report_error(ret, "TLS handshake failed, mbedtls reports: ");
      return -1;
    }

  writecf(FS_SERV, "[TLS HANDSHAKE DONE  ]");
  snprintf(tmpstr, TMPSTRSIZE, "[TLS CIPHER SUITE    ] %s",
           mbedtls_ssl_get_ciphersuite(ssl));
  writecf(FS_SERV, tmpstr);

  const mbedtls_x509_crt *peer_cert = mbedtls_ssl_get_peer_cert(ssl);
  mbedtls_x509_crt_info(tmpstr, sizeof(tmpstr), "[TLS PEER INFO       ] ",
                        peer_cert);

  for (token = strtok(tmpstr, "\n"); token; token = strtok(NULL, "\n"))
    writecf(FS_SERV, token);

#if MBEDTLS_VERSION_MAJOR == 3 && MBEDTLS_VERSION_MINOR == 0
  const uint8_t *const rawcert_buf =
      peer_cert->MBEDTLS_PRIVATE(raw).MBEDTLS_PRIVATE(p);
  size_t rawcert_len = peer_cert->MBEDTLS_PRIVATE(raw).MBEDTLS_PRIVATE(len);
#else
  const uint8_t *const rawcert_buf = peer_cert->raw.p;
  size_t rawcert_len = peer_cert->raw.len;
#endif
  const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_string("SHA1");
  if (mdinfo) {
    mbedtls_md(mdinfo, rawcert_buf, rawcert_len, digest);

    char *fp = fingerprint;
    for (int j = 0; j < mbedtls_md_get_size(mdinfo); j++)
      fp += sprintf(fp, "%02X:", digest[j]);
    assert(fp > fingerprint);
    fp[-1] = 0;
    snprintf(tmpstr, TMPSTRSIZE, "[TLS FINGERPRINT     ] %s (from server)",
             fingerprint);
    writecf(FS_SERV, tmpstr);

    if (getintoption(CF_PINFINGER) && verify_or_store_fingerprint(fingerprint))
      return 1;
  } else {
    writecf(FS_ERR, "Warning: Unable to load SHA-1 md");
    if (getintoption(CF_PINFINGER)) {
      writecf(
          FS_ERR,
          "ERROR: Can not compute fingerprint, but pinning check is required");
      return 1;
    }
  }

  ret = mbedtls_ssl_get_verify_result(ssl);
  switch (ret) {
  case 0:
    writecf(FS_SERV, "[TLS HANDSHAKE OK    ]");
    break;
  case -1:
    writecf(FS_ERR, "Error: TLS verify for an unknown reason");
    return -1;
  case MBEDTLS_X509_BADCERT_SKIP_VERIFY:
  case MBEDTLS_X509_BADCERT_NOT_TRUSTED:
    if (getintoption(CF_IGNSSL) || !getintoption(CF_VERIFYSSL))
      return 0;
    vc_tls_report_error(ret, "TLS verify failed, mbedtls reports: ");
    return -1;
  default:
    vc_tls_report_error(ret, "TLS verify failed, mbedtls reports: ");
    return -1;
  }

  return 0;
}

ssize_t vc_mbedtls_sendmessage(const void *buf, size_t size) {
  return mbedtls_ssl_write(&_mbedtls_state._ssl, buf, size);
}

ssize_t vc_mbedtls_receivemessage(void *buf, size_t size) {
  ssize_t received = (ssize_t)mbedtls_ssl_read(&_mbedtls_state._ssl, buf, size);
  switch (received) {
  case MBEDTLS_ERR_SSL_WANT_READ:
  case MBEDTLS_ERR_SSL_WANT_WRITE:
    return -2;
  case MBEDTLS_ERR_SSL_CONN_EOF:
  case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
  case 0:
    return 0;
  default:
    if (received > 0)
      return received;
    return -1;
  }
}

void vc_mbedtls_cleanup() {
  mbedtls_x509_crt_free(&_mbedtls_state._cacert);
  mbedtls_x509_crt_free(&_mbedtls_state._cert);
  mbedtls_pk_free(&_mbedtls_state._key);
  mbedtls_ssl_free(&_mbedtls_state._ssl);
  mbedtls_ssl_config_free(&_mbedtls_state._conf);
  mbedtls_ctr_drbg_free(&_mbedtls_state._ctr_drbg);
}

/* Taken from https://testssl.sh/openssl-iana.mapping.html */
static const char * xlate_openssl[] = {
"NULL-MD5", "TLS-RSA-WITH-NULL-MD5",
"NULL-SHA", "TLS-RSA-WITH-NULL-SHA",
"EXP-RC4-MD5", "TLS-RSA-EXPORT-WITH-RC4-40-MD5",
"RC4-MD5", "TLS-RSA-WITH-RC4-128-MD5",
"RC4-SHA", "TLS-RSA-WITH-RC4-128-SHA",
"EXP-RC2-CBC-MD5", "TLS-RSA-EXPORT-WITH-RC2-CBC-40-MD5",
"IDEA-CBC-SHA", "TLS-RSA-WITH-IDEA-CBC-SHA",
"EXP-DES-CBC-SHA", "TLS-RSA-EXPORT-WITH-DES40-CBC-SHA",
"DES-CBC-SHA", "TLS-RSA-WITH-DES-CBC-SHA",
"DES-CBC3-SHA", "TLS-RSA-WITH-3DES-EDE-CBC-SHA",
"EXP-DH-DSS-DES-CBC-SHA", "TLS-DH-DSS-EXPORT-WITH-DES40-CBC-SHA",
"DH-DSS-DES-CBC-SHA", "TLS-DH-DSS-WITH-DES-CBC-SHA",
"DH-DSS-DES-CBC3-SHA", "TLS-DH-DSS-WITH-3DES-EDE-CBC-SHA",
"EXP-DH-RSA-DES-CBC-SHA", "TLS-DH-RSA-EXPORT-WITH-DES40-CBC-SHA",
"DH-RSA-DES-CBC-SHA", "TLS-DH-RSA-WITH-DES-CBC-SHA",
"DH-RSA-DES-CBC3-SHA", "TLS-DH-RSA-WITH-3DES-EDE-CBC-SHA",
"EXP-EDH-DSS-DES-CBC-SHA", "TLS-DHE-DSS-EXPORT-WITH-DES40-CBC-SHA",
"EDH-DSS-DES-CBC-SHA", "TLS-DHE-DSS-WITH-DES-CBC-SHA",
"EDH-DSS-DES-CBC3-SHA", "TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA",
"EXP-EDH-RSA-DES-CBC-SHA", "TLS-DHE-RSA-EXPORT-WITH-DES40-CBC-SHA",
"EDH-RSA-DES-CBC-SHA", "TLS-DHE-RSA-WITH-DES-CBC-SHA",
"EDH-RSA-DES-CBC3-SHA", "TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA",
"EXP-ADH-RC4-MD5", "TLS-DH-anon-EXPORT-WITH-RC4-40-MD5",
"ADH-RC4-MD5", "TLS-DH-anon-WITH-RC4-128-MD5",
"EXP-ADH-DES-CBC-SHA", "TLS-DH-anon-EXPORT-WITH-DES40-CBC-SHA",
"ADH-DES-CBC-SHA", "TLS-DH-anon-WITH-DES-CBC-SHA",
"ADH-DES-CBC3-SHA", "TLS-DH-anon-WITH-3DES-EDE-CBC-SHA",
"KRB5-DES-CBC-SHA", "TLS-KRB5-WITH-DES-CBC-SHA",
"KRB5-DES-CBC3-SHA", "TLS-KRB5-WITH-3DES-EDE-CBC-SHA",
"KRB5-RC4-SHA", "TLS-KRB5-WITH-RC4-128-SHA",
"KRB5-IDEA-CBC-SHA", "TLS-KRB5-WITH-IDEA-CBC-SHA",
"KRB5-DES-CBC-MD5", "TLS-KRB5-WITH-DES-CBC-MD5",
"KRB5-DES-CBC3-MD5", "TLS-KRB5-WITH-3DES-EDE-CBC-MD5",
"KRB5-RC4-MD5", "TLS-KRB5-WITH-RC4-128-MD5",
"KRB5-IDEA-CBC-MD5", "TLS-KRB5-WITH-IDEA-CBC-MD5",
"EXP-KRB5-DES-CBC-SHA", "TLS-KRB5-EXPORT-WITH-DES-CBC-40-SHA",
"EXP-KRB5-RC2-CBC-SHA", "TLS-KRB5-EXPORT-WITH-RC2-CBC-40-SHA",
"EXP-KRB5-RC4-SHA", "TLS-KRB5-EXPORT-WITH-RC4-40-SHA",
"EXP-KRB5-DES-CBC-MD5", "TLS-KRB5-EXPORT-WITH-DES-CBC-40-MD5",
"EXP-KRB5-RC2-CBC-MD5", "TLS-KRB5-EXPORT-WITH-RC2-CBC-40-MD5",
"EXP-KRB5-RC4-MD5", "TLS-KRB5-EXPORT-WITH-RC4-40-MD5",
"PSK-NULL-SHA", "TLS-PSK-WITH-NULL-SHA",
"DHE-PSK-NULL-SHA", "TLS-DHE-PSK-WITH-NULL-SHA",
"RSA-PSK-NULL-SHA", "TLS-RSA-PSK-WITH-NULL-SHA",
"AES128-SHA", "TLS-RSA-WITH-AES-128-CBC-SHA",
"DH-DSS-AES128-SHA", "TLS-DH-DSS-WITH-AES-128-CBC-SHA",
"DH-RSA-AES128-SHA", "TLS-DH-RSA-WITH-AES-128-CBC-SHA",
"DHE-DSS-AES128-SHA", "TLS-DHE-DSS-WITH-AES-128-CBC-SHA",
"DHE-RSA-AES128-SHA", "TLS-DHE-RSA-WITH-AES-128-CBC-SHA",
"ADH-AES128-SHA", "TLS-DH-anon-WITH-AES-128-CBC-SHA",
"AES256-SHA", "TLS-RSA-WITH-AES-256-CBC-SHA",
"DH-DSS-AES256-SHA", "TLS-DH-DSS-WITH-AES-256-CBC-SHA",
"DH-RSA-AES256-SHA", "TLS-DH-RSA-WITH-AES-256-CBC-SHA",
"DHE-DSS-AES256-SHA", "TLS-DHE-DSS-WITH-AES-256-CBC-SHA",
"DHE-RSA-AES256-SHA", "TLS-DHE-RSA-WITH-AES-256-CBC-SHA",
"ADH-AES256-SHA", "TLS-DH-anon-WITH-AES-256-CBC-SHA",
"NULL-SHA256", "TLS-RSA-WITH-NULL-SHA256",
"AES128-SHA256", "TLS-RSA-WITH-AES-128-CBC-SHA256",
"AES256-SHA256", "TLS-RSA-WITH-AES-256-CBC-SHA256",
"DH-DSS-AES128-SHA256", "TLS-DH-DSS-WITH-AES-128-CBC-SHA256",
"DH-RSA-AES128-SHA256", "TLS-DH-RSA-WITH-AES-128-CBC-SHA256",
"DHE-DSS-AES128-SHA256", "TLS-DHE-DSS-WITH-AES-128-CBC-SHA256",
"CAMELLIA128-SHA", "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA",
"DH-DSS-CAMELLIA128-SHA", "TLS-DH-DSS-WITH-CAMELLIA-128-CBC-SHA",
"DH-RSA-CAMELLIA128-SHA", "TLS-DH-RSA-WITH-CAMELLIA-128-CBC-SHA",
"DHE-DSS-CAMELLIA128-SHA", "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA",
"DHE-RSA-CAMELLIA128-SHA", "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA",
"ADH-CAMELLIA128-SHA", "TLS-DH-anon-WITH-CAMELLIA-128-CBC-SHA",
"EXP1024-RC4-MD5", "TLS-RSA-EXPORT1024-WITH-RC4-56-MD5",
"EXP1024-RC2-CBC-MD5", "TLS-RSA-EXPORT1024-WITH-RC2-CBC-56-MD5",
"EXP1024-DES-CBC-SHA", "TLS-RSA-EXPORT1024-WITH-DES-CBC-SHA",
"EXP1024-DHE-DSS-DES-CBC-SHA", "TLS-DHE-DSS-EXPORT1024-WITH-DES-CBC-SHA",
"EXP1024-RC4-SHA", "TLS-RSA-EXPORT1024-WITH-RC4-56-SHA",
"EXP1024-DHE-DSS-RC4-SHA", "TLS-DHE-DSS-EXPORT1024-WITH-RC4-56-SHA",
"DHE-DSS-RC4-SHA", "TLS-DHE-DSS-WITH-RC4-128-SHA",
"DHE-RSA-AES128-SHA256", "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256",
"DH-DSS-AES256-SHA256", "TLS-DH-DSS-WITH-AES-256-CBC-SHA256",
"DH-RSA-AES256-SHA256", "TLS-DH-RSA-WITH-AES-256-CBC-SHA256",
"DHE-DSS-AES256-SHA256", "TLS-DHE-DSS-WITH-AES-256-CBC-SHA256",
"DHE-RSA-AES256-SHA256", "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256",
"ADH-AES128-SHA256", "TLS-DH-anon-WITH-AES-128-CBC-SHA256",
"ADH-AES256-SHA256", "TLS-DH-anon-WITH-AES-256-CBC-SHA256",
"GOST94-GOST89-GOST89", "TLS-GOSTR341094-WITH-28147-CNT-IMIT",
"GOST2001-GOST89-GOST89", "TLS-GOSTR341001-WITH-28147-CNT-IMIT",
"GOST94-NULL-GOST94", "TLS-GOSTR341001-WITH-NULL-GOSTR3411",
"GOST2001-GOST89-GOST89", "TLS-GOSTR341094-WITH-NULL-GOSTR3411",
"CAMELLIA256-SHA", "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA",
"DH-DSS-CAMELLIA256-SHA", "TLS-DH-DSS-WITH-CAMELLIA-256-CBC-SHA",
"DH-RSA-CAMELLIA256-SHA", "TLS-DH-RSA-WITH-CAMELLIA-256-CBC-SHA",
"DHE-DSS-CAMELLIA256-SHA", "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA",
"DHE-RSA-CAMELLIA256-SHA", "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA",
"ADH-CAMELLIA256-SHA", "TLS-DH-anon-WITH-CAMELLIA-256-CBC-SHA",
"PSK-RC4-SHA", "TLS-PSK-WITH-RC4-128-SHA",
"PSK-3DES-EDE-CBC-SHA", "TLS-PSK-WITH-3DES-EDE-CBC-SHA",
"PSK-AES128-CBC-SHA", "TLS-PSK-WITH-AES-128-CBC-SHA",
"PSK-AES256-CBC-SHA", "TLS-PSK-WITH-AES-256-CBC-SHA",
"SEED-SHA", "TLS-RSA-WITH-SEED-CBC-SHA",
"DH-DSS-SEED-SHA", "TLS-DH-DSS-WITH-SEED-CBC-SHA",
"DH-RSA-SEED-SHA", "TLS-DH-RSA-WITH-SEED-CBC-SHA",
"DHE-DSS-SEED-SHA", "TLS-DHE-DSS-WITH-SEED-CBC-SHA",
"DHE-RSA-SEED-SHA", "TLS-DHE-RSA-WITH-SEED-CBC-SHA",
"ADH-SEED-SHA", "TLS-DH-anon-WITH-SEED-CBC-SHA",
"AES128-GCM-SHA256", "TLS-RSA-WITH-AES-128-GCM-SHA256",
"AES256-GCM-SHA384", "TLS-RSA-WITH-AES-256-GCM-SHA384",
"DHE-RSA-AES128-GCM-SHA256", "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256",
"DHE-RSA-AES256-GCM-SHA384", "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384",
"DH-RSA-AES128-GCM-SHA256", "TLS-DH-RSA-WITH-AES-128-GCM-SHA256",
"DH-RSA-AES256-GCM-SHA384", "TLS-DH-RSA-WITH-AES-256-GCM-SHA384",
"DHE-DSS-AES128-GCM-SHA256", "TLS-DHE-DSS-WITH-AES-128-GCM-SHA256",
"DHE-DSS-AES256-GCM-SHA384", "TLS-DHE-DSS-WITH-AES-256-GCM-SHA384",
"DH-DSS-AES128-GCM-SHA256", "TLS-DH-DSS-WITH-AES-128-GCM-SHA256",
"DH-DSS-AES256-GCM-SHA384", "TLS-DH-DSS-WITH-AES-256-GCM-SHA384",
"ADH-AES128-GCM-SHA256", "TLS-DH-anon-WITH-AES-128-GCM-SHA256",
"ADH-AES256-GCM-SHA384", "TLS-DH-anon-WITH-AES-256-GCM-SHA384",
"CAMELLIA128-SHA256", "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256",
"DH-DSS-CAMELLIA128-SHA256", "TLS-DH-DSS-WITH-CAMELLIA-128-CBC-SHA256",
"DH-RSA-CAMELLIA128-SHA256", "TLS-DH-RSA-WITH-CAMELLIA-128-CBC-SHA256",
"DHE-DSS-CAMELLIA128-SHA256", "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256",
"DHE-RSA-CAMELLIA128-SHA256", "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256",
"ADH-CAMELLIA128-SHA256", "TLS-DH-anon-WITH-CAMELLIA-128-CBC-SHA256",
"TLS-FALLBACK-SCSV", "TLS-EMPTY-RENEGOTIATION-INFO-SCSV",
"TLS-AES-128-GCM-SHA256", "TLS-AES-128-GCM-SHA256",
"TLS-AES-256-GCM-SHA384", "TLS-AES-256-GCM-SHA384",
"TLS-CHACHA20-POLY1305-SHA256", "TLS-CHACHA20-POLY1305-SHA256",
"TLS-AES-128-CCM-SHA256", "TLS-AES-128-CCM-SHA256",
"TLS-AES-128-CCM-8-SHA256", "TLS-AES-128-CCM-8-SHA256",
"ECDH-ECDSA-NULL-SHA", "TLS-ECDH-ECDSA-WITH-NULL-SHA",
"ECDH-ECDSA-RC4-SHA", "TLS-ECDH-ECDSA-WITH-RC4-128-SHA",
"ECDH-ECDSA-DES-CBC3-SHA", "TLS-ECDH-ECDSA-WITH-3DES-EDE-CBC-SHA",
"ECDH-ECDSA-AES128-SHA", "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA",
"ECDH-ECDSA-AES256-SHA", "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA",
"ECDHE-ECDSA-NULL-SHA", "TLS-ECDHE-ECDSA-WITH-NULL-SHA",
"ECDHE-ECDSA-RC4-SHA", "TLS-ECDHE-ECDSA-WITH-RC4-128-SHA",
"ECDHE-ECDSA-DES-CBC3-SHA", "TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA",
"ECDHE-ECDSA-AES128-SHA", "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA",
"ECDHE-ECDSA-AES256-SHA", "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA",
"ECDH-RSA-NULL-SHA", "TLS-ECDH-RSA-WITH-NULL-SHA",
"ECDH-RSA-RC4-SHA", "TLS-ECDH-RSA-WITH-RC4-128-SHA",
"ECDH-RSA-DES-CBC3-SHA", "TLS-ECDH-RSA-WITH-3DES-EDE-CBC-SHA",
"ECDH-RSA-AES128-SHA", "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA",
"ECDH-RSA-AES256-SHA", "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA",
"ECDHE-RSA-NULL-SHA", "TLS-ECDHE-RSA-WITH-NULL-SHA",
"ECDHE-RSA-RC4-SHA", "TLS-ECDHE-RSA-WITH-RC4-128-SHA",
"ECDHE-RSA-DES-CBC3-SHA", "TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA",
"ECDHE-RSA-AES128-SHA", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA",
"ECDHE-RSA-AES256-SHA", "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA",
"AECDH-NULL-SHA", "TLS-ECDH-anon-WITH-NULL-SHA",
"AECDH-RC4-SHA", "TLS-ECDH-anon-WITH-RC4-128-SHA",
"AECDH-DES-CBC3-SHA", "TLS-ECDH-anon-WITH-3DES-EDE-CBC-SHA",
"AECDH-AES128-SHA", "TLS-ECDH-anon-WITH-AES-128-CBC-SHA",
"AECDH-AES256-SHA", "TLS-ECDH-anon-WITH-AES-256-CBC-SHA",
"SRP-3DES-EDE-CBC-SHA", "TLS-SRP-SHA-WITH-3DES-EDE-CBC-SHA",
"SRP-RSA-3DES-EDE-CBC-SHA", "TLS-SRP-SHA-RSA-WITH-3DES-EDE-CBC-SHA",
"SRP-DSS-3DES-EDE-CBC-SHA", "TLS-SRP-SHA-DSS-WITH-3DES-EDE-CBC-SHA",
"SRP-AES-128-CBC-SHA", "TLS-SRP-SHA-WITH-AES-128-CBC-SHA",
"SRP-RSA-AES-128-CBC-SHA", "TLS-SRP-SHA-RSA-WITH-AES-128-CBC-SHA",
"SRP-DSS-AES-128-CBC-SHA", "TLS-SRP-SHA-DSS-WITH-AES-128-CBC-SHA",
"SRP-AES-256-CBC-SHA", "TLS-SRP-SHA-WITH-AES-256-CBC-SHA",
"SRP-RSA-AES-256-CBC-SHA", "TLS-SRP-SHA-RSA-WITH-AES-256-CBC-SHA",
"SRP-DSS-AES-256-CBC-SHA", "TLS-SRP-SHA-DSS-WITH-AES-256-CBC-SHA",
"ECDHE-ECDSA-AES128-SHA256", "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256",
"ECDHE-ECDSA-AES256-SHA384", "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384",
"ECDH-ECDSA-AES128-SHA256", "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256",
"ECDH-ECDSA-AES256-SHA384", "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA384",
"ECDHE-RSA-AES128-SHA256", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256",
"ECDHE-RSA-AES256-SHA384", "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384",
"ECDH-RSA-AES128-SHA256", "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA256",
"ECDH-RSA-AES256-SHA384", "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA384",
"ECDHE-ECDSA-AES128-GCM-SHA256", "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256",
"ECDHE-ECDSA-AES256-GCM-SHA384", "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384",
"ECDH-ECDSA-AES128-GCM-SHA256", "TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256",
"ECDH-ECDSA-AES256-GCM-SHA384", "TLS-ECDH-ECDSA-WITH-AES-256-GCM-SHA384",
"ECDHE-RSA-AES128-GCM-SHA256", "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256",
"ECDHE-RSA-AES256-GCM-SHA384", "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",
"ECDH-RSA-AES128-GCM-SHA256", "TLS-ECDH-RSA-WITH-AES-128-GCM-SHA256",
"ECDH-RSA-AES256-GCM-SHA384", "TLS-ECDH-RSA-WITH-AES-256-GCM-SHA384",
"ECDHE-PSK-RC4-SHA", "TLS-ECDHE-PSK-WITH-RC4-128-SHA",
"ECDHE-PSK-3DES-EDE-CBC-SHA", "TLS-ECDHE-PSK-WITH-3DES-EDE-CBC-SHA",
"ECDHE-PSK-AES128-CBC-SHA", "TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA",
"ECDHE-PSK-AES256-CBC-SHA", "TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA",
"ECDHE-PSK-AES128-CBC-SHA256", "TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA256",
"ECDHE-PSK-AES256-CBC-SHA384", "TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA384",
"ECDHE-PSK-NULL-SHA", "TLS-ECDHE-PSK-WITH-NULL-SHA",
"ECDHE-PSK-NULL-SHA256", "TLS-ECDHE-PSK-WITH-NULL-SHA256",
"ECDHE-PSK-NULL-SHA384", "TLS-ECDHE-PSK-WITH-NULL-SHA384",
"ECDHE-ECDSA-CAMELLIA128-SHA256", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256",
"ECDHE-ECDSA-CAMELLIA256-SHA38", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA384",
"ECDH-ECDSA-CAMELLIA128-SHA256", "TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA256",
"ECDH-ECDSA-CAMELLIA256-SHA384", "TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA384",
"ECDHE-RSA-CAMELLIA128-SHA256", "TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256",
"ECDHE-RSA-CAMELLIA256-SHA384", "TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA384",
"ECDH-RSA-CAMELLIA128-SHA256", "TLS-ECDH-RSA-WITH-CAMELLIA-128-CBC-SHA256",
"ECDH-RSA-CAMELLIA256-SHA384", "TLS-ECDH-RSA-WITH-CAMELLIA-256-CBC-SHA384",
"PSK-CAMELLIA128-SHA256", "TLS-PSK-WITH-CAMELLIA-128-CBC-SHA256",
"PSK-CAMELLIA256-SHA384", "TLS-PSK-WITH-CAMELLIA-256-CBC-SHA384",
"DHE-PSK-CAMELLIA128-SHA256", "TLS-DHE-PSK-WITH-CAMELLIA-128-CBC-SHA256",
"DHE-PSK-CAMELLIA256-SHA384", "TLS-DHE-PSK-WITH-CAMELLIA-256-CBC-SHA384",
"RSA-PSK-CAMELLIA128-SHA256", "TLS-RSA-PSK-WITH-CAMELLIA-128-CBC-SHA256",
"RSA-PSK-CAMELLIA256-SHA384", "TLS-RSA-PSK-WITH-CAMELLIA-256-CBC-SHA384",
"ECDHE-PSK-CAMELLIA128-SHA256", "TLS-ECDHE-PSK-WITH-CAMELLIA-128-CBC-SHA256",
"ECDHE-PSK-CAMELLIA256-SHA384", "TLS-ECDHE-PSK-WITH-CAMELLIA-256-CBC-SHA384",
"AES128-CCM", "TLS-RSA-WITH-AES-128-CCM",
"AES256-CCM", "TLS-RSA-WITH-AES-256-CCM",
"DHE-RSA-AES128-CCM", "TLS-DHE-RSA-WITH-AES-128-CCM",
"DHE-RSA-AES256-CCM", "TLS-DHE-RSA-WITH-AES-256-CCM",
"AES128-CCM8", "TLS-RSA-WITH-AES-128-CCM-8",
"AES256-CCM8", "TLS-RSA-WITH-AES-256-CCM-8",
"DHE-RSA-AES128-CCM8", "TLS-DHE-RSA-WITH-AES-128-CCM-8",
"DHE-RSA-AES256-CCM8", "TLS-DHE-RSA-WITH-AES-256-CCM-8",
"PSK-AES128-CCM", "TLS-PSK-WITH-AES-128-CCM",
"PSK-AES256-CCM", "TLS-PSK-WITH-AES-256-CCM",
"DHE-PSK-AES128-CCM", "TLS-DHE-PSK-WITH-AES-128-CCM",
"DHE-PSK-AES256-CCM", "TLS-DHE-PSK-WITH-AES-256-CCM",
"PSK-AES128-CCM8", "TLS-PSK-WITH-AES-128-CCM-8",
"PSK-AES256-CCM8", "TLS-PSK-WITH-AES-256-CCM-8",
"DHE-PSK-AES128-CCM8", "TLS-PSK-DHE-WITH-AES-128-CCM-8",
"DHE-PSK-AES256-CCM8", "TLS-PSK-DHE-WITH-AES-256-CCM-8",
"ECDHE-ECDSA-AES128-CCM", "TLS-ECDHE-ECDSA-WITH-AES-128-CCM",
"ECDHE-ECDSA-AES256-CCM", "TLS-ECDHE-ECDSA-WITH-AES-256-CCM",
"ECDHE-ECDSA-AES128-CCM8", "TLS-ECDHE-ECDSA-WITH-AES-128-CCM-8",
"ECDHE-ECDSA-AES256-CCM8", "TLS-ECDHE-ECDSA-WITH-AES-256-CCM-8",
"ECDHE-RSA-CHACHA20-POLY1305-OLD", "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256-OLD",
"ECDHE-ECDSA-CHACHA20-POLY1305-OLD", "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256-OLD",
"DHE-RSA-CHACHA20-POLY1305-OLD", "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256-OLD",
"ECDHE-RSA-CHACHA20-POLY1305", "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256",
"ECDHE-ECDSA-CHACHA20-POLY1305", "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256",
"DHE-RSA-CHACHA20-POLY1305", "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256",
"PSK-CHACHA20-POLY1305", "TLS-PSK-WITH-CHACHA20-POLY1305-SHA256",
"ECDHE-PSK-CHACHA20-POLY1305", "TLS-ECDHE-PSK-WITH-CHACHA20-POLY1305-SHA256",
"DHE-PSK-CHACHA20-POLY1305", "TLS-DHE-PSK-WITH-CHACHA20-POLY1305-SHA256",
"RSA-PSK-CHACHA20-POLY1305", "TLS-RSA-PSK-WITH-CHACHA20-POLY1305-SHA256",
"GOST-MD5", "TLS-GOSTR341094-RSA-WITH-28147-CNT-MD5",
"GOST-GOST94", "TLS-RSA-WITH-28147-CNT-GOST94",
"RC4-MD5", "SSL-CK-RC4-128-WITH-MD5",
"EXP-RC4-MD5", "SSL-CK-RC4-128-EXPORT40-WITH-MD5",
"RC2-CBC-MD5", "SSL-CK-RC2-128-CBC-WITH-MD5",
"EXP-RC2-CBC-MD5", "SSL-CK-RC2-128-CBC-EXPORT40-WITH-MD5",
"IDEA-CBC-MD5", "SSL-CK-IDEA-128-CBC-WITH-MD5",
"DES-CBC-MD5", "SSL-CK-DES-64-CBC-WITH-MD5",
"DES-CBC-SHA", "SSL-CK-DES-64-CBC-WITH-SHA",
"DES-CBC3-MD5", "SSL-CK-DES-192-EDE3-CBC-WITH-MD5",
"DES-CBC3-SHA", "SSL-CK-DES-192-EDE3-CBC-WITH-SHA",
"RC4-64-MD5", "SSL-CK-RC4-64-WITH-MD5",
"DES-CFB-M1", "SSL-CK-DES-64-CFB64-WITH-MD5-1",
NULL
};
// fprintf(stderr, "SUCCESS: %s => %s => %d\n\n", xlate_openssl[i], xlate_openssl[i+1], mbedtls_ssl_get_ciphersuite_id(xlate_openssl[i+1]));
static int map_openssl_suite(char *openssl_name) {
  int i;
  for (i = 0; xlate_openssl[i]; i += 2) {
    if (!strcmp(xlate_openssl[i], openssl_name))
      return mbedtls_ssl_get_ciphersuite_id(xlate_openssl[i + 1]);
  }
  return 0;
}

#endif
