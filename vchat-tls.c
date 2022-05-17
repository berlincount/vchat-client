/*
 * vchat-client - alpha version
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <readline/readline.h>

#include "vchat.h"
#include "vchat-tls.h"

const char *vchat_tls_version = "vchat-tls.c      $Id$";
const char *vchat_tls_version_external = "Unknown implementation; version unknown";

void vc_cleanup_x509store(vc_x509store_t *store)
{
   free(store->cafile);
   free(store->capath);
   free(store->crlfile);
   free(store->certfile);
   free(store->keyfile);
   memset(store, 0, sizeof(vc_x509store_t));
}

void vc_x509store_setflags(vc_x509store_t *store, int flags) { store->flags |= flags; }
void vc_x509store_clearflags(vc_x509store_t *store, int flags) { store->flags &= ~flags; }
void vc_x509store_set_pkeycb(vc_x509store_t *store, vc_askpass_cb_t callback) { store->askpass_callback = callback; }

void vc_x509store_setcafile(vc_x509store_t *store, char *file)
{
   free(store->cafile);
   store->cafile = ( file ? strdup(file) : 0 );
   store->flags |= VC_X509S_USE_CAFILE;
}

void vc_x509store_setcapath(vc_x509store_t *store, char *path)
{
   free(store->capath);
   store->capath = ( path ? strdup(path) : 0 );
}

void vc_x509store_setcrlfile(vc_x509store_t *store, char *file)
{
   free(store->crlfile);
   store->crlfile = ( file ? strdup(file) : 0 );
}

void vc_x509store_setkeyfile(vc_x509store_t *store, char *file)
{
   free(store->keyfile);
   store->keyfile = ( file ? strdup(file) : 0 );
}

void vc_x509store_setcertfile(vc_x509store_t *store, char *file)
{
   free(store->certfile);
   store->certfile = ( file ? strdup(file) : 0 );
   store->flags |= VC_X509S_USE_CERTIFICATE;
}

//// OPENSSL SPECIFIC

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>

void vchat_tls_get_version_external()
{
   snprintf(tmpstr, sizeof(tmpstr), "OpenSSL %s with %s", SSLeay_version(SSLEAY_VERSION), SSLeay_version(SSLEAY_CFLAGS));
   vchat_tls_version_external = strdup(tmpstr);
}

/* Helpers to work with vc_x509store_t used by all tls libs */
void vc_init_x509store(vc_x509store_t *store)
{
   static int sslinit;
   if (!sslinit++) {
      SSL_library_init ();
      SSL_load_error_strings();
   }
   memset(store, 0, sizeof(vc_x509store_t));

   /* We want to make verifying the peer the default */
   store->flags |= VC_X509S_SSL_VERIFY_PEER;
}

/* connection BIO for openssl */
static BIO *server_conn = NULL;

static SSL_CTX * vc_create_sslctx( vc_x509store_t *vc_store );
static int vc_verify_callback(int, X509_STORE_CTX *);
static X509_STORE * vc_x509store_create(vc_x509store_t *);

static SSL_CTX * vc_create_sslctx( vc_x509store_t *vc_store )
{
   int flags = 0;

   /* Explicitly use TLSv1 (or maybe later) */
   SSL_CTX    *ctx   = SSL_CTX_new(TLS_client_method());
   X509_STORE *store = vc_x509store_create(vc_store);

   if (!ctx || !store) {
      snprintf(tmpstr, sizeof(tmpstr), "CREATE CTX: %s",ERR_error_string (ERR_get_error (), NULL));
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
     SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA");

   SSL_CTX_set_verify_depth (ctx, getintoption(CF_VERIFYSSL));

   if( !(vc_store->flags & VC_X509S_SSL_VERIFY_MASK) ) {
      writecf(FS_DBG, tmpstr);
      flags = SSL_VERIFY_NONE;
   } else {
      if(vc_store->flags & VC_X509S_SSL_VERIFY_PEER)
         flags |= SSL_VERIFY_PEER;
      if(vc_store->flags & VC_X509S_SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
         flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
      if(vc_store->flags & VC_X509S_SSL_VERIFY_CLIENT_ONCE)
         flags |= SSL_VERIFY_CLIENT_ONCE;
   }

   SSL_CTX_set_verify(ctx, flags, vc_verify_callback);

   if(vc_store->flags & VC_X509S_USE_CERTIFICATE) {
      int r = 0;
      if(vc_store->certfile)
         SSL_CTX_use_certificate_chain_file(ctx, vc_store->certfile);

      SSL_CTX_set_default_passwd_cb(ctx, vc_store->askpass_callback);

      if(vc_store->keyfile)
         r=SSL_CTX_use_PrivateKey_file(ctx, vc_store->keyfile,
               SSL_FILETYPE_PEM);

      if( r!=1 || !SSL_CTX_check_private_key(ctx)) {
         snprintf(tmpstr, sizeof(tmpstr), "CREATE CTX: Load private key failed");
         writecf(FS_ERR, tmpstr);
         SSL_CTX_free(ctx);
         return NULL;
      }
   }

   SSL_CTX_set_app_data(ctx, vc_store);
   return(ctx);
}

int vc_tls_connect( int serverfd, vc_x509store_t *vc_store )
{
  SSL_CTX * ctx = vc_create_sslctx(vc_store);
  X509 *peercert = NULL;
  BIO *ssl_conn = NULL;
  const SSL *sslp = NULL;
  const SSL_CIPHER * cipher = NULL;

  server_conn = BIO_new_socket( serverfd, 1 );

  /* To display and check server fingerprint */
  char fingerprint[EVP_MAX_MD_SIZE*4];
  unsigned char fingerprint_bin[EVP_MAX_MD_SIZE];
  unsigned int fingerprint_len;

  FILE *fingerprint_file = NULL;
  char * fp = fingerprint;

  long result, j;

  if( !ctx )
    goto all_errors;

  ssl_conn = BIO_new_ssl(ctx, 1);
  SSL_CTX_free(ctx);

  if( !ssl_conn )
    goto ssl_error;

  BIO_push( ssl_conn, server_conn );
  server_conn = ssl_conn;
  fflush(stdout);

  if( BIO_do_handshake( server_conn ) <= 0 )
    goto ssl_error;

  /* Show information about cipher used */
  /* Get cipher object */
  BIO_get_ssl(ssl_conn, &sslp);
  if (!sslp)
    goto ssl_error;

  cipher = SSL_get_current_cipher(sslp);
  if (cipher) {
    char cipher_desc[TMPSTRSIZE];
    snprintf(tmpstr, TMPSTRSIZE, "[SSL CIPHER       ] %s", SSL_CIPHER_description(cipher, cipher_desc, TMPSTRSIZE));
    writecf(FS_SERV, tmpstr);
  } else {
    snprintf(tmpstr, TMPSTRSIZE, "[SSL ERROR        ] Cipher not known / SSL object can't be queried!");
    writecf(FS_ERR, tmpstr);
  }

  /* Accept being connected, _if_ verification passed */
  peercert = SSL_get_peer_certificate(sslp);
  if (!peercert)
    goto ssl_error;

  /* show basic information about peer cert */
  snprintf(tmpstr, TMPSTRSIZE, "[SSL SUBJECT      ] %s", X509_NAME_oneline(X509_get_subject_name(peercert),0,0));
  writecf(FS_SERV, tmpstr);
  snprintf(tmpstr, TMPSTRSIZE, "[SSL ISSUER       ] %s", X509_NAME_oneline(X509_get_issuer_name(peercert),0,0));
  writecf(FS_SERV, tmpstr);

  /* calculate fingerprint */
  if (!X509_digest(peercert,EVP_sha1(),fingerprint_bin,&fingerprint_len))
    goto ssl_error;

  assert ( ( fingerprint_len > 1 ) && (fingerprint_len <= EVP_MAX_MD_SIZE ));
  for (j=0; j<(int)fingerprint_len; j++)
    fp += sprintf(fp, "%02X:", fingerprint_bin[j]);
  assert ( fp > fingerprint );
  fp[-1] = 0;
  snprintf(tmpstr, TMPSTRSIZE, "[SSL FINGERPRINT  ] %s (from server)", fingerprint);
  writecf(FS_SERV, tmpstr);

  /* we don't need the peercert anymore */
  X509_free(peercert);

  /* verify fingerprint */
  if (getintoption(CF_PINFINGER)) {

    fingerprint_file = fopen(tilde_expand(getstroption(CF_FINGERPRINT)), "r");
    if (fingerprint_file) {

      /* Read fingerprint from file */
      char old_fingerprint[EVP_MAX_MD_SIZE*4];
      char * r = fgets(old_fingerprint, sizeof(old_fingerprint), fingerprint_file);
      fclose(fingerprint_file);

      if (r) {
        /* chomp */
        char *nl = strchr(r, '\n');
        if (nl) *nl = 0;

        /* verify fingerprint matches stored version */
        if (!strcmp(fingerprint, old_fingerprint))
          return 0;
      }

      snprintf(tmpstr, TMPSTRSIZE, "[SSL FINGERPRINT  ] %s (from %s)", r ? old_fingerprint : "<FILE READ ERROR>", getstroption(CF_FINGERPRINT));
      writecf(FS_ERR, tmpstr);
      writecf(FS_ERR, "[SSL CONNECT ERROR] Fingerprint mismatch! Server cert updated?");
      return 1;
    }

    fingerprint_file = fopen(tilde_expand(getstroption(CF_FINGERPRINT)), "w");
    if (!fingerprint_file) {
      snprintf (tmpstr, TMPSTRSIZE, "[WARNING] Can't write fingerprint file, %s.", strerror(errno));
      writecf(FS_ERR, tmpstr);
    } else {
      fputs(fingerprint, fingerprint_file);
      fclose(fingerprint_file);
      writecf(FS_SERV, "Stored fingerprint.");
    }
    return 0;
  }

  /* If verify of x509 chain was requested, do the check here */
  result = SSL_get_verify_result(sslp);

  if (result == X509_V_OK)
    return 0;

  if (getintoption(CF_IGNSSL)) {
    writecf(FS_ERR, "[SSL VERIFY ERROR ] FAILURE IGNORED!!!");
    return 0;
  }

ssl_error:
  snprintf(tmpstr, TMPSTRSIZE, "[SSL CONNECT ERROR] %s", ERR_error_string (ERR_get_error (), NULL));
  writecf(FS_ERR, tmpstr);
all_errors:
  BIO_free_all( server_conn );
  server_conn = NULL;
  return 1;
}

#define VC_STORE_ERR_EXIT(s) do { \
      fprintf(stderr, "[E] SSL_STORE: %s\n", ERR_error_string (ERR_get_error (), NULL)); \
      if(s)  X509_STORE_free(s); \
      return(0); \
   } while(0)

X509_STORE *vc_x509store_create(vc_x509store_t *vc_store)
{
   X509_STORE *store    = NULL;
   X509_LOOKUP *lookup  = NULL;

   store = X509_STORE_new();

   X509_STORE_set_verify_cb_func(store, vc_verify_callback);

   if( !(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) )
      VC_STORE_ERR_EXIT(store);

   if (!vc_store->cafile) {
      if( !(vc_store->flags & VC_X509S_USE_CAFILE) )
         X509_LOOKUP_load_file(lookup, 0, X509_FILETYPE_DEFAULT);
   } else if( !X509_LOOKUP_load_file(lookup, vc_store->cafile,
            X509_FILETYPE_PEM) )
      VC_STORE_ERR_EXIT(store);

   if (vc_store->crlfile) {
      if( !X509_load_crl_file(lookup, vc_store->crlfile,
               X509_FILETYPE_PEM) )
         VC_STORE_ERR_EXIT(store);

      X509_STORE_set_flags( store,
            X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL );
   }

   if ( !(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir())) )
      VC_STORE_ERR_EXIT(store);

   if ( !vc_store->capath ) {
      if( !(vc_store->flags & VC_X509S_USE_CAPATH) )
         X509_LOOKUP_add_dir(lookup, 0, X509_FILETYPE_DEFAULT);
   } else if( !X509_LOOKUP_add_dir(lookup, vc_store->capath,
            X509_FILETYPE_PEM) )
      VC_STORE_ERR_EXIT(store);

   return(store);
}

int vc_verify_callback(int ok, X509_STORE_CTX *store)
{
   if(!ok) {
      snprintf(tmpstr, TMPSTRSIZE, "[SSL VERIFY ERROR ] %s",
               X509_verify_cert_error_string(X509_STORE_CTX_get_error(store)));
      writecf(FS_ERR, tmpstr);
   }
   return (ok | getintoption(CF_IGNSSL));
}

ssize_t vc_tls_sendmessage(const void *buf, size_t size) {
   return BIO_write(server_conn, buf, size);
}

ssize_t vc_tls_receivemessage(void *buf, size_t size) {
   ssize_t received = (ssize_t)BIO_read (server_conn, buf, size);
   if (received != 0)
      return received;
   if (BIO_should_retry(server_conn))
      return -2;
   return 0;
}

void vc_tls_cleanup() {
  BIO_free_all( server_conn );
  server_conn = NULL;
}
