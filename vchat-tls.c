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

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>

#include <readline/readline.h>

#include "vchat.h"
#include "vchat-tls.h"

const char *vchat_ssl_version = "vchat-tlsl.c      $Id$";

/* connection BIO for openssl */
static BIO *server_conn = NULL;

typedef int (*vc_x509verify_cb_t)(int, X509_STORE_CTX *);
struct vc_x509store_t {
   char                 *cafile;
   char                 *capath;
   char                 *crlfile;
   vc_x509verify_cb_t   callback;
   vc_askpass_cb_t      askpass_callback;
   STACK_OF(X509)       *certs;
   STACK_OF(X509_CRL)   *crls;
   char                 *use_certfile;
   STACK_OF(X509)       *use_certs;
   char                 *use_keyfile;
   EVP_PKEY             *use_key;
   int                  flags;
};

static SSL_CTX * vc_create_sslctx( vc_x509store_t *vc_store );
static int vc_verify_callback(int, X509_STORE_CTX *);
static X509_STORE * vc_x509store_create(vc_x509store_t *);
static void vc_x509store_clearflags(vc_x509store_t *, int);
static void vc_x509store_setcapath(vc_x509store_t *, char *);
static void vc_x509store_setcrlfile(vc_x509store_t *, char *);
static void vc_x509store_addcert(vc_x509store_t *, X509 *);
static void vc_x509store_setcb(vc_x509store_t *, vc_x509verify_cb_t);

#define VC_CTX_ERR_EXIT(se, cx) do { \
      snprintf(tmpstr, TMPSTRSIZE, "CREATE CTX: %s", \
            ERR_error_string (ERR_get_error (), NULL)); \
      writecf(FS_ERR, tmpstr); \
      if(se)  X509_STORE_free(se); \
      if(cx) SSL_CTX_free(cx); \
      return(0); \
   } while(0)

#define VC_SETCERT_ERR_EXIT(se, cx, err) do { \
      snprintf(tmpstr, TMPSTRSIZE, "CREATE CTX: %s", err); \
      writecf(FS_ERR, tmpstr); \
      if(se)  X509_STORE_free(se); \
      if(cx) SSL_CTX_free(cx); \
      return(NULL); \
   } while(0)

static SSL_CTX * vc_create_sslctx( vc_x509store_t *vc_store )
{
   int                  i                 = 0;
   int                  n                 = 0;
   int                  flags             = 0;
   int                  r                 = 0;
   SSL_CTX              *ctx              = NULL;
   X509_STORE           *store            = NULL;
   vc_x509verify_cb_t   verify_callback   = NULL;

   /* Explicitly use TLSv1 (or maybe later) */
   if( !(ctx = SSL_CTX_new(TLS_client_method())) )
      VC_CTX_ERR_EXIT(store, ctx);

   if( !(store = vc_x509store_create(vc_store)) )
      VC_CTX_ERR_EXIT(store, ctx);

   SSL_CTX_set_cert_store(ctx, store);
   store = NULL;
   /* Disable some insecure protocols explicitly */
   SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
   if (getstroption(CF_CIPHERSUITE))
     SSL_CTX_set_cipher_list(ctx, getstroption(CF_CIPHERSUITE));
   else
     SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA");

   SSL_CTX_set_verify_depth (ctx, getintoption(CF_VERIFYSSL));

   if( !(verify_callback = vc_store->callback) )
      verify_callback = vc_verify_callback;

   if( !(vc_store->flags & VC_X509S_SSL_VERIFY_MASK) ) {
      writecf(FS_DBG, tmpstr);
      flags = SSL_VERIFY_NONE;
   }
   else {
      if(vc_store->flags & VC_X509S_SSL_VERIFY_PEER)
         flags |= SSL_VERIFY_PEER;
      if(vc_store->flags & VC_X509S_SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
         flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
      if(vc_store->flags & VC_X509S_SSL_VERIFY_CLIENT_ONCE)
         flags |= SSL_VERIFY_CLIENT_ONCE;
   }

   SSL_CTX_set_verify(ctx, flags, verify_callback);

   if(vc_store->flags & VC_X509S_USE_CERTIFICATE) {
      if(vc_store->use_certfile)
         SSL_CTX_use_certificate_chain_file(ctx, vc_store->use_certfile);
      else {
         SSL_CTX_use_certificate(ctx,
               sk_X509_value(vc_store->use_certs, 0));
         for(i=0,n=sk_X509_num(vc_store->use_certs); i<n; i++)
            SSL_CTX_add_extra_chain_cert(ctx,
                  sk_X509_value(vc_store->use_certs, i));
      }

      SSL_CTX_set_default_passwd_cb(ctx, vc_store->askpass_callback);

      if(vc_store->use_keyfile) {
         r=SSL_CTX_use_PrivateKey_file(ctx, vc_store->use_keyfile,
               SSL_FILETYPE_PEM);
      } else if(vc_store->use_key)
            r=SSL_CTX_use_PrivateKey(ctx, vc_store->use_key);

      if( r!=1 || !SSL_CTX_check_private_key(ctx))
         VC_SETCERT_ERR_EXIT(store, ctx, "Load private key failed");
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
   int i                = 0;
   int n                = 0;
   X509_STORE *store    = NULL;
   X509_LOOKUP *lookup  = NULL;

   store = X509_STORE_new();

   if(vc_store->callback)
      X509_STORE_set_verify_cb_func(store, vc_store->callback);
   else
      X509_STORE_set_verify_cb_func(store, vc_verify_callback);

   if( !(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) )
      VC_STORE_ERR_EXIT(store);

   if(!vc_store->cafile) {
      if( !(vc_store->flags & VC_X509S_NODEF_CAFILE) )
         X509_LOOKUP_load_file(lookup, 0, X509_FILETYPE_DEFAULT);
   } else if( !X509_LOOKUP_load_file(lookup, vc_store->cafile,
            X509_FILETYPE_PEM) )
      VC_STORE_ERR_EXIT(store);

   if(vc_store->crlfile) {
      if( !X509_load_crl_file(lookup, vc_store->crlfile,
               X509_FILETYPE_PEM) )
         VC_STORE_ERR_EXIT(store);

      X509_STORE_set_flags( store,
            X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL );
   }

   if( !(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir())) )
      VC_STORE_ERR_EXIT(store);

   if( !vc_store->capath ) {
      if( !(vc_store->flags & VC_X509S_NODEF_CAPATH) )
         X509_LOOKUP_add_dir(lookup, 0, X509_FILETYPE_DEFAULT);
   } else if( !X509_LOOKUP_add_dir(lookup, vc_store->capath,
            X509_FILETYPE_PEM) )
      VC_STORE_ERR_EXIT(store);

   for( i=0, n=sk_X509_num(vc_store->certs); i<n; i++)
      if( !X509_STORE_add_cert(store, sk_X509_value(vc_store->certs, i)) )
         VC_STORE_ERR_EXIT(store);

   for( i=0, n=sk_X509_CRL_num(vc_store->crls); i<n; i++)
      if( !X509_STORE_add_crl(store,
               sk_X509_CRL_value(vc_store->crls, i)) )
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

void vc_x509store_setflags(vc_x509store_t *store, int flags)
{
   store->flags |= flags;
}

void vc_x509store_clearflags(vc_x509store_t *store, int flags)
{
   store->flags &= ~flags;
}

void vc_x509store_setcb(vc_x509store_t *store,
      vc_x509verify_cb_t callback)
{
   store->callback = callback;
}

void vc_x509store_set_pkeycb(vc_x509store_t *store,
      vc_askpass_cb_t callback)
{
   store->askpass_callback = callback;
}

void vc_x509store_addcert(vc_x509store_t *store, X509 *cert)
{
   sk_X509_push(store->certs, cert);
}

void vc_x509store_setcafile(vc_x509store_t *store, char *file)
{
   free(store->cafile);
   store->cafile = ( file ? strdup(file) : 0 );
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
   free(store->use_keyfile);
   store->use_keyfile = ( file ? strdup(file) : 0 );
}

void vc_x509store_setcertfile(vc_x509store_t *store, char *file)
{
   free(store->use_certfile);
   store->use_certfile = ( file ? strdup(file) : 0 );
}

vc_x509store_t *vc_init_x509store()
{
   vc_x509store_t *s = malloc(sizeof(vc_x509store_t));
   if (s) {

       static int sslinit;
       if( !sslinit++ ) {
           SSL_library_init ();
           SSL_load_error_strings();
       }

       s->cafile         = NULL;
       s->capath         = NULL;
       s->crlfile        = NULL;
       s->callback       = NULL;
       s->askpass_callback = NULL;
       s->certs          = sk_X509_new_null();
       s->crls           = sk_X509_CRL_new_null();
       s->use_certfile   = NULL;
       s->use_certs      = sk_X509_new_null();
       s->use_keyfile    = NULL;
       s->use_key        = NULL;
       s->flags          = 0;
   }
   return s;
}

void vc_cleanup_x509store(vc_x509store_t *s)
{
   free(s->cafile);
   free(s->capath);
   free(s->crlfile);
   free(s->use_certfile);
   free(s->use_keyfile);
   free(s->use_key);
   sk_X509_free(s->certs);
   sk_X509_CRL_free(s->crls);
   sk_X509_free(s->use_certs);
   free(s);
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

const char *vchat_ssl_version_external = "OpenSSL implementation; version unknown";
void vchat_ssl_get_version_external()
{
   char tmpstr[TMPSTRSIZE];
   snprintf(tmpstr, TMPSTRSIZE, "%s with %s", SSLeay_version(SSLEAY_VERSION), SSLeay_version(SSLEAY_CFLAGS));
   vchat_ssl_version_external = strdup(tmpstr);
}
