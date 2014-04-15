/*
 * vchat-client - alpha version
 * vchat-ssl.c - handling of SSL connection and X509 certificate
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

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>

#include <readline/readline.h>

#include "vchat.h"
#include "vchat-ssl.h"

char *vchat_ssl_version = "$Id$";

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

SSL_CTX * vc_create_sslctx( vc_x509store_t *vc_store )
{
   int                  i                 = 0;
   int                  n                 = 0;
   int                  flags             = 0;
   int                  r                 = 0;
   SSL_CTX              *ctx              = NULL;
   X509_STORE           *store            = NULL;
   vc_x509verify_cb_t   verify_callback   = NULL;

   /* Explicitly use TLSv1 (or maybe later) */
   if( !(ctx = SSL_CTX_new(TLSv1_client_method())) )
      VC_CTX_ERR_EXIT(store, ctx);

   if( !(store = vc_x509store_create(vc_store)) )
      VC_CTX_ERR_EXIT(store, ctx);

   SSL_CTX_set_cert_store(ctx, store);
   store = NULL;
   /* Disable some insecure protocols explicitly */
   SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
   SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

   SSL_CTX_set_verify_depth (ctx, 2);

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

int vc_connect_ssl( BIO **conn, vc_x509store_t *vc_store )
{
  BIO *ssl_conn = NULL;
  SSL_CTX * ctx = vc_create_sslctx(vc_store);

  if( !ctx )
    return 1;

  ssl_conn = BIO_new_ssl(ctx, 1);
  SSL_CTX_free(ctx);

  if( ssl_conn ) {
    BIO_push( ssl_conn, *conn );
    *conn = ssl_conn;
    fflush(stdout);
    if( BIO_do_handshake( *conn ) > 0 ) {
      /* Show information about cipher used */
      const SSL *sslp = NULL;
      const SSL_CIPHER * cipher = NULL;

      /* Get cipher object */
      BIO_get_ssl(ssl_conn, &sslp);
        cipher = SSL_get_current_cipher(sslp);
      if (cipher) {
        char cipher_desc[TMPSTRSIZE];
        snprintf(tmpstr, TMPSTRSIZE, "[SSL CIPHER] %s", SSL_CIPHER_description(cipher, cipher_desc, TMPSTRSIZE));
        writecf(FS_SERV, tmpstr);
      } else {
        snprintf(tmpstr, TMPSTRSIZE, "[SSL ERROR] Cipher not known / SSL object can't be queried!");
        writecf(FS_ERR, tmpstr);
      }
      return 0;
    }
  }

  snprintf(tmpstr, TMPSTRSIZE, "[SSL ERROR] %s", ERR_error_string (ERR_get_error (), NULL));
  writecf(FS_ERR, tmpstr);

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
      /* XXX handle action/abort */
      if(!(ok=getintoption(CF_IGNSSL)))
         snprintf(tmpstr, TMPSTRSIZE, "[SSL ERROR] %s", 
               X509_verify_cert_error_string(store->error));
      else
         snprintf(tmpstr, TMPSTRSIZE, "[SSL ERROR] %s (ignored)", 
               X509_verify_cert_error_string(store->error));

      writecf(FS_ERR, tmpstr);
   }
   return(ok);
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


void vc_init_x509store(vc_x509store_t *s)
{
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

void vc_cleanup_x509store(vc_x509store_t *s)
{
   free(s->cafile);
   free(s->capath);
   free(s->crlfile);
   free(s->use_certfile);
   free(s->use_keyfile);
   free(s->use_key);
   sk_X509_free(s->certs);
   sk_X509_free(s->crls);
   sk_X509_free(s->use_certs);
}
