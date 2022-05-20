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
#include <errno.h>

#include <readline/readline.h>

#include "vchat.h"
#include "vchat-tls.h"

const char *vchat_tls_version = "vchat-tls.c      $Id$";
const char *vchat_tls_version_external = "Unknown implementation; version unknown";

/* Helpers to work with vc_x509store_t used by all tls libs */
void vc_cleanup_x509store(vc_x509store_t *store) {
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

void vc_x509store_setcafile(vc_x509store_t *store, char *file) {
    free(store->cafile);
    store->cafile = ( file ? strdup(file) : 0 );
    store->flags |= VC_X509S_USE_CAFILE;
}

void vc_x509store_setcapath(vc_x509store_t *store, char *path) {
    free(store->capath);
    store->capath = ( path ? strdup(path) : 0 );
}

void vc_x509store_setcrlfile(vc_x509store_t *store, char *file) {
    free(store->crlfile);
    store->crlfile = ( file ? strdup(file) : 0 );
}

void vc_x509store_setkeyfile(vc_x509store_t *store, char *file) {
    free(store->keyfile);
    store->keyfile = ( file ? strdup(file) : 0 );
}

void vc_x509store_setcertfile(vc_x509store_t *store, char *file) {
    free(store->certfile);
    store->certfile = ( file ? strdup(file) : 0 );
    store->flags |= VC_X509S_USE_CERTIFICATE;
}

static int verify_or_store_fingerprint(const char *fingerprint) {
    char *fingerprint_file_path = tilde_expand(getstroption(CF_FINGERPRINT));
    if (!fingerprint_file_path) {
        writecf(FS_ERR, "[SSL FINGERPRINT  ] The CF_FINGERPRINT path is not set.");
        return -1;
    }

    FILE *fingerprint_file = fopen(fingerprint_file_path, "r");
    if (fingerprint_file) {
        /* Read fingerprint from file */
        char old_fingerprint[128];
        char * r = fgets(old_fingerprint, sizeof(old_fingerprint), fingerprint_file);
        fclose(fingerprint_file);

        if (r) {
            /* chomp */
            char *nl = strchr(r, '\n');
            if (nl) *nl = 0;

            /* verify fingerprint matches stored version */
            if (!strcmp(fingerprint, old_fingerprint))
                goto cleanup_happy;
        }

        snprintf(tmpstr, TMPSTRSIZE, "[SSL FINGERPRINT  ] Found pinned fingerprint (in %s) %s but expected %s", r ? old_fingerprint : "<FILE READ ERROR>", getstroption(CF_FINGERPRINT), fingerprint);
        writecf(FS_ERR, tmpstr);
        writecf(FS_ERR, "[SSL CONNECT ERROR] Fingerprint mismatch! Server cert updated?");
        free(fingerprint_file_path);
        return 1;
    } else
        writecf(FS_ERR, "[WARNING] No pinned Fingerprint found!");

    fingerprint_file = fopen(fingerprint_file_path, "w");
    if (!fingerprint_file) {
        snprintf (tmpstr, TMPSTRSIZE, "[WARNING] Can't write fingerprint file, %s.", strerror(errno));
        writecf(FS_ERR, tmpstr);
    } else {
        fputs(fingerprint, fingerprint_file);
        fclose(fingerprint_file);
        writecf(FS_SERV, "Stored pinned fingerprint.");
    }
cleanup_happy:
    free(fingerprint_file_path);
    return 0;
}

#ifdef TLS_LIB_OPENSSL

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

    char * fp = fingerprint;

    long j;

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

    if (getintoption(CF_PINFINGER) && verify_or_store_fingerprint(fingerprint))
        return 1;

    /* If verify of x509 chain was requested, do the check here */
    if (X509_V_OK == SSL_get_verify_result(sslp))
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

X509_STORE *vc_x509store_create(vc_x509store_t *vc_store) {
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

int vc_verify_callback(int ok, X509_STORE_CTX *store) {
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
#endif

#ifdef TLS_LIB_MBEDTLS

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/pk.h>
#include <mbedtls/debug.h>
#include "mbedtls/error.h"

#include <sys/socket.h>

const char *DRBG_PERS = "mbed TLS vchat client";

typedef struct {
    mbedtls_entropy_context _entropy;
    mbedtls_ctr_drbg_context _ctr_drbg;
    mbedtls_x509_crt _cacert;
    mbedtls_x509_crt _cert;
    mbedtls_pk_context _key;
    mbedtls_ssl_context _ssl;
    mbedtls_ssl_config  _conf;
} mbedstate;
static mbedstate _mbedtls_state;

void vchat_tls_get_version_external()
{
    snprintf(tmpstr, sizeof(tmpstr), "%s", MBEDTLS_VERSION_STRING_FULL);
    vchat_tls_version_external = strdup(tmpstr);
}

static int static_tcp_recv(void *ctx, unsigned char *buf, size_t len ) {
    return recv((int)(intptr_t)ctx, buf, len, 0);
}
static int static_tcp_send(void *ctx, const unsigned char *buf, size_t len ) {
    return send((int)(intptr_t)ctx, buf, len, 0);
}

void vc_init_x509store(vc_x509store_t *store)
{
    static int sslinit;
    if (!sslinit++) {
        mbedtls_entropy_init(&_mbedtls_state._entropy);
        mbedtls_ctr_drbg_init(&_mbedtls_state._ctr_drbg);

        mbedtls_ctr_drbg_seed(&_mbedtls_state._ctr_drbg, mbedtls_entropy_func, &_mbedtls_state._entropy,
                (const unsigned char *) DRBG_PERS, sizeof (DRBG_PERS));
    }
    memset(store, 0, sizeof(vc_x509store_t));

    /* We want to make verifying the peer the default */
    store->flags |= VC_X509S_SSL_VERIFY_PEER;
}

static void vc_tls_report_error(int error, char *message) {
    size_t used = snprintf(tmpstr, sizeof(tmpstr), "%s", message);
    mbedtls_strerror(error, tmpstr + used, sizeof(tmpstr) - used);
    writecf(FS_ERR, tmpstr);
}

int vc_tls_connect( int serverfd, vc_x509store_t *vc_store )
{
    /* Some aliases for shorter references */
    mbedstate *s = &_mbedtls_state;
    mbedtls_ssl_config *conf = &_mbedtls_state._conf;
    mbedtls_ssl_context *ssl = &_mbedtls_state._ssl;
    int ret;

    mbedtls_x509_crt_init(&s->_cacert);
    mbedtls_x509_crt_init(&s->_cert);
    mbedtls_pk_init(&s->_key);

    mbedtls_ssl_config_init(conf);
    mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    /* TODO: Always verify peer */
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, &s->_ctr_drbg);

    /*  mbedtls_ssl_conf_ciphersuites( */

    /* Read in all certs */
    if (vc_store->cafile) {
        mbedtls_x509_crt_parse_file(&s->_cacert, vc_store->cafile);
        mbedtls_ssl_conf_ca_chain(conf, &s->_cacert, NULL);
    }

    mbedtls_x509_crt_parse_file(&s->_cert, vc_store->certfile);
    char *password = NULL;
    char password_buf[1024];
    while (1) {
        ret = mbedtls_pk_parse_keyfile(&s->_key, vc_store->keyfile, password
#if MBEDTLS_SSL_MAJOR_VERSION_3 >= 3
        , mbedtls_ctr_drbg_random, &s->_ctr_drbg
#endif
        );
        if (!ret)
            break;
        if (ret != MBEDTLS_ERR_PK_PASSWORD_REQUIRED && ret != MBEDTLS_ERR_PK_PASSWORD_MISMATCH) {
            vc_tls_report_error(ret, "CREATE CTX: Loading key failed, mbedtls reports: ");
            return -1;
        }
        if (ret == MBEDTLS_ERR_PK_PASSWORD_MISMATCH)
            vc_tls_report_error(ret, "Wrong passphrase, mbedtls reports: ");
        vc_store->askpass_callback(password_buf, sizeof(password_buf), 0, NULL);
        password = password_buf;
    }
    memset_s(password_buf, sizeof(password_buf), 0, sizeof(password_buf));

#if 0
    /* pk member made private in mbedtls 3 */
    if (mbedtls_pk_check_pair(&(s->_cert.pk), &s->_key)) {
        fprintf(stderr, "KEYPAIR MISSMATCH\n");
    }
#endif
    mbedtls_ssl_conf_own_cert(conf, &s->_cert, &s->_key);

    /* Config constructed, pass to ssl */
    /* Init ssl and config structs and configure ssl ctx */
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_setup(ssl, conf);
    /* TODO: mbedtls_ssl_set_hostname(&ssl, SERVER_NAME) */

    mbedtls_ssl_set_bio(ssl, (void*)(intptr_t)serverfd, static_tcp_send, static_tcp_recv, NULL );

    while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            vc_tls_report_error(ret, "TLS handshake failed, mbedtls reports: ");
            return -1;
        }
    }

    mbedtls_ssl_get_verify_result(ssl);

    return 0;
}

ssize_t vc_tls_sendmessage(const void *buf, size_t size) {
    return mbedtls_ssl_write( &_mbedtls_state._ssl, buf, size);
}

ssize_t vc_tls_receivemessage(void *buf, size_t size) {
    ssize_t received = (ssize_t)mbedtls_ssl_read (&_mbedtls_state._ssl, buf, size);
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

void vc_tls_cleanup() {
    mbedtls_x509_crt_free(&_mbedtls_state._cacert);
    mbedtls_x509_crt_free(&_mbedtls_state._cert);
    mbedtls_pk_free(&_mbedtls_state._key);
    mbedtls_ssl_free(&_mbedtls_state._ssl );
    mbedtls_ssl_config_free(&_mbedtls_state._conf );
    mbedtls_ctr_drbg_free(&_mbedtls_state._ctr_drbg );
}

#endif
