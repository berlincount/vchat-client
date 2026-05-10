/*
 * vchat-client - beta version
 * vchat-connection.c - handling of server connection and tls library dispatch
 *
 * Copyright (C) 2022 Dirk Engling <erdgeist@erdgeist.org>
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

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* For tilde_expand */
#include <readline/readline.h>

#include "vchat-connection.h"
#include "vchat-tls.h"
#include "vchat.h"

/* version of this module */
const char *vchat_cn_version =
    "vchat-connection.c $Id$";

static int serverfd = -1;
unsigned int want_tcp_keepalive = 0;

enum { TLS_ENGINE_UNSET, TLS_ENGINE_OPENSSL, TLS_ENGINE_MBEDTLS };
static int _engine = TLS_ENGINE_UNSET;

#define STAGING_SIZE 16384
#define RECEIVEBUF_SIZE 4096

/* Generic tcp connector, blocking */
static int connect_tcp_socket(const char *server, const char *port) {
  struct addrinfo hints, *res, *res0;
  int s, error;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  error = getaddrinfo(server, port, &hints, &res0);
  if (error)
    return -1;
  s = -1;
  for (res = res0; res; res = res->ai_next) {
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0)
      continue;
    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
      close(s);
      s = -1;
      continue;
    }
    break; /* okay we got one */
  }
  freeaddrinfo(res0);

  if (want_tcp_keepalive) {
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
  }
  return s;
}

/* Return a tilde expanded path in a malloced buffer or NULL */
static char *get_tilde_expanded(confopt opt) {
  char *str = getstroption(opt);
  if (!str)
    return str;
  if (str[0] == '~')
    return tilde_expand(str);
  return strdup(str);
}

/* connects to server */
int vc_connect(const char *server, const char *port) {
  /* vchat connection x509 store */
  vc_x509store_t vc_store;

  /* pointer to tilde-expanded certificate/keyfile-names */
  char *certfile, *cafile;
  int result = -1, want_openssl = !strcmp(getstroption(CF_TLSLIB), "openssl");

  /* Connect to the server */
  serverfd = connect_tcp_socket(server, port);
  if (serverfd < 0) {
    /* inform user */
    snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_CANTCONNECT), server, port);
    writechan(tmpstr);
    return -1;
  }

  if (!getintoption(CF_USESSL))
    return 0;

#ifdef TLS_LIB_OPENSSL
  _engine = TLS_ENGINE_OPENSSL;
#endif
#ifdef TLS_LIB_MBEDTLS
  /* Make mbedtls default unless mbedtls is configured */
  if (!want_openssl || _engine == TLS_ENGINE_UNSET)
    _engine = TLS_ENGINE_MBEDTLS;
#endif

  if (_engine == TLS_ENGINE_UNSET) {
    writecf(FS_ERR, "Error: tls requested but no tls engine compiled in.");
    return -1;
  }

  if (want_openssl && _engine == TLS_ENGINE_MBEDTLS)
    writecf(FS_SERV, "Warning: tls engine openssl requested but openssl engine "
                     "not compiled in. Using mbedtls");

  if (!want_openssl && _engine == TLS_ENGINE_OPENSSL)
    writecf(FS_SERV, "Warning: tls engine mbedtls requested but mbedts engine "
                     "not compiled in. Using openssl");

    /* If SSL is requested, get our ssl-BIO running */
#ifdef TLS_LIB_OPENSSL
  if (_engine == TLS_ENGINE_OPENSSL)
    vc_openssl_init_x509store(&vc_store);
#endif
#ifdef TLS_LIB_MBEDTLS
  if (_engine == TLS_ENGINE_MBEDTLS)
    vc_mbedtls_init_x509store(&vc_store);
#endif

  /* get name of certificate file */
  certfile = get_tilde_expanded(CF_CERTFILE);
  /* do we have a certificate file? */
  if (certfile) {
    /* get name of key file */
    char *keyfile = get_tilde_expanded(CF_KEYFILE);

    vc_x509store_setcertfile(&vc_store, certfile);
    vc_x509store_set_pkeycb(&vc_store, (vc_askpass_cb_t)passprompt);

    /* if we don't have a key file, the key may be in the cert file */
    vc_x509store_setkeyfile(&vc_store, keyfile ? keyfile : certfile);

    free(keyfile);
    free(certfile);
  }

  /* get name of ca file */
  cafile = get_tilde_expanded(CF_CAFILE);
  if (cafile && !access(cafile, F_OK))
    vc_x509store_setcafile(&vc_store, cafile);
  free(cafile);

  /* upgrade our plain BIO to ssl */
#ifdef TLS_LIB_OPENSSL
  if (_engine == TLS_ENGINE_OPENSSL)
    result = vc_openssl_connect(server, serverfd, &vc_store);
#endif
#ifdef TLS_LIB_MBEDTLS
  if (_engine == TLS_ENGINE_MBEDTLS)
    result = vc_mbedtls_connect(server, serverfd, &vc_store);
#endif
  vc_cleanup_x509store(&vc_store);

  if (result) {
    close(serverfd);
    serverfd = -1;
    errno = EIO;
#ifdef TLS_LIB_OPENSSL
    if (_engine == TLS_ENGINE_OPENSSL)
      vc_openssl_cleanup();
#endif
#ifdef TLS_LIB_MBEDTLS
    if (_engine == TLS_ENGINE_MBEDTLS)
      vc_mbedtls_cleanup();
#endif

    _engine = TLS_ENGINE_UNSET;
    snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_CANTCONNECT), server, port);
    writechan(tmpstr);
    return -1;
  }

  /* inform user */
  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_CONNECTED), server, port);
  writechan(tmpstr);

#ifdef DEBUG
  dumpfile = fopen("dumpfile", "a");
#endif

  /* if we didn't fail until now, we've got a connection. */
  return 0;
}

/* Poll for activity on the socket or stdin */
int vc_poll(int timeout_seconds) {
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(0, &readfds);
  if (serverfd != -1)
    FD_SET(serverfd, &readfds);
  struct timeval tv = {timeout_seconds, 0};
  int nfds = (serverfd != -1 ? serverfd : 0) + 1;
  int result = select(nfds, &readfds, NULL, NULL, &tv);
  if (result <= 0)
    return result;
  result = FD_ISSET(0, &readfds) ? 1 : 0;
  if (serverfd != -1)
    result += FD_ISSET(serverfd, &readfds) ? 2 : 0;
  return result;
}

/* disconnect from server */
void vc_disconnect() {
  if (serverfd >= 0) {
    close(serverfd);
    serverfd = -1;
  }
#ifdef TLS_LIB_OPENSSL
  if (_engine == TLS_ENGINE_OPENSSL)
    vc_openssl_cleanup();
#endif
#ifdef TLS_LIB_MBEDTLS
  if (_engine == TLS_ENGINE_MBEDTLS)
    vc_mbedtls_cleanup();
#endif

  _engine = TLS_ENGINE_UNSET;
  loggedin = 0;
}

void vc_sendmessage(const char *msg) {
  static char staging[STAGING_SIZE];
  size_t sent = 0, len = snprintf(staging, sizeof(staging), "%s\r\n", msg);
  /* The wire protocol is line-oriented; \r and \n are the framing.
   * Any embedded \r/\n in 'msg' would let a user smuggle additional
   * protocol commands - e.g. typing "/MSG nick foo\r\n.x bye" inside
   * a private message body would log the user out.  Replace such
   * bytes with spaces in the body portion (everything except the
   * trailing "\r\n" we just appended).  No-op for well-formed input. */
  if (len > 2) {
    size_t body = len - 2;
    for (size_t i = 0; i < body; ++i)
      if (staging[i] == '\r' || staging[i] == '\n')
        staging[i] = ' ';
  }
#ifdef DEBUG
  /* debugging? log network output! */
  fprintf(dumpfile, ">| (%zd) %s\n", len - 2, msg);
#endif

  if (getintoption(CF_USESSL)) {
#ifdef TLS_LIB_OPENSSL
    if (_engine == TLS_ENGINE_OPENSSL)
      sent = vc_openssl_sendmessage(staging, len);
#endif
#ifdef TLS_LIB_MBEDTLS
    if (_engine == TLS_ENGINE_MBEDTLS)
      sent = vc_mbedtls_sendmessage(staging, len);
#endif
  } else
    sent = write(serverfd, staging, len);
  if (sent != len)
    writecf(FS_ERR, "Message sending fuzzy.");
}

/* get data from servers connection */
int vc_receive(void) {
  /* offset in buffer (for linebreaks at packet borders) */
  static char buf[RECEIVEBUF_SIZE];
  static size_t buf_fill;
  char *endmsg;
  size_t freebytes = sizeof(buf) - buf_fill;
  ssize_t bytes = 0;

  /* If the buffer is already full and contains no newline, the server
   * sent a single line longer than RECEIVEBUF_SIZE.  We cannot resync
   * without losing data either way, so report it explicitly and bail
   * instead of looping with a zero-byte read that the EOF branch then
   * misreports as "EOF from server". */
  if (freebytes == 0) {
    snprintf(tmpstr, TMPSTRSIZE,
             "Receive fails: server line longer than %zu bytes.", sizeof(buf));
    snprintf(errstr, ERRSTRSIZE,
             "Receive fails: server line longer than %zu bytes.\n",
             sizeof(buf));
    writecf(FS_ERR, tmpstr);
    return -1;
  }

  if (!getintoption(CF_USESSL))
    bytes = read(serverfd, buf + buf_fill, freebytes);
  else
#ifdef TLS_LIB_OPENSSL
    if (_engine == TLS_ENGINE_OPENSSL)
      bytes = vc_openssl_receivemessage(buf + buf_fill, freebytes);
#endif
#ifdef TLS_LIB_MBEDTLS
   if (_engine == TLS_ENGINE_MBEDTLS)
      bytes = vc_mbedtls_receivemessage(buf + buf_fill, freebytes);
#endif

  /* Our tls functions may require retries with handshakes etc, this is
   * signalled by -2 */
  if (bytes == -2)
    return 0;

  /* Error on the socket read? raise error message, bail out */
  if (bytes == -1) {
    snprintf(tmpstr, TMPSTRSIZE, "Receive fails, %s.", strerror(errno));
    snprintf(errstr, ERRSTRSIZE, "Receive fails, %s.\n", strerror(errno));
    writecf(FS_ERR, tmpstr);
    return -1;
  }

  /* end of file from server? */
  if (bytes == 0) {
    /* inform user, bail out */
    writecf(FS_SERV, "* EOF from server.");
    snprintf(errstr, ERRSTRSIZE, "* EOF from server.\n");
    return -1;
  }

  buf_fill += bytes;

  /* as long as there are lines .. */
  while ((endmsg = memchr(buf, '\n', buf_fill)) != NULL) {
    if (endmsg > buf) {
      /* Zero terminate message, optionally chomp CR */
      endmsg[0] = 0;
      if (endmsg[-1] == '\r')
        endmsg[-1] = 0;
      /* If terminating and chomping left us with a message, give it to line
       * handler */
      if (buf[0]) {
#ifdef DEBUG
        /* debugging? log network input! */
        fprintf(stderr, "<| %s\n", buf);
#endif
        protocol_parsemsg(buf);
      }
    }
    buf_fill -= 1 + endmsg - buf;
    memmove(buf, endmsg + 1, buf_fill);
  }
  return 0;
}

const char *vchat_tls_version_external() {
#ifdef TLS_LIB_OPENSSL
  char *openssl_version = vc_openssl_version();
#else
  char *openssl_version = strdup("not installed");
#endif
#ifdef TLS_LIB_MBEDTLS
  char *mbedtls_version = vc_mbedtls_version();
#else
  char *mbedtls_version = strdup("not installed");
#endif

  snprintf(tmpstr, TMPSTRSIZE,
           "Module plain v0.1\nModule openssl version: %s\nModule mbedtls "
           "version: %s",
           openssl_version, mbedtls_version);

  free(openssl_version);
  free(mbedtls_version);
  return tmpstr;
}
