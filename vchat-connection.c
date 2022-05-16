/*
 * vchat-client - alpha version
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

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* For tilde_expand */
#include <readline/readline.h>

#include "vchat.h"
#include "vchat-connection.h"
#include "vchat-tls.h"

static int serverfd = -1;
unsigned int want_tcp_keepalive = 0;

/* Generic tcp connector, blocking */
static int connect_tcp_socket( const char *server, const char *port ) {
  struct addrinfo hints, *res, *res0;
  int s, error;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  error = getaddrinfo( server, port, &hints, &res0 );
  if (error) return -1;
  s = -1;
  for (res = res0; res; res = res->ai_next) {
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) continue;
    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
      close(s);
      s = -1;
      continue;
    }
    break;  /* okay we got one */
  }
  freeaddrinfo(res0);

  if (want_tcp_keepalive) {
    int one=1;
    setsockopt(s,SOL_SOCKET,SO_KEEPALIVE,&one,sizeof(one));
  }
  return s;
}

/* Return a tilde expanded path in a malloced buffer or NULL */
static char *get_tilde_expanded(confopt opt) {
  char *str = getstroption (opt);
  if (!str)
    return str;
  if (str[0] == '~')
    return tilde_expand (str);
  return strdup(str);
}

/* connects to server */
int
vc_connect (const char *server, const char *port)
{
  /* vchat connection x509 store */
  vc_x509store_t *vc_store;

  /* pointer to tilde-expanded certificate/keyfile-names */
  char *certfile, *cafile;

  /* Connect to the server */
  serverfd = connect_tcp_socket( server, port );
  if( serverfd < 0 ) {
    /* inform user */
    snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_CANTCONNECT), server, port );
    writechan (tmpstr);
    return -1;
  }

  if (!getintoption(CF_USESSL))
    return 0;

  /* If SSL is requested, get our ssl-BIO running */
  vc_store = vc_init_x509store();
  if( !vc_store ) {
      snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_ERR), "Out of memory" );
      writechan (tmpstr);
      return -1;
  }

  /* get name of certificate file */
  certfile = get_tilde_expanded (CF_CERTFILE);
  /* do we have a certificate file? */
  if (certfile) {
    /* get name of key file */
    char *keyfile = get_tilde_expanded (CF_KEYFILE);

    vc_x509store_setflags(vc_store, VC_X509S_USE_CERTIFICATE);
    vc_x509store_setcertfile(vc_store, certfile);

    vc_x509store_set_pkeycb(vc_store, (vc_askpass_cb_t)passprompt);
    /* if we don't have a key file, the key may be in the cert file */
    vc_x509store_setkeyfile(vc_store, keyfile ? keyfile : certfile);

    free(keyfile);
    free(certfile);
  }

  vc_x509store_setflags(vc_store, VC_X509S_SSL_VERIFY_PEER);

  /* get name of ca file */
  cafile = get_tilde_expanded (CF_CAFILE);
  if (cafile && !access(cafile, F_OK)) {
    vc_x509store_setflags(vc_store, VC_X509S_NODEF_CAFILE);
    vc_x509store_setcafile(vc_store, cafile);
  }
  free(cafile);

  /* upgrade our plain BIO to ssl */
  int result = vc_tls_connect( serverfd, vc_store );
  vc_cleanup_x509store(vc_store);

  if (result) {
    close(serverfd);
    serverfd = -1;
    errno = EIO;
    snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_CANTCONNECT), server, port );
    writechan (tmpstr);
    return -1;
  }

  /* inform user */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_CONNECTED), server, port);
  writechan (tmpstr);

#ifdef DEBUG
  dumpfile = fopen( "dumpfile", "a");
#endif

  /* if we didn't fail until now, we've got a connection. */
  return 0;
}

/* Poll for activity on the socket or stdin */
int vc_poll (int timeout_seconds) {
  fd_set readfds;
  FD_ZERO (&readfds);
  FD_SET (0, &readfds);
  if (serverfd != -1)
    FD_SET (serverfd, &readfds);
  struct timeval tv = { timeout_seconds, 0};
  int result = select (serverfd + 2, &readfds, NULL, NULL, &tv);
  if (result <= 0)
    return result;
  result = FD_ISSET (0, &readfds) ? 1 : 0;
  if (serverfd != -1)
    result += FD_ISSET (serverfd, &readfds) ? 2 : 0;
  return result;
}

/* disconnect from server */
void
vc_disconnect () {
  if (serverfd > 0) {
    close(serverfd);
    serverfd = -1;
  }
  vc_tls_cleanup();
  loggedin = 0;
}

void
vc_sendmessage (const char *msg)
{
#ifdef DEBUG
  /* debugging? log network output! */
  fprintf (dumpfile, ">| %s (%zd)\n", msg, strlen(msg));
#endif

  if (getintoption(CF_USESSL)) {
    /* send data to server */
    if (vc_tls_sendmessage (msg, strlen (msg)) != strlen (msg))
      writecf (FS_ERR,"Message sending fuzzy.");

    /* send line termination to server */
    if (vc_tls_sendmessage ("\r\n", 2) != 2)
      writecf (FS_ERR,"Message sending fuzzy.");
  } else {
    /* send data to server */
    if (write (serverfd, msg, strlen (msg)) != strlen (msg))
      writecf (FS_ERR,"Message sending fuzzy.");

    /* send line termination to server */
    if (write (serverfd, "\r\n", 2) != 2)
      writecf (FS_ERR,"Message sending fuzzy.");
  }
}

ssize_t
vc_receivemessage (char *buffer, size_t size) {
  if (getintoption(CF_USESSL))
    return vc_tls_receivemessage (buffer, size);
  else
    return read(serverfd, buffer, size);
}
