/*
 * vchat-client - alpha version
 * vchat-protocol.c - handling of server connection & messages
 *
 * Copyright (C) 2001 Andreas Kotes <count@flatline.de>
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

/* general includes */
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <readline/readline.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* local includes */
#include "vchat.h"

/* version of this module */
unsigned char *vchat_io_version = "$Id$";

/* externally used variables */
int serverfd = -1;
unsigned int usingcert = 1;

/* locally global variables */
/* SSL-connection */
static SSL *sslconn = NULL;

/* declaration of an OpenSSL function which isn't exported by the includes,
 * but by the library. we use it to set the accepted list of ciphers */
STACK_OF(SSL_CIPHER) * ssl_create_cipher_list (const SSL_METHOD * meth, STACK_OF (SSL_CIPHER) ** pref, STACK_OF (SSL_CIPHER) ** sorted, const unsigned char *rule_str);

static unsigned char *sslpubkey = NULL; /* servers public key extracted from X.509 certificate */
static int sslpubkeybits = 0;  /* length of server public key */

/* declaration of local helper functions */
static void usersignon (unsigned char *);
static void usersignoff (unsigned char *);
static void usernickchange (unsigned char *);
static void userjoin (unsigned char *);
static void userleave (unsigned char *);                                                                                                                                                                         
static void receivenicks (unsigned char *message);
static void justloggedin (unsigned char *message);
static void nickerr (unsigned char *message);
static void login (unsigned char *message);
static void anonlogin (unsigned char *message);
static void topicinfo (unsigned char *message);
static void pubaction (unsigned char *message);
static void idleprompt (unsigned char *message);
static void topicchange (unsigned char *message);
static void pmnotsent (unsigned char *message);

/* declaration of server message array */
#include "vchat-messages.h"

/* status-variable from vchat-client.c
 * eventloop is done as long as this is true */
extern int status;

int usessl = 1;

/* connects to server */
int
vcconnect (unsigned char *server, unsigned int port)
{
  /* used for tilde expansion of cert & key filenames */
  unsigned char *tildex = NULL;
  /* buffer for X.509 subject of server certificate */
  unsigned char subjbuf[256];
  /* variables used to split the subject */
  unsigned char *subjv = NULL;
  unsigned char *subjn = NULL;
  unsigned char *subjc = NULL;
  unsigned char *subjh = NULL;
  /* pointer to key in certificate */
  EVP_PKEY *certpubkey = NULL;
  /* temporary result */
  int result;
  /* servers hostentry */
  struct hostent *serverhe;
  /* servers sockaddr */
  struct sockaddr_in serversi;
  /* SSL-context */
  SSL_CTX *sslctx = NULL;
  /* SSL server certificate */
  X509 *sslserv = NULL;
  /* SSL method function    */
  SSL_METHOD *sslmeth = NULL;

  /* pointer to tilde-expanded certificate/keyfile-names */
  unsigned char *certfile = NULL, *keyfile = NULL;

  /* variable for verify return */
  long verify;

  /* get host-entry for server */
  if ((serverhe = gethostbyname (server)) == NULL)
    return 0;

  /* get socket */
  if ((serverfd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    return 0;

  /* initialize datastructure for connect */
  serversi.sin_family = AF_INET;
  serversi.sin_port = htons (port);
  serversi.sin_addr = *((struct in_addr *) serverhe->h_addr);
  memset (&(serversi.sin_zero), 0, 8);

  /* attempt connect */
  if (connect (serverfd, (struct sockaddr *) &serversi, sizeof (struct sockaddr)) == -1)
    return 0;

  /* inform user */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_CONNECTED), server, port);
  writechan (tmpstr);

  usessl = getintoption(CF_USESSL);

  /* do we want to use SSL? */
  if (usessl)
    {
      /* set ssl method -> SSLv2, SSLv3 & TLSv1 client */
      sslmeth = SSLv23_client_method ();
      /* generate new SSL context */
      sslctx = SSL_CTX_new (sslmeth);

      /* set passphrase-callback to own function from vchat-ui.c */
      SSL_CTX_set_default_passwd_cb (sslctx, passprompt);

      /* set our list of accepted ciphers */
      ssl_create_cipher_list (sslctx->method, &(sslctx->cipher_list), &(sslctx->cipher_list_by_id), getstroption (CF_CIPHERSUITE));

      /* get name of certificate file */
      certfile = getstroption (CF_CERTFILE);

      /* do we have a certificate file? */
      if (certfile)
        {
          /* does the filename start with a tilde? expand it! */
          if (certfile[0] == '~')
	    tildex = tilde_expand (certfile);
          else
	    tildex = certfile;

          if (usingcert) {
             /* try to load certificate */
             result = SSL_CTX_use_certificate_file (sslctx, tildex, SSL_FILETYPE_PEM);
             if (!result)
	       {
                 /* failed, inform user */
	         snprintf (tmpstr, TMPSTRSIZE, "!! Loading user certificate fails: %s", ERR_error_string (ERR_get_error (), NULL));
	         writecf (FS_ERR,tmpstr);
	       }
             else
	       {
                 /* get name of key file */
	         keyfile = getstroption (CF_KEYFILE);

                 /* if we don't have a key file, the key may be in the cert file */
	         if (!keyfile)
	            keyfile = certfile;

                 /* does the filename start with a tilde? expand it! */
	         if (keyfile[0] == '~')
	            tildex = tilde_expand (keyfile);
	         else
	            tildex = keyfile;

                 /* try to load key (automatically asks for passphrase, if encrypted */
                 result = SSL_CTX_use_PrivateKey_file (sslctx, tildex, SSL_FILETYPE_PEM);
	         if (!result)
	           {
                     /* failed, inform user */
	             snprintf (tmpstr, TMPSTRSIZE, "!! Loading private key fails: %s", ERR_error_string (ERR_get_error (), NULL));
	             writecf (FS_ERR,tmpstr);
	           }
	          else
	           {
                     /* check if OpenSSL thinks key & cert belong together */
	             result = SSL_CTX_check_private_key (sslctx);
	             if (!result)
		       {
                         /* they don't, inform user */
		         snprintf (tmpstr, TMPSTRSIZE, "!! Verifying key and certificate fails: %s", ERR_error_string (ERR_get_error (), NULL));
		         writecf (FS_ERR,tmpstr);
		       }
	           }
	       }
          }
        }

      /* don't worry to much about servers X.509 certificate chain */
      SSL_CTX_set_verify_depth (sslctx, 0);

      /* debug massage about verify mode */
      snprintf (tmpstr, TMPSTRSIZE, "# Connecting with verify depth %d in mode %d", SSL_CTX_get_verify_depth (sslctx), SSL_CTX_get_verify_mode (sslctx));
      writecf (FS_DBG,tmpstr);

      /* generate new SSL connection object and associate
       * filedescriptor of server connection */
      sslconn = SSL_new (sslctx);
      SSL_set_fd (sslconn, serverfd);

      /* try SSL handshake */
      if (SSL_connect (sslconn) <= 0)
	{
          /* no SSL connection possible */
	  snprintf (tmpstr, TMPSTRSIZE, "!! SSL Connect fails: %s", ERR_error_string (ERR_get_error (), NULL));
	  writecf (FS_ERR,tmpstr);
	  return 0;
	}

      /* debug message about used symmetric cipher */
      snprintf (tmpstr, TMPSTRSIZE, "# SSL connection uses %s cipher (%d bits)", SSL_get_cipher_name (sslconn), SSL_get_cipher_bits (sslconn, NULL));
      writecf (FS_DBG,tmpstr);

      /* if we can't get the servers certificate something is damn wrong */
      if (!(sslserv = SSL_get_peer_certificate (sslconn)))
	return 0;

      /* ugly dump of server certificate */
      /* TODO: make this happen elsewhere, and preferably only when user wants
       * or a new key needs to be added to the known_hosts */
      writecf (FS_DBG,"# SSL Server information:");
      /* copy X.509 to local buffer */
      strncpy (subjbuf, sslserv->name, 256);
      /* split a subject line and print the fullname/value pairs */
      subjv = &subjbuf[1];
      while (subjv)
	{
	  subjc = strchr (subjv, '=');
	  subjc[0] = '\0';
	  subjc++;
          /* yeah, ugly */
	  if (!strcasecmp ("C", subjv))
	    {
	      subjn = "Country     ";
	    }
	  else if (!strcasecmp ("ST", subjv))
	    {
	      subjn = "State       ";
	    }
	  else if (!strcasecmp ("L", subjv))
	    {
	      subjn = "Location    ";
	    }
	  else if (!strcasecmp ("O", subjv))
	    {
	      subjn = "Organization";
	    }
	  else if (!strcasecmp ("OU", subjv))
	    {
	      subjn = "Organiz.unit";
	    }
	  else if (!strcasecmp ("CN", subjv))
	    {
	      subjn = "Common name ";
	      subjh = subjc;
	    }
	  else if (!strcasecmp ("Email", subjv))
	    {
	      subjn = "Emailaddress";
	    }
	  else
	    {
	      subjn = "UNKNOWN     ";
	    }
	  subjv = strchr (subjc, '/');
	  if (subjv)
	    {
	      subjv[0] = '\0';
	      subjv++;
	    }
          /* print value pair */
	  snprintf (tmpstr, TMPSTRSIZE, "#   %s: %s", subjn, subjc);
	  writecf (FS_DBG,tmpstr);
	}

      /* check if verifying the server's certificate yields any errors */
      verify = SSL_get_verify_result (sslconn);
      if (verify)
	{
          /* it does - yield a warning to the user */
	  snprintf (tmpstr, TMPSTRSIZE, "!! Certificate verification fails: %s", X509_verify_cert_error_string (verify));
	  writecf (FS_ERR,tmpstr);
	}

      /* check if servers name in certificate matches the hostname we connected to */
      if (subjh)
	if (strcasecmp (server, subjh))
	  {
            /* it doesn't - yield a warning and show difference */
	    writecf (FS_ERR,"!! Server name does not match name in presented certificate!");
	    snprintf (tmpstr, TMPSTRSIZE, "!! '%s' != '%s'", server, subjh);
	    writecf (FS_ERR,tmpstr);
	  }

      /* try to get the servers public key */
      certpubkey = X509_get_pubkey (sslserv);
      if (certpubkey == NULL)
	{
          /* huh, we can't? */
	  writecf (FS_ERR,"!! Can't get the public key associated to the certificate");
	}
      /* check what type of key we've got here */
      else if (certpubkey->type == EVP_PKEY_RSA)
	{
          /* RSA key, convert bignum values from OpenSSL's structures to
           * something readable */
	  sslpubkey = BN_bn2hex (certpubkey->pkey.rsa->n);
	  sslpubkeybits = BN_num_bits (certpubkey->pkey.rsa->n);
          /* dump keylength and hexstring of servers key to user */
	  snprintf (tmpstr, TMPSTRSIZE, "# RSA public key%s: %d %s", (certpubkey->pkey.rsa-> d) ? " (private key available)" : "", sslpubkeybits, sslpubkey);
	  writecf (FS_DBG,tmpstr);
          /* TODO: known_hosts check here ... */
	}
      else if (certpubkey->type == EVP_PKEY_DSA)
	{
          /* Can't handle (and didn't encounter) DSA keys */
	  writecf (FS_ERR,"# DSA Public Key (output currently not supported)");
          /* TODO: known_hosts check here ... */
	}
      else
	{
	  writecf (FS_ERR,"# Public Key type not supported");
          /* TODO: fail known_hosts check ... */
	}
    }

  /* if we didn't fail until now, we've got a connection. */
  return 1;
}

/* disconnect from server */
void
vcdisconnect ()
{
  close (serverfd);
  serverfd = -1;
}

/* handle a pm not sent error
 *  format: 412 %s */
static void
pmnotsent (unsigned char *message)
{
  while(*message && *message!=' ') message++;
  snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_ERR),message+1);
  writepriv( tmpstr);

}

/* parse and handle an action string
 *  format: 118 %s %s
 *    vars: %s nick
 *          %s action */
static void
pubaction (unsigned char *message)
{
  unsigned char *nick = NULL, *action = NULL;
  nick = strchr (message, ' ');
  nick[0] = '\0';
  nick++;

  action = strchr (nick, ' ');
  action[0] = '\0';
  action++;

  snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_PUBACTION),nick,action);
  writechan (tmpstr);
}

/* parse and handle an idle message
 *  format: 305
 *    vars: %s message */
static void
idleprompt (unsigned char *message)
{
  unsigned char *msg = NULL;
  msg = strchr (message, ' ');
  msg[0] = '\0';
  msg++;

  snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_IDLE),msg);
  writechan (tmpstr);
}

/* parse and handle a topic information string
 *  format: 115 %d %s
 *    vars: %d chan  - channel number
 *          %s topic - topic  */
static void
topicinfo (unsigned char *message)
{
  unsigned char *channel = NULL, *topic = NULL;
  int tmpchan = 0;
  
  /* search start of channel number */
  channel = strchr (message, ' ');
  channel++;

  /* search start of topic and terminate channel number */
  topic = strchr (channel, ' ');
  topic[0] = '\0';
  topic++;

  /* convert channel number to integer */
  tmpchan = atoi (channel);

  if (tmpchan == chan) {
     /* show change in topic window */
     if (strlen(topic))
        snprintf (topicstr, TOPICSTRSIZE, getformatstr(FS_TOPICW), chan, topic);
      else
        snprintf (topicstr, TOPICSTRSIZE, getformatstr(FS_NOTOPICW), chan);
     topicline(NULL);
  }

  /* announce change in channel window */
  if (strlen(topic))
     snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_TOPIC), tmpchan, topic);
   else
     snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_NOTOPIC), tmpchan);
  writechan (tmpstr);
}

/* parse and handle a topic change string
 *  format: 114 %s changes topic to '%s'
 *    vars: %s nick
 *          %s topic */
static void
topicchange (unsigned char *message)
{
  unsigned char *nick = NULL, *topic = NULL;
  int len;

  /* search start of nickname */
  nick = strchr (message, ' ');
  nick++;

  /* search start of message before topic, terminate nick */
  topic = strchr (nick, ' ');
  topic[0] = '\0';
  topic++;

  /* search start of real topic and terminate channel number */
  topic = strchr (topic, '\'');
  topic[0] = '\0';
  topic++;

  /* remove ending '\'', if there */
  len = strlen (topic);
  if (topic[len-1] == '\'')
    topic[len-1] = '\0';

  /* show change in topic window */
  snprintf (topicstr, TOPICSTRSIZE, getformatstr(FS_TOPICW), chan, topic);
  topicline(NULL);

  /* announce change in channel window */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_CHGTOPIC), nick, topic);
  writechan (tmpstr);
}

/* parse and handle a login message
 *  format: 212 %s %s
 *    vars: %s str1 - nick used to login
 *          %s str2 - servers message */
static void
justloggedin (unsigned char *message)
{
  unsigned char *str1 = NULL, *str2 = NULL;
  /* search start of nickname */
  str1 = strchr (message, ' ');
  str1++;

  /* search start of message, terminate nick */
  str2 = strchr (str1, ' ');
  str2[0] = '\0';
  str2++;

  /* if we have a new nick, store it */
  if (!nick || strcasecmp (nick, str1))
     setstroption(CF_NICK,str1);

  /* show change in console window */
  snprintf (consolestr, CONSOLESTRSIZE, getformatstr(FS_CONSOLE), nick, getstroption (CF_SERVERHOST), getintoption (CF_SERVERPORT));
  consoleline (NULL);

  /* announce login as servermessage */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_SIGNON), nick, str2);
  writechan (tmpstr);

  /* we're not logged in, change status and request nicks */
  if (!loggedin)
    {
      networkoutput (".S");
      loggedin = 1;
    }
}

/* this user joins a different channel */
void
ownjoin (int channel)
{
  /* change global channel info */
  chan = channel;
  networkoutput(".t");
  snprintf(tmpstr, TMPSTRSIZE, ".S %d",chan);
  networkoutput(tmpstr);
}

/* this user leaves a channel */
void
ownleave (int channel)
{
  /* change global channel info */
  chan = 0;
}

/* this user changes his nick */
void
ownnickchange (unsigned char *newnick)
{
  /* free old nick, store copy of new nick */
  setstroption(CF_NICK,newnick);

  /* show change in console window */
  snprintf (consolestr, CONSOLESTRSIZE, getformatstr(FS_CONSOLE), nick, getstroption (CF_SERVERHOST), getintoption (CF_SERVERPORT));
  consoleline (NULL);
}

/* parse and handle a nick error message
 *  format: 401 %s
 *          403 %s
 *          415 %s
 *    vars: %s - server message */
static void
nickerr (unsigned char *message)
{
  unsigned char *helpkiller = NULL;
  /* mutate message for output */
  message[2] = '!';
  /* help information found? remove it. */
  if ((helpkiller = strstr (message, " Type .h for help")))
    helpkiller[0] = '\0';
  /* nickchange not done? eliminate message */
  if (loggedin && (helpkiller = strstr (message, " - Nick not changed")))
    helpkiller[0] = '\0';
  /* show errormessage */
  writecf (FS_ERR,&message[2]);

  /* not logged in? insist on getting a new nick */
  if (!loggedin)
    {
      /* free bogus nick */
      setstroption(CF_NICK,NULL);
      /* get new nick via vchat-ui.c */
      nickprompt ();
      
      /* form login message and send it to server */
      snprintf (tmpstr, TMPSTRSIZE, ".l %s %s %d", nick, getstroption (CF_FROM), getintoption (CF_CHANNEL));
      networkoutput (tmpstr);
    }
}

/* parse and handle a registered nick information
 *  format: 120 %s %s
 *    vars: %s      - this users registered nick
 *          %s msg  - server message */
static void
login (unsigned char *message)
{
  unsigned char *msg = NULL;

  /* mutate message for output */
  message[2] = '*';
  /* show message to user */
  writecf (FS_SERV,&message[2]);

  /* we don't know our nick? */
  if (!nick)
    {
      /* find message after nick */
      msg = strchr (&message[4], ' ');
      if (msg)
	{
          /* terminate string before message and copy nick */
	  msg[0] = '\0';
	  setstroption(CF_NICK,&message[4]);
	}
      else
	{
          /* no string in servers message (huh?), ask user for nick */
	  nickprompt ();
	}
    }
  
  /* form login message and send it to server */
  snprintf (tmpstr, TMPSTRSIZE, ".l %s %s %d", nick, getstroption (CF_FROM), getintoption (CF_CHANNEL));
  networkoutput (tmpstr);
}

/* parse and handle anon login request
 *  format: 121 %s
 *    vars: %s - server message */
static void
anonlogin (unsigned char *message)
{
  /* mutate message for output */
  message[2] = '*';
  /* show message to user */
  writecf (FS_SERV,&message[2]);

  /* we don't know our nick? ask for it! */
  if (!nick)
    nickprompt ();

  /* form login message and send it to server */
  snprintf (tmpstr, TMPSTRSIZE, ".l %s %s %d", nick, getstroption (CF_FROM), getintoption (CF_CHANNEL));
  networkoutput (tmpstr);
}

/* parse and handle list of nicks (from '.S')
 *  format: 119 %s ..
 *    vars: %s nick - a users nick */
static void
receivenicks (unsigned char *message)
{
  unsigned char *str1 = NULL, *str2 = NULL;
  int mychan = 0;
  void (*ul_myfunc)(unsigned char*,int);

  /* show message to user */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_USONLINE), &message[4]);
  writechan (tmpstr);

  /* search for channelnumber */
  str1 = strchr (message, ' ');
  str1++;
  if (str1[0] == '*') {
      if (nicks) return;
      ul_myfunc = ul_add;
      str1++;
  } else {
      str2 = str1;
      str1 = strchr(str2,' ');
      str1[0] = '\0';
      mychan = atoi(str2);
      ul_myfunc = ul_moveuser;
  }
  str1++;

  /* while user .. */
  while (str1)
    {
      /* search next user */
      str2 = strchr (str1, ' ');
      /* there is another user? terminate this one */
      if (str2) {
	str2[0] = '\0';
        str2++;
      }

      /* add this user via vchat-user.c */
      ul_myfunc (str1,mychan);

      /* next user .. */
      str1 = str2;
    }
}

/* parse and handle a login message
 *  format: 211 %s %s
 *    vars: %s nick - who logged on
 *          %s msg  - servers message */
static void
usersignon (unsigned char *message)
{
  unsigned char *nick = NULL, *msg = NULL;
  /* search start of nickname */
  nick = strchr (message, ' ');
  nick++;

  /* search start of message, terminate nick */
  msg = strchr (nick, ' ');
  msg[0] = '\0';
  msg++;

  /* add this user via vchat-user.c */
  ul_add (nick, 0);

  /* show message to user */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_SIGNON), nick, msg);
  writechan (tmpstr);
}

/* parse and handle a logoff message
 *  format: 221 %s %s
 *    vars: %s nick - who logged off
 *          %s msg  - servers message */
static void
usersignoff (unsigned char *message)
{
  unsigned char *nick = NULL, *msg = NULL;
  /* search start of nickname */
  nick = strchr (message, ' ');
  nick++;

  /* search start of message, terminate nick */
  msg = strchr (nick, ' ');
  msg[0] = '\0';
  msg++;

  /* delete this user via vchat-user.c */
  ul_del (nick, 0);

  /* show message to user */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_SIGNOFF), nick, msg);
  writechan (tmpstr);
}

/* parse and handle a join message
 *  format: 232 %s %s %d
 *    vars: %s nick - who joined
 *          %s msg  - servers message
 *          %d chan - channel joined */
static void
userjoin (unsigned char *message)
{
  unsigned char *nick = NULL, *msg = NULL, *channel = NULL;
  int chan = 0;

  /* search start of nickname */
  nick = strchr (message, ' ');
  nick++;

  /* search start of message, terminate nick */
  msg = strchr (nick, ' ');
  msg[0] = '\0';
  msg++;

  /* search start of channel, terminate message */
  channel = strrchr (msg, ' ');
  channel[0] = '\0';
  channel++;

  /* convert channel to integer */
  chan = atoi (channel);

  /* notice channel join via vchat-user.c */
  ul_join (nick, chan);

  /* show message to user */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_JOIN), nick, msg, chan);
  writechan (tmpstr);
}

/* parse and handle a leave message
 *  format: 231 %s %s %d
 *    vars: %s nick - who left
 *          %s msg  - servers message
 *          %d chan - channel joined */
static void
userleave (unsigned char *message)
{
  unsigned char *nick = NULL, *msg = NULL, *channel = NULL;
  int chan = 0;

  /* search start of nickname */
  nick = strchr (message, ' ');
  nick++;

  /* search start of message, terminate nick */
  msg = strchr (nick, ' ');
  msg[0] = '\0';
  msg++;

  /* convert channel to integer */
  channel = strrchr (msg, ' ');
  channel[0] = '\0';
  channel++;

  /* convert channel to integer */
  chan = atoi (channel);

  /* notice channel leave via vchat-user.c */
  ul_leave (nick, chan);

  /* show message to user */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_LEAVE), nick, msg, chan);
  writechan (tmpstr);
}

/* parse and handle a nickchange message
 *  format: 241 %s %s %s
 *    vars: %s oldnick - users old nick
 *          %s newnick - users new nick
 *          %s msg     - server message */
static void
usernickchange (unsigned char *message)
{
  unsigned char *oldnick = NULL, *newnick = NULL, *msg = NULL;

  /* search start of old nickname */
  oldnick = strchr (message, ' ');
  oldnick++;

  /* search start of new nickname, terminate old nick */
  newnick = strchr (oldnick, ' ');
  newnick[0] = '\0';
  newnick++;

  /* search start of message, terminate new nick */
  msg = strchr (newnick, ' ');
  msg[0] = '\0';
  msg++;

  /* notice nickchange via vchat-user.c */
  ul_nickchange (oldnick, newnick);

  /* show message to user */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_NICKCHANGE), oldnick, newnick, msg);
  writechan (tmpstr);
}

/* handle received message from server */
static void
parsemsg (unsigned char *message)
{
  unsigned char *str1, *str2;
  int i;
  /* message to short or starts with '<'? must be channel */
  if (message[0] == '<')
  {
    str1 = &message[1];
    str2 = strchr(str1,'>');
    str2[0] = '\0';
    str2++;
    if (str2[0] == ' ') str2++;
    if (!strncasecmp(nick,str2,strlen(nick)))
       snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_MYPUBMSG),str1,str2);
    else
       snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_RXPUBMSG),str1,str2);
    writechan (tmpstr);
  }
  else if (message[0] == '[')
  {
    str1 = &message[1];
    str2 = strchr(str1,']');
    str2[0] = '\0';
    str2++;
    if (str2[0] == ' ') str2++;
    if (!strncasecmp(nick,str2,strlen(nick)))
       snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_MYPUBURL),str1,str2);
    else
       snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_RXPUBURL),str1,str2);
    writechan (tmpstr);
  }
  /* message starts with '*'? must be private */
  else if (message[0] == '*')
  {
    str1 = &message[1];
    str2 = strchr(str1,'*');
    str2[0] = '\0';
    str2++;
    if (str2[0] == ' ') str2++;
    snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_RXPRIVMSG),str1,str2);
    writepriv (tmpstr);
    ul_msgfrom(str1);
  }
  /* message starts with a number? must be a servermessage */
  else if ((message[0] >= '0') && (message[0] <= '9'))
    {
      /* walk server message array */
      for (i = 0; servermessages[i].id[0]; i++)
	{
          /* is this the message? */
	  if (!(strncmp (servermessages[i].id, message, 3)))
	    {
              /* scripting hook available - call it */
	      if (servermessages[i].hook)
		servermessages[i].hook (message);
              /* function available - call it */
	      else if (servermessages[i].funct)
		servermessages[i].funct (message);
              /* no function available, but known - give output */
	      else
		{
                  /* remove continutation mark */
		  if (message[3] == '-')
		    message[3] = ' ';

                  /* mutate message for display */
		  message[2] = '*';
                  /* giveout message by type */
		  switch (servermessages[i].type)
		    {
		    case SM_IGNORE:
		      break;
		    case SM_INFO:
                      /* change marker and send as servermessage */
		      message[2] = '#';
		      writecf (FS_SERV,&message[2]);
		      break;
		    case SM_USERINFO:
                      /* keep marker and send as servermessage */
		      writecf (FS_SERV,&message[2]);
		      break;
		    case SM_CHANNEL:
                      /* keep marker and send as channelmessage */
		      writechan (&message[2]);
		      break;
		    case SM_ERROR:
                      /* change marker and send as errormessage */
		      message[2] = '!';
		      writecf (FS_ERR,&message[2]);
		      break;
		    default:
                      /* fallback: keep marker and send as servermessage */
		      writecf (FS_SERV,&message[2]);
		    }
		}
	      return;
	    }
	}
      /* message not in list, raise errormessage */
      snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_UNKNOWNMSG), message);
      writecf (FS_ERR,tmpstr);
    }
  else
    {
      /* message neither public, private or server, raise errormessage */
      snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_BOGUSMSG), message);
      writecf (FS_ERR,tmpstr);
    }
}

/* offset in buffer (for linebreaks at packet borders) */
static int bufoff = 0;

/* get data from servers filedescriptor */
void
networkinput (void)
{
  int bytes;
  unsigned char *tmp = NULL;
#define BUFSIZE 4096
  unsigned char buf[BUFSIZE];     /* data buffer */
  unsigned char *ltmp = buf;
  buf[BUFSIZE-1] = '\0'; /* sanity stop */

  /* check if we use ssl or if we don't and receive data at offset */
  if (!usessl)
    bytes = recv (serverfd, &buf[bufoff], BUFSIZE-1 - bufoff, 0);
  else
    bytes = SSL_read (sslconn, &buf[bufoff], BUFSIZE-1 - bufoff);

  /* no bytes transferred? raise error message, bail out */
  if (bytes < 0)
    {
      snprintf (tmpstr, TMPSTRSIZE, "Receive fails, %s.", sys_errlist[errno]);
      strncpy(errstr,tmpstr,TMPSTRSIZE-2);
      errstr[TMPSTRSIZE-2] = '\0';
      strcat(errstr,"\n");
      writecf (FS_ERR,tmpstr);
      status = 0;
    }
  /* end of file from server? */
  else if (bytes == 0)
    {
      /* inform user, bail out */
      writecf (FS_SERV,"* EOF from server");
      strncpy(errstr,"* EOF from server",TMPSTRSIZE-2);
      errstr[TMPSTRSIZE-2] = '\0';
      strcat(errstr,"\n");
      status = 0;
    }
  else
    {
      /* terminate message */
      buf[bytes + bufoff] = '\0';
      /* as long as there are lines .. */
      while ((tmp = strchr (ltmp, '\n')) != NULL)
	{
          /* did the server send CR+LF instead of LF with the last line? */
	  if (tmp[-1] == '\r')
	    tmp[-1] = '\0';

          /* remove newline from previous message, advance pointer of next
           * message */
	  tmp[0] = '\0';
	  tmp++;

          /* we have a last message? give away to line handler! */
	  if (ltmp[0])
            {
#ifdef DEBUG
              /* debugging? log network input! */
              fprintf (stderr, "<| %s\n", ltmp);
#endif
	      parsemsg (ltmp);
            }

          /* move line along .. */
	  ltmp = tmp;
	}
      /* buffer exhausted, move partial line to start of buffer and go on .. */
      bufoff = (bytes+bufoff) - (ltmp-buf);
      if (bufoff > 0)
        memmove (buf, ltmp, bufoff);
      else
        bufoff = 0;
    }
}

void
networkoutput (unsigned char *msg)
{
#ifdef DEBUG
  /* debugging? log network output! */
  fprintf (stderr, ">| %s\n", msg);
#endif

  /* TODO: err .. rework this (blocking) code */

  /* check if we use ssl or if we don't and send data to server */
  if (!usessl) {
      if (send (serverfd, msg, strlen (msg), 0) != strlen (msg)) {
	  writecf (FS_ERR,"Message sending fuzzy.");
	}
    } else if (SSL_write (sslconn, msg, strlen (msg)) != strlen (msg)) {
      writecf (FS_ERR,"Message sending fuzzy.");
    }

  /* check if we use ssl or if we don't and send line termination to server */
  if (!usessl) {
      if (send (serverfd, "\r\n", 2, 0) != 2) {
	  writecf (FS_ERR,"Message sending fuzzy!");
	}
    } else if (SSL_write (sslconn, "\r\n", 2) != 2) {
      writecf (FS_ERR,"Message sending fuzzy.");
    }
}
