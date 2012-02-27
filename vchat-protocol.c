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
#include <locale.h>
#include <langinfo.h>

/* local includes */
#include "vchat.h"
#include "vchat-user.h"
#include "vchat-ssl.h"

/* version of this module */
char *vchat_io_version = "$Id$";

/* externally used variables */
int serverfd = -1;

/* locally global variables */
/* our connection BIO */
static BIO *server_conn = NULL;

/* declaration of local helper functions */
static void usersignon (char *);
static void usersignoff (char *);
static void usernickchange (char *);
static void userjoin (char *);
static void userleave (char *);
static void receivenicks (char *message);
static void justloggedin (char *message);
static void nickerr (char *message);
static void login (char *message);
static void anonlogin (char *message);
static void topicinfo (char *message);
static void pubaction (char *message);
static void pubthoughts (char *message);
static void serverlogin (char *message);
static void idleprompt (char *message);
static void topicchange (char *message);
static void pmnotsent (char *message);

/* declaration of server message array */
#include "vchat-messages.h"

/* status-variable from vchat-client.c
 * eventloop is done as long as this is true */
extern int status;
char *encoding;

static int connect_socket( char *server, char *port ) {
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
  return s;
}

/* connects to server */
int
vcconnect (char *server, char *port)
{
  /* used for tilde expansion of cert & key filenames */
  char *tildex = NULL;

  /* vchat connection x509 store */
  vc_x509store_t vc_store;

  /* pointer to tilde-expanded certificate/keyfile-names */
  char *certfile = NULL, *keyfile = NULL;

  /* Connect to the server */
  serverfd = connect_socket( server, port );
  if( serverfd < 0 ) {
    /* inform user */
    snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_CANTCONNECT), server, port );
    writechan (tmpstr);
    return -1;
  }
  /* Abstract server IO in openssls BIO */
  server_conn = BIO_new_socket( serverfd, 1 );

  /* If SSL is requested, get our ssl-BIO running */
  if( server_conn && getintoption(CF_USESSL) ) {
    static int sslinit;
    if( !sslinit++ ) {
      SSL_library_init ();
      SSL_load_error_strings();
    }

    vc_init_x509store(&vc_store);
    vc_x509store_setflags(&vc_store, VC_X509S_SSL_VERIFY_PEER);

    /* get name of certificate file */
    certfile = getstroption (CF_CERTFILE);
    /* do we have a certificate file? */
    if (certfile) {
      /* does the filename start with a tilde? expand it! */
      if (certfile[0] == '~')
        tildex = tilde_expand (certfile);
      else
        tildex = certfile;

      vc_x509store_setflags(&vc_store, VC_X509S_USE_CERTIFICATE);
      vc_x509store_setcertfile(&vc_store, tildex);

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

      vc_x509store_set_pkeycb(&vc_store, (vc_askpass_cb_t)passprompt);
      vc_x509store_setkeyfile(&vc_store, tildex);
    }

    /* upgrade our plain BIO to ssl */
    if( vc_connect_ssl( &server_conn, &vc_store ) )
      BIO_free_all( server_conn );
  }

  if( !server_conn ) {
    /* inform user */
    snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_CANTCONNECT), server, port );
    writechan (tmpstr);
    return -1;
  }

  /* inform user */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_CONNECTED), server, port);
  writechan (tmpstr);

  /* if we didn't fail until now, we've got a connection. */
  return 0;
}

/* disconnect from server */
void
vcdisconnect () {
  BIO_free_all( server_conn );
  serverfd = -1;
}

/* handle a pm not sent error
 *  format: 412 %s */
static void
pmnotsent (char *message)
{
  while(*message && *message!=' ') message++;
  snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_ERR),message+1);
  writepriv( tmpstr, 0);

}

/* parse and handle an action string
 *  format: 118 %s %s
 *    vars: %s nick
 *          %s action */
static void
pubaction (char *message)
{
  char *nick = NULL, *action = NULL;
  nick = strchr (message, ' ');
  nick[0] = '\0';
  nick++;
  ul_public_action(nick);

  action = strchr (nick, ' ');
  action[0] = '\0';
  action++;

  snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_PUBACTION),nick,action);
  writechan (tmpstr);
}

/* parse and handle an thought string
 *  format: 124 %s %s
 *    vars: %s nick
 *          %s thought */
static void
pubthoughts (char *message)
{
  char *nick = NULL, *thoughts = NULL;
  nick = strchr (message, ' ');
  nick[0] = '\0';
  nick++;
  ul_public_action(nick);

  thoughts = strchr (nick, ' ');
  thoughts[0] = '\0';
  thoughts++;

  snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_PUBTHOUGHT),nick,thoughts);
  writechan (tmpstr);
}

/* parse and handle server logon */
static void
serverlogin (char *message)
{
  int utf8=!strcmp(nl_langinfo(CODESET), "UTF-8");
  if (utf8)
    networkoutput(".e utf8");
}

/* parse and handle an idle message
 *  format: 305
 *    vars: %s message */
static void
idleprompt (char *message)
{
  char *msg = NULL;
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
topicinfo (char *message)
{
  char *channel = NULL, *topic = NULL;
  int tmpchan = 0, ownchan = own_channel_get();

  /* search start of channel number */
  channel = strchr (message, ' ');
  channel++;

  /* search start of topic and terminate channel number */
  topic = strchr (channel, ' ');
  topic[0] = '\0';
  topic++;

  /* convert channel number to integer */
  tmpchan = atoi (channel);

  if (tmpchan == ownchan ) {
     /* show change in topic window */
     if (strlen(topic))
        snprintf (topicstr, TOPICSTRSIZE, getformatstr(FS_TOPICW), ownchan, topic);
      else
        snprintf (topicstr, TOPICSTRSIZE, getformatstr(FS_NOTOPICW), ownchan );
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
topicchange (char *message)
{
  char *nick = NULL, *topic = NULL;
  int len, ownchan = own_channel_get();

  /* search start of nickname */
  nick = strchr (message, ' ');
  nick++;
  ul_public_action(nick);

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
  snprintf (topicstr, TOPICSTRSIZE, getformatstr(FS_TOPICW), ownchan, topic);
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
justloggedin (char *message)
{
  char *str1 = NULL, *str2 = NULL;
  /* search start of nickname */
  str1 = strchr (message, ' ');
  str1++;

  /* search start of message, terminate nick */
  str2 = strchr (str1, ' ');
  str2[0] = '\0';
  str2++;

  /* if we have a new nick, store it */
  own_nick_set( str1 );

  /* show change in console window */
  snprintf (consolestr, CONSOLESTRSIZE, getformatstr(FS_CONSOLE), str1, getstroption (CF_SERVERHOST), getstroption (CF_SERVERPORT));
  consoleline (NULL);

  /* announce login as servermessage */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_SIGNON), str1, str2);
  writechan (tmpstr);

  /* we're not logged in, change status and request nicks */
  if (!loggedin)
    {
      loadcfg(getstroption(CF_LOGINSCRIPT),handleline);
      handleline(".S");
      loggedin = 1;
    }
}

/* this user joins a different channel */
void
ownjoin (int channel)
{
  networkoutput(".t");
  snprintf(tmpstr, TMPSTRSIZE, ".S %d",channel);
  networkoutput(tmpstr);
}

/* this user changes his nick */
void
ownnickchange (char *newnick)
{
}

/* parse and handle a nick error message
 *  format: 401 %s
 *          403 %s
 *          415 %s
 *    vars: %s - server message */
static void
nickerr (char *message)
{
  char *helpkiller = NULL;
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
      own_nick_set(NULL);

      /* get new nick via vchat-ui.c */
      nickprompt ();

      /* form login message and send it to server */
      snprintf (tmpstr, TMPSTRSIZE, ".l %s %s %d", own_nick_get(), getstroption (CF_FROM), getintoption (CF_CHANNEL));
      networkoutput (tmpstr);
    }
}

/* parse and handle a registered nick information
 *  format: 120 %s %s
 *    vars: %s      - this users registered nick
 *          %s msg  - server message */
static void
login (char *message) {
  char *msg = NULL;

  /* mutate message for output */
  message[2] = '*';
  /* show message to user */
  writecf (FS_SERV,&message[2]);

  /* we don't know our nick? */
  if (!own_nick_get() ) {
    /* find message after nick */
    msg = strchr (&message[4], ' ');
    if (msg) {
      /* terminate string before message and copy nick */
      msg[0] = '\0';
      own_nick_set(&message[4]);
    } else {
      /* no string in servers message (huh?), ask user for nick */
      nickprompt ();
    }
  }

  /* form login message and send it to server */
  snprintf (tmpstr, TMPSTRSIZE, ".l %s %s %d", own_nick_get(), getstroption (CF_FROM), getintoption (CF_CHANNEL));
  networkoutput (tmpstr);
}

/* parse and handle anon login request
 *  format: 121 %s
 *    vars: %s - server message */
static void
anonlogin (char *message)
{
  /* mutate message for output */
  message[2] = '*';
  /* show message to user */
  writecf (FS_SERV,&message[2]);

  /* we don't know our nick? ask for it! */
  if (!own_nick_get())
    nickprompt ();

  /* form login message and send it to server */
  snprintf (tmpstr, TMPSTRSIZE, ".l %s %s %d", own_nick_get(), getstroption (CF_FROM), getintoption (CF_CHANNEL));
  networkoutput (tmpstr);
}

/* parse and handle list of nicks (from '.S')
 *  format: 119 %s ..
 *    vars: %s nick - a users nick */
static void
receivenicks (char *message) {
  char *str1 = NULL, *str2 = NULL;
  int chanflag = -1;

  /* show message to user */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_USONLINE), &message[4]);
  writechan (tmpstr);

  /* search for channelnumber */
  if( !(str1 = strchr (message, ' ') ) ) return;
  str1++;

  if (str1[0] == '*') {
      ul_rebuild_list();
      str1++;
  } else {
      int mychan;
      str2 = str1;
      str1 = strchr(str2,' ');
      str1[0] = '\0';
      mychan = atoi(str2);
      if( mychan != own_channel_get() )
        return;

      /* Kick all users from the IN_MY_CHANNEL list */
      own_channel_set( own_channel_get() );
      chanflag = 1;
  }
  str1++;

  /* while user .. */
  while (str1) {
    /* search next user */
    str2 = strchr (str1, ' ');
    /* there is another user? terminate this one */
    if (str2) {
      str2[0] = '\0';
      str2++;
    }

    /* add this user via vchat-user.c */
    ul_add(str1, chanflag);

    /* next user .. */
    str1 = str2;
  }
  ul_clean();
}

/* parse and handle a login message
 *  format: 211 %s %s
 *    vars: %s nick - who logged on
 *          %s msg  - servers message */
static void
usersignon (char *message)
{
  char *nick = NULL, *msg = NULL;
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
usersignoff (char *message)
{
  char *nick = NULL, *msg = NULL;
  /* search start of nickname */
  nick = strchr (message, ' ');
  nick++;

  /* search start of message, terminate nick */
  msg = strchr (nick, ' ');
  if( msg ) {
    msg[0] = '\0';
    msg++;
  }

  /* delete this user via vchat-user.c */
  ul_del (nick);

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
userjoin (char *message)
{
  char *nick = NULL, *msg = NULL, *channel = NULL;
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

  /* is it myself joining */
  if( own_nick_check(nick) )
    own_channel_set(chan);

  /* notice channel join via vchat-user.c */
  if( own_channel_get() == chan )
    ul_enter_chan(nick);

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
userleave (char *message)
{
  char *nick = NULL, *msg = NULL, *channel = NULL;
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
  ul_leave_chan(nick);

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
usernickchange (char *message)
{
  char *oldnick = NULL, *newnick = NULL, *msg = NULL;

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
  ul_rename (oldnick, newnick);

  if( own_nick_check(newnick) ) {
    /* show change in console window */
    snprintf (consolestr, CONSOLESTRSIZE, getformatstr(FS_CONSOLE), newnick, getstroption (CF_SERVERHOST), getstroption (CF_SERVERPORT));
    consoleline (NULL);
  }

  /* show message to user */
  snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_NICKCHANGE), oldnick, newnick, msg);
  writechan (tmpstr);
}

/* handle received message from server */
static void
parsemsg (char *message)
{
  char *str1, *str2;
  int i;
  /* message to short or starts with '<'? must be channel */
  if (message[0] == '<')
  {
    str1 = &message[1];
    str2 = strchr(str1,'>');
    str2[0] = '\0';
    str2++;
    if (str2[0] == ' ') str2++;
    if (own_nick_check(str1))
       snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_MYPUBMSG),str1,str2);
    else
       snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_RXPUBMSG),str1,str2);
    writechan (tmpstr);

    ul_public_action(str1);
  }
  else if (message[0] == '[')
  {
    str1 = &message[1];
    str2 = strchr(str1,']');
    str2[0] = '\0';
    str2++;
    if (str2[0] == ' ') str2++;
    if (own_nick_check( str1 ))
       snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_MYPUBURL),str1,str2);
    else
       snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_RXPUBURL),str1,str2);
    ul_public_action(str1);
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
    writepriv (tmpstr, 1);
    ul_private_action(str1);
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
  char *tmp = NULL;
#define BUFSIZE 4096
  char buf[BUFSIZE];     /* data buffer */
  char *ltmp = buf;
  buf[BUFSIZE-1] = '\0'; /* sanity stop */

  /* receive data at offset */
  bytes = BIO_read (server_conn, &buf[bufoff], BUFSIZE-1 - bufoff);

  /* no bytes transferred? raise error message, bail out */
  if (bytes < 0)
    {
      snprintf (tmpstr, TMPSTRSIZE, "Receive fails, %s.", strerror(errno));
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
networkoutput (char *msg)
{
#ifdef DEBUG
  /* debugging? log network output! */
  fprintf (stderr, ">| %s\n", msg);
#endif

  /* send data to server */
  if (BIO_write (server_conn, msg, strlen (msg)) != strlen (msg))
    writecf (FS_ERR,"Message sending fuzzy.");

  /* send line termination to server */
  if (BIO_write (server_conn, "\r\n", 2) != 2)
    writecf (FS_ERR,"Message sending fuzzy.");
}
