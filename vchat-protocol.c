/*
 * vchat-client - beta version
 * vchat-protocol.c - handling of server messages
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
#include <errno.h>
#include <langinfo.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <readline/readline.h>

#ifdef DEBUG
FILE *dumpfile;
#endif

/* local includes */
#include "vchat-connection.h"
#include "vchat-user.h"
#include "vchat.h"

/* version of this module */
const char *vchat_io_version =
    "vchat-protocol.c   $Id$";

/* declaration of local helper functions */
static void usersignon(char *);
static void usersignoff(char *);
static void usernickchange(char *);
static void userjoin(char *);
static void userleave(char *);
static void receivenicks(char *message);
static void justloggedin(char *message);
static void nickerr(char *message);
static void login(char *message);
static void anonlogin(char *message);
static void topicinfo(char *message);
static void pubaction(char *message);
static void pubthoughts(char *message);
static void serverlogin(char *message);
static void idleprompt(char *message);
static void topicchange(char *message);
static void pmnotsent(char *message);

/* declaration of server message array */
#include "vchat-messages.h"

char *encoding;

/* handle a pm not sent error
 *  format: 412 %s */
static void pmnotsent(char *message) {
  while (*message && *message != ' ')
    message++;
  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_ERR), message + 1);
  writepriv(tmpstr, 0);
}

/* parse and handle an action string
 *  format: 118 %s %s
 *    vars: %s nick
 *          %s action */
static void pubaction(char *message) {
  char *nick, *action;
  if (!(nick = strchr(message, ' ')))
    return;
  *nick++ = '\0';
  if (!(action = strchr(nick, ' ')))
    return;
  *action++ = '\0';

  ul_public_action(nick);
  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_PUBACTION), nick, action);
  writechan(tmpstr);
}

/* parse and handle an thought string
 *  format: 124 %s %s
 *    vars: %s nick
 *          %s thought */
static void pubthoughts(char *message) {
  char *nick, *thoughts;
  if (!(nick = strchr(message, ' ')))
    return;
  *nick++ = '\0';
  if (!(thoughts = strchr(nick, ' ')))
    return;
  *thoughts++ = '\0';

  ul_public_action(nick);
  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_PUBTHOUGHT), nick, thoughts);
  writechan(tmpstr);
}

/* parse and handle server logon */
static void serverlogin(char *message) {
  (void)message;
  const char *codeset = nl_langinfo(CODESET);
  if (codeset && !strcmp(codeset, "UTF-8"))
    vc_sendmessage(".e utf8");
}

/* parse and handle an idle message
 *  format: 305
 *    vars: %s message */
static void idleprompt(char *message) {
  char *msg;
  if (!(msg = strchr(message, ' ')))
    return;
  *msg++ = '\0';

  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_IDLE), msg);
  writechan(tmpstr);
}

/* parse and handle a topic information string
 *  format: 115 %d %s
 *    vars: %d chan  - channel number
 *          %s topic - topic  */
static void topicinfo(char *message) {
  char *channel, *topic;
  int tmpchan = 0, ownchan = own_channel_get();

  /* search start of channel number */
  if (!(channel = strchr(message, ' ')))
    return;
  channel++;

  /* search start of topic and terminate channel number */
  if (!(topic = strchr(channel, ' ')))
    return;
  *topic++ = '\0';

  /* convert channel number to integer */
  tmpchan = atoi(channel);

  if (tmpchan == ownchan) {
    /* show change in topic window */
    if (strlen(topic))
      snprintf(topicstr, TOPICSTRSIZE, getformatstr(FS_TOPICW), ownchan, topic);
    else
      snprintf(topicstr, TOPICSTRSIZE, getformatstr(FS_NOTOPICW), ownchan);
    topicline(NULL);
  }

  /* announce change in channel window */
  if (strlen(topic))
    snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_TOPIC), tmpchan, topic);
  else
    snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_NOTOPIC), tmpchan);
  writechan(tmpstr);
}

/* parse and handle a topic change string
 *  format: 114 %s changes topic to '%s'
 *    vars: %s nick
 *          %s topic */
static void topicchange(char *message) {
  char *nick, *topic;
  int len, ownchan = own_channel_get();

  /* search start of nickname */
  if (!(nick = strchr(message, ' ')))
    return;
  nick++;

  /* search start of message before topic, terminate nick */
  if (!(topic = strchr(nick, ' ')))
    return;
  *topic++ = '\0';

  /* search start of real topic and terminate channel number */
  if (!(topic = strchr(topic, '\'')))
    return;
  *topic++ = '\0';

  /* remove ending '\'', if there */
  len = strlen(topic);
  if (len && topic[len - 1] == '\'')
    topic[len - 1] = '\0';

  ul_public_action(nick);
  /* show change in topic window */
  snprintf(topicstr, TOPICSTRSIZE, getformatstr(FS_TOPICW), ownchan, topic);
  topicline(NULL);

  /* announce change in channel window */
  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_CHGTOPIC), nick, topic);
  writechan(tmpstr);
}

/* parse and handle a login message
 *  format: 212 %s %s
 *    vars: %s str1 - nick used to login
 *          %s str2 - servers message */
static void justloggedin(char *message) {
  char *str1, *str2;
  /* search start of nickname */
  if (!(str1 = strchr(message, ' ')))
    return;
  str1++;

  /* search start of message, terminate nick */
  if (!(str2 = strchr(str1, ' ')))
    return;
  *str2++ = '\0';

  /* if we have a new nick, store it */
  own_nick_set(str1);

  /* show change in console window */
  snprintf(consolestr, CONSOLESTRSIZE, getformatstr(FS_CONSOLE), str1,
           getstroption(CF_SERVERHOST), getstroption(CF_SERVERPORT));
  consoleline(NULL);

  /* announce login as servermessage */
  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_SIGNON), str1, str2);
  writechan(tmpstr);

  /* we're not logged in, change status and request nicks */
  if (!loggedin) {
    loadcfg(getstroption(CF_LOGINSCRIPT), 0, handleline);
    handleline(".S");
    loggedin = 1;
    flushconnect();
  }
}

/* this user joins a different channel */
void ownjoin(int channel) {
  vc_sendmessage(".t");
  snprintf(tmpstr, TMPSTRSIZE, ".S %d", channel);
  vc_sendmessage(tmpstr);
}

/* this user changes his nick */
void ownnickchange(const char *newnick) { (void)newnick; }

/* parse and handle a nick error message
 *  format: 401 %s
 *          403 %s
 *          415 %s
 *    vars: %s - server message */
static void nickerr(char *message) {
  char *helpkiller = NULL;
  /* mutate message for output */
  message[2] = '!';
  /* help information found? remove it. */
  if ((helpkiller = strstr(message, " Type .h for help")))
    helpkiller[0] = '\0';
  /* nickchange not done? eliminate message */
  if (loggedin && (helpkiller = strstr(message, " - Nick not changed")))
    helpkiller[0] = '\0';
  /* show errormessage */
  writecf(FS_ERR, &message[2]);

  /* not logged in? insist on getting a new nick */
  if (!loggedin) {
    /* free bogus nick */
    own_nick_set(NULL);

    /* get new nick via vchat-ui.c */
    nickprompt();

    /* form login message and send it to server */
    snprintf(tmpstr, TMPSTRSIZE, ".l %s %s %d", own_nick_get(),
             getstroption(CF_FROM), getintoption(CF_CHANNEL));
    vc_sendmessage(tmpstr);
  }
}

/* parse and handle a registered nick information
 *  format: 120 %s %s
 *    vars: %s      - this users registered nick
 *          %s msg  - server message */
static void login(char *message) {
  char *msg = NULL;

  /* mutate message for output */
  message[2] = '*';
  /* show message to user */
  writecf(FS_SERV, &message[2]);

  /* we don't know our nick? */
  if (!own_nick_get()) {
    /* find message after nick */
    msg = strchr(&message[4], ' ');
    if (msg) {
      /* terminate string before message and copy nick */
      msg[0] = '\0';
      own_nick_set(&message[4]);
    } else {
      /* no string in servers message (huh?), ask user for nick */
      nickprompt();
    }
  }

  /* form login message and send it to server */
  snprintf(tmpstr, TMPSTRSIZE, ".l %s %s %d", own_nick_get(),
           getstroption(CF_FROM), getintoption(CF_CHANNEL));
  vc_sendmessage(tmpstr);
}

/* parse and handle anon login request
 *  format: 121 %s
 *    vars: %s - server message */
static void anonlogin(char *message) {
  /* mutate message for output */
  message[2] = '*';
  /* show message to user */
  writecf(FS_SERV, &message[2]);

  /* we don't know our nick? ask for it! */
  if (!own_nick_get())
    nickprompt();

  /* form login message and send it to server */
  snprintf(tmpstr, TMPSTRSIZE, ".l %s %s %d", own_nick_get(),
           getstroption(CF_FROM), getintoption(CF_CHANNEL));
  vc_sendmessage(tmpstr);
}

/* parse and handle list of nicks (from '.S')
 *  format: 119 %s ..
 *    vars: %s nick - a users nick */
static void receivenicks(char *message) {
  char *str1 = NULL, *str2 = NULL;
  int chanflag = -1;

  /* show message to user */
  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_USONLINE), &message[4]);
  writechan(tmpstr);

  /* search for channelnumber */
  if (!(str1 = strchr(message, ' ')))
    return;
  str1++;

  if (str1[0] == '*') {
    ul_rebuild_list();
    str1++;
  } else {
    int mychan;
    str2 = str1;
    if (!(str1 = strchr(str2, ' ')))
      return;
    *str1 = '\0';
    mychan = atoi(str2);
    if (mychan != own_channel_get())
      return;

    /* Kick all users from the IN_MY_CHANNEL list */
    own_channel_set(own_channel_get());
    chanflag = 1;
  }
  str1++;

  /* while user .. */
  while (str1) {
    /* search next user */
    str2 = strchr(str1, ' ');
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
static void usersignon(char *message) {
  char *nick, *msg;
  /* search start of nickname */
  if (!(nick = strchr(message, ' ')))
    return;
  nick++;

  /* search start of message, terminate nick */
  if (!(msg = strchr(nick, ' ')))
    return;
  *msg++ = '\0';

  /* add this user via vchat-user.c */
  ul_add(nick, 0);

  /* show message to user */
  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_SIGNON), nick, msg);
  writechan(tmpstr);
}

/* parse and handle a logoff message
 *  format: 221 %s %s
 *    vars: %s nick - who logged off
 *          %s msg  - servers message */
static void usersignoff(char *message) {
  char *nick, *msg;
  /* search start of nickname */
  if (!(nick = strchr(message, ' ')))
    return;
  nick++;

  /* search start of message, terminate nick */
  msg = strchr(nick, ' ');
  if (msg) {
    *msg++ = '\0';
  }

  /* delete this user via vchat-user.c */
  ul_del(nick);

  /* show message to user */
  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_SIGNOFF), nick, msg);
  writechan(tmpstr);
}

/* parse and handle a join message
 *  format: 232 %s %s %d
 *    vars: %s nick - who joined
 *          %s msg  - servers message
 *          %d chan - channel joined */
static void userjoin(char *message) {
  char *nick, *msg, *channel;
  int chan = 0;

  /* search start of nickname */
  if (!(nick = strchr(message, ' ')))
    return;
  nick++;

  /* search start of message, terminate nick */
  if (!(msg = strchr(nick, ' ')))
    return;
  *msg++ = '\0';

  /* search start of channel, terminate message */
  if (!(channel = strrchr(msg, ' ')))
    return;
  *channel++ = '\0';

  /* convert channel to integer */
  chan = atoi(channel);

  /* is it myself joining */
  if (own_nick_check(nick))
    own_channel_set(chan);

  /* notice channel join via vchat-user.c */
  if (own_channel_get() == chan)
    ul_enter_chan(nick);

  /* show message to user */
  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_JOIN), nick, msg, chan);
  writechan(tmpstr);
}

/* parse and handle a leave message
 *  format: 231 %s %s %d
 *    vars: %s nick - who left
 *          %s msg  - servers message
 *          %d chan - channel joined */
static void userleave(char *message) {
  char *nick, *msg, *channel;
  int chan = 0;

  /* search start of nickname */
  if (!(nick = strchr(message, ' ')))
    return;
  nick++;

  /* search start of message, terminate nick */
  if (!(msg = strchr(nick, ' ')))
    return;
  *msg++ = '\0';

  /* convert channel to integer */
  if (!(channel = strrchr(msg, ' ')))
    return;
  *channel++ = '\0';

  /* convert channel to integer */
  chan = atoi(channel);

  /* notice channel leave via vchat-user.c */
  ul_leave_chan(nick);

  /* show message to user */
  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_LEAVE), nick, msg, chan);
  writechan(tmpstr);
}

/* parse and handle a nickchange message
 *  format: 241 %s %s %s
 *    vars: %s oldnick - users old nick
 *          %s newnick - users new nick
 *          %s msg     - server message */
static void usernickchange(char *message) {
  char *oldnick, *newnick, *msg;

  /* search start of old nickname */
  if (!(oldnick = strchr(message, ' ')))
    return;
  oldnick++;

  /* search start of new nickname, terminate old nick */
  if (!(newnick = strchr(oldnick, ' ')))
    return;
  *newnick++ = '\0';

  /* search start of message, terminate new nick */
  if (!(msg = strchr(newnick, ' ')))
    return;
  *msg++ = '\0';

  /* notice nickchange via vchat-user.c */
  ul_rename(oldnick, newnick);

  if (own_nick_check(newnick)) {
    /* show change in console window */
    snprintf(consolestr, CONSOLESTRSIZE, getformatstr(FS_CONSOLE), newnick,
             getstroption(CF_SERVERHOST), getstroption(CF_SERVERPORT));
    consoleline(NULL);
  }

  /* show message to user */
  snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_NICKCHANGE), oldnick, newnick,
           msg);
  writechan(tmpstr);
}

/* handle received message from server */
void protocol_parsemsg(char *message) {
  char *str1, *str2;
  int i;
  /* message to short or starts with '<'? must be channel */
  if (message[0] == '<') {
    str1 = &message[1];
    if (!(str2 = strchr(str1, '>')))
      return;
    *str2++ = '\0';
    if (str2[0] == ' ')
      str2++;
    if (own_nick_check(str1))
      snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_MYPUBMSG), str1, str2);
    else
      snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_RXPUBMSG), str1, str2);
    writechan(tmpstr);

    ul_public_action(str1);
  } else if (message[0] == '[') {
    str1 = &message[1];
    if (!(str2 = strchr(str1, ']')))
      return;
    *str2++ = '\0';
    if (str2[0] == ' ')
      str2++;
    if (own_nick_check(str1))
      snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_MYPUBURL), str1, str2);
    else
      snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_RXPUBURL), str1, str2);
    ul_public_action(str1);
    writechan(tmpstr);
  }
  /* message starts with '*'? must be private */
  else if (message[0] == '*') {
    str1 = &message[1];
    if (!(str2 = strchr(str1, '*')))
      return;
    *str2++ = '\0';
    if (str2[0] == ' ')
      str2++;
    snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_RXPRIVMSG), str1, str2);
    writepriv(tmpstr, 1);
    ul_private_action(str1);
  }
  /* message starts with a number? must be a servermessage */
  else if ((message[0] >= '0') && (message[0] <= '9')) {
    /* walk server message array */
    for (i = 0; servermessages[i].id[0]; i++) {
      /* is this the message? */
      if (!(strncmp(servermessages[i].id, message, 3))) {
        /* scripting hook available - call it */
        if (servermessages[i].hook)
          servermessages[i].hook(message);
        /* function available - call it */
        else if (servermessages[i].funct)
          servermessages[i].funct(message);
        /* no function available, but known - give output */
        else {
          /* remove continutation mark */
          if (message[3] == '-')
            message[3] = ' ';

          /* mutate message for display */
          message[2] = '*';
          /* giveout message by type */
          switch (servermessages[i].type) {
          case SM_IGNORE:
            break;
          case SM_INFO:
            /* change marker and send as servermessage */
            message[2] = '#';
            writecf(FS_SERV, &message[2]);
            break;
          case SM_USERINFO:
            /* keep marker and send as servermessage */
            writecf(FS_SERV, &message[2]);
            break;
          case SM_CHANNEL:
            /* keep marker and send as channelmessage */
            writechan(&message[2]);
            break;
          case SM_ERROR:
            /* change marker and send as errormessage */
            message[2] = '!';
            writecf(FS_ERR, &message[2]);
            break;
          default:
            /* fallback: keep marker and send as servermessage */
            writecf(FS_SERV, &message[2]);
          }
        }
        return;
      }
    }
    /* message not in list, raise errormessage */
    snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_UNKNOWNMSG), message);
    writecf(FS_ERR, tmpstr);
  } else {
    /* message neither public, private or server, raise errormessage */
    snprintf(tmpstr, TMPSTRSIZE, getformatstr(FS_BOGUSMSG), message);
    writecf(FS_ERR, tmpstr);
  }
}
