/*
 * vchat-client - alpha version
 * vchat-user.c - functions working with the userlist
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <time.h>
#include <readline/readline.h>
#include "vchat.h"

struct user
{
  char *nick;       /* nick of user */
  int chan;         /* channel user is on */
  int chan_valid;   /* are we sure he is? */
  int client_pv;    /* client protocol version */
  int messaged;     /* did we message with this user? */
  struct user *next;/* next user in linked list */
};

/* version of this module */
char *vchat_us_version = "$Id$";

/* externally used variables */
/*   current nick */
char *nick = NULL;
/*   current channel */
int chan = 0;
/*   userlist */
user *nicks = NULL;

/* add user to userlist */
void
ul_add (char *name, int ignored)
{
  user *tmp = NULL;

  /* no list? create one */
  if (!nicks)
    {
      nicks = malloc (sizeof (user));
      memset(nicks,0,sizeof(user));
      nicks->nick = strdup(name);
      nicks->chan = 0;       /* users default in channel 0 */
      nicks->chan_valid = 0;
      nicks->next = NULL;
    }
  else
    {
      /* travel list until end */
      tmp = nicks;
      while (tmp)
	{
          /* it is this user? return */
	  if (!strcmp (name, tmp->nick))
	    return;
          /* is there a next user? */
	  if (tmp->next)
	    tmp = tmp->next;
	  else
	    {
              /* create one */
	      tmp->next = malloc (sizeof (user));
	      tmp = tmp->next;
              memset(tmp,0,sizeof(user));
	      tmp->nick = strdup(name);
	      tmp->chan = 0;
	      tmp->chan_valid = 0;
	      tmp->next = NULL;
	      tmp = NULL;
	    }
	}
    }
#ifndef OLDREADLINE
  rl_last_func = NULL;
#endif
}

/* delete user from userlist */
void
ul_del (char *name, int ignored)
{
  user *tmp = NULL, *ltmp = NULL;

  /* is it this client? return */
  if (nick && !strcmp (nick, name))
    return;
  /* no list? return */
  if (!nicks)
    return;
  /* the user on top of list? */
  if (!strcmp (name, nicks->nick))
    {
      /* remove user and copy next in list */
      tmp = nicks->next;
      free (nicks);
      nicks = tmp;
      return;
    }
  /* travel through list, skip first entry */
  ltmp = nicks;
  tmp = nicks->next;
  while (tmp)
    {
      /* is it this user? */
      if (!strcmp (name, tmp->nick))
	{
          /* hook next to last, discard this */
	  ltmp->next = tmp->next;
	  free (tmp);
	  return;
	}
      /* advance in list */
      ltmp = tmp;
      tmp = tmp->next;
    }
#ifndef OLDREADLINE
  rl_last_func = NULL;
#endif
}

/* let user join a channel */
void
ul_join (char *name, int channel)
{
  /* is it this client? handle and return */
  if (nick && !strcmp (nick, name))
    {
      ownjoin (channel);
      return;
    } else ul_moveuser(name,channel);
#ifndef OLDREADLINE
  rl_last_func = NULL;
#endif
}

user *
ul_finduser (char *name) {
  user *tmp = nicks;
  snprintf( tmpstr, TMPSTRSIZE, "%s:", name);

  /* search user */
  while (tmp)
    {
      /* is it this user? */
      if (!strcmp (name, tmp->nick) || !strcmp(tmpstr, tmp->nick))
	{
	  return tmp;
	}
      /* advance in list */
      tmp = tmp->next;
    }
  return NULL;
}

char *
ul_matchuser( char *regex) {
  user    *tmp = nicks;
  char    *dest = tmpstr;
  regex_t  preg;

  *dest = 0;
  if( !regcomp( &preg, regex,  REG_ICASE | REG_EXTENDED | REG_NEWLINE)) {
      while( tmp ) {
          /* does the username match? */
          if( !regexec( &preg, tmp->nick, 0, NULL, 0)) /* append username to list */
              dest += snprintf ( dest, 256, " %s", tmp->nick);
          tmp = tmp->next;
      }
  }
  regfree( &preg );
  return tmpstr;
}

static void
ul_usertofront( user *who ) {
  user *tmp = nicks;

  while( tmp->next && ( tmp->next != who ) )
      tmp = tmp->next;

  if( tmp->next == who ) {
      tmp->next = tmp->next->next;      
      who->next = nicks;
      nicks     = who;
  }
#ifndef OLDREADLINE
  rl_last_func = NULL;
#endif
}

void
ul_msgto (char *name) {
  user *tmp = ul_finduser(name);

  if (tmp) {
      tmp->messaged |= 1;
      ul_usertofront( tmp );
  }
}

void
ul_msgfrom (char *name) {
  user *tmp = ul_finduser(name);

  if (tmp) {
      tmp->messaged |= 2;
      ul_usertofront( tmp );
  }
}

/* set channel of user */
void
ul_moveuser (char *name, int channel) {
  user *tmp = ul_finduser(name);

  if (tmp) {
     /* store channel information and mark it valid */
     tmp->chan = channel;
     tmp->chan_valid = 1;
  }
#ifndef OLDREADLINE
  rl_last_func = NULL;
#endif
}

/* let user leave a channel */
void
ul_leave (char *name, int channel)
{
  user *tmp = ul_finduser(name);
  /* is it this client? handle and return */
  if (nick && !strcmp (nick, name))
    {
      ownleave (channel);
      return;
    }

  if (tmp)
    {
      /* mark channel information invalid */
      tmp->chan_valid = 0;
      return;
    }
#ifndef OLDREADLINE
  rl_last_func = NULL;
#endif
}

/* let user change nick */
void
ul_nickchange (char *oldnick, char *newnick)
{
  user *tmp = ul_finduser(oldnick);
  /* is it this client? handle and return */
  if (nick && !strcmp (nick, oldnick))
    {
      ownnickchange (newnick);
      return;
    }
  if (tmp)
    {
      /* exchange nickname */
      free (tmp->nick);
      tmp->nick = strdup (newnick);
      return;
    }
#ifndef OLDREADLINE
  rl_last_func = NULL;
#endif
}

/* clear userlist */
void
ul_clear (void)
{
  user *tmp = nicks, *tmp2;
  /* walk list */
  while (tmp)
    {
      /* store next, delete this */
      tmp2 = tmp->next;
      free (tmp->nick);
      free (tmp);
      /* advance */
      tmp = tmp2;
    }
  /* mark list empty */
  nicks = NULL;
#ifndef OLDREADLINE
  rl_last_func = NULL;
#endif
}

int ulnc_casenick(user *tmp, const char *text, int len, int value) {
   return (!strncmp(tmp->nick, text, len));
}

int ulnc_ncasenick(user *tmp, const char *text, int len, int value) {
   return (!strncasecmp(tmp->nick, text, len));
}

char *
ulnc_complete (const char *text, int state, int value, int (*checkfn)(user *,const char *,int,int)) {
  static int  len;
  static user *tmp;
  char        *name;

  /* first round? reset pointers! */
  if (!state)
    {
      tmp = nicks;
      len = strlen (text);
    }

  /* walk list .. */
  while (tmp)
    {
      /* we found a match? */
      if (checkfn(tmp,text,len,value))
	{
          /* copy nick, advance pointer for next call, return nick */
	  name = tmp->nick;
	  tmp = tmp->next;
	  return name;
	}
      else
	{
	  tmp = tmp->next;
	}
    }
  return NULL;
}

/* nick completion functions for readline in vchat-ui.c */
char *
ul_nickcomp (const char *text, int state)
{
  int ncasemode = 1;
  char *name = NULL;
  if (!state) ncasemode = 0;
  if (!ncasemode) {
     name = ulnc_complete(text,state,0,ulnc_casenick);
     if (!state && !name) ncasemode = 1;
  }
  if (ncasemode)
     name = ulnc_complete(text,state,0,ulnc_ncasenick);
  if (name)
      return strdup(name);
    else
      return NULL;
}

int ulnc_casenickc(user *tmp, const char *text, int len, int value) {
   return (!strncmp(tmp->nick, text, len) && (tmp->chan_valid) && (tmp->chan == value));
}

int ulnc_ncasenickc(user *tmp, const char *text, int len, int value) {
   return (!strncasecmp(tmp->nick, text, len) && (tmp->chan_valid) && (tmp->chan == value));
}

/* nick completion for channel, used by vchat-ui.c */
char *
ul_cnickcomp (const char *text, int state)
{
  int ncasemode = 1;
  static char *name = NULL;

  if (!state) ncasemode = 0;
  if (!ncasemode) {
     name = ulnc_complete(text,state,chan,ulnc_casenickc);
     if (!state && !name) ncasemode = 1;
  }
  if (ncasemode)
     name = ulnc_complete(text,state,chan,ulnc_ncasenickc);
  if (name) {
     snprintf(tmpstr,TMPSTRSIZE,"%s:",name);
     return strdup(tmpstr);
  } else
     return NULL;
}

int ulnc_casenickm(user *tmp, const char *text, int len, int value) {
   return (!strncmp(tmp->nick, text, len) && (tmp->messaged));
}

int ulnc_ncasenickm(user *tmp, const char *text, int len, int value) {
   return (!strncasecmp(tmp->nick, text, len) && (tmp->messaged));
}

/* nick completion for channel, used by vchat-ui.c */
char *
ul_mnickcomp (const char *text, int state)
{
  int ncasemode = 1;
  static char *name = NULL;

  if (!state) ncasemode = 0;
  if (!ncasemode) {
     name = ulnc_complete(text,state,chan,ulnc_casenickm);
     if (!state && !name) ncasemode = 1;
  }
  if (ncasemode)
     name = ulnc_complete(text,state,chan,ulnc_ncasenickm);
  if (name) {
     snprintf(tmpstr,TMPSTRSIZE,".m %s",name);
     return strdup(tmpstr);
  } else
     return NULL;
}
