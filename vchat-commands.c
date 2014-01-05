/*
 * vchat-client - alpha version
 * vchat-commands.c - handling of client commands
 *
 * Copyright (C) 2003 Dirk Engling <erdgeist@erdgeist.org>
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
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <readline/readline.h>

/* local includes */
#include "vchat.h"
#include "vchat-help.h"
#include "vchat-user.h"

/* version of this module */
char *vchat_cm_version = "$Id$";

/* from vchat-client.c */
extern int ownquit;
extern int wantreconnect;
extern int status;

/* our "/command " table */
enum {
COMMAND_VERSION,
COMMAND_FILTERS,
COMMAND_LSFLT,
COMMAND_RMFLT,
COMMAND_CLFLT,
COMMAND_HELP,
COMMAND_FORMAT,
COMMAND_KEYS,
COMMAND_QUIT,
COMMAND_USER,
COMMAND_DICT,
COMMAND_FLT,
COMMAND_PM,
COMMAND_ACTION,
COMMAND_PMSHORT,
COMMAND_QUERY,
COMMAND_QUITSHORT,
COMMAND_PLAIN,
COMMAND_RECONNECT,
COMMAND_NONE
};

static void command_quit      ( char *tail);
static void command_user      ( char *tail);
static void command_pm        ( char *tail);
static void command_action    ( char *tail);
static void command_help      ( char *tail);
static void command_format    ( char *tail);
static void command_flt       ( char *tail);
static void command_lsflt     ( char *tail);
static void command_clflt     ( char *tail);
static void command_rmflt     ( char *tail);
       void command_version   ( char *tail);
static void command_none      ( char *line);
static void command_query     ( char *tail);
static void command_reconnect ( char *tail);
static void command_dict      ( char *tail);

static void output_default  ( char *tail);

/* commandentry defined in vchat.h */

static commandentry
commandtable[] = {
{ COMMAND_VERSION,   "VERSION",   7, command_version,   SHORT_HELPTEXT_VERSION,   LONG_HELPTEXT_VERSION   },
{ COMMAND_LSFLT,     "LSFLT",     5, command_lsflt,     NULL,                     LONG_HELPTEXT_LSFLT     },
{ COMMAND_RMFLT,     "RMFLT",     5, command_rmflt,     NULL,                     LONG_HELPTEXT_RMFLT     },
{ COMMAND_CLFLT,     "CLFLT",     5, command_clflt,     NULL,                     LONG_HELPTEXT_CLFLT     },
{ COMMAND_HELP,      "HELP",      4, command_help,      SHORT_HELPTEXT_HELP,      LONG_HELPTEXT_HELP      },
{ COMMAND_FILTERS,   "FILTERS",   7, command_help,      SHORT_HELPTEXT_FILTERS,   LONG_HELPTEXT_FILTERS   },
{ COMMAND_FORMAT,    "FORMAT",    6, command_format,    NULL,                     NULL                    },
{ COMMAND_RECONNECT, "RECONNECT", 9, command_reconnect, SHORT_HELPTEXT_RECONNECT, LONG_HELPTEXT_RECONNECT },
{ COMMAND_KEYS,      "KEYS",      4, command_help,      SHORT_HELPTEXT_KEYS,      LONG_HELPTEXT_KEYS      },
{ COMMAND_QUERY,     "QUERY",     5, command_query,     NULL,                     NULL                    },
{ COMMAND_QUIT,      "QUIT",      4, command_quit,      SHORT_HELPTEXT_QUIT,      LONG_HELPTEXT_QUIT      },
{ COMMAND_USER,      "USER",      4, command_user,      SHORT_HELPTEXT_USER,      LONG_HELPTEXT_USER      },
{ COMMAND_DICT,      "DICT",      4, command_dict,      SHORT_HELPTEXT_DICT,      LONG_HELPTEXT_DICT      },
{ COMMAND_FLT,       "FLT",       3, command_flt,       NULL,                     LONG_HELPTEXT_FLT       },
{ COMMAND_PM,        "MSG",       3, command_pm,        SHORT_HELPTEXT_MSG,       LONG_HELPTEXT_MSG       },
{ COMMAND_ACTION,    "ME",        2, command_action,    SHORT_HELPTEXT_ME,        LONG_HELPTEXT_ME        },
{ COMMAND_PMSHORT,   "M",         1, command_pm,        NULL,                     SHORT_HELPTEXT_MSG      },
{ COMMAND_QUITSHORT, "Q",         1, command_quit,      SHORT_HELPTEXT_QUIT,      LONG_HELPTEXT_QUIT      },
{ COMMAND_PLAIN,     "/",         1, output_default,    NULL,                     NULL                    },
{ COMMAND_NONE,      "",          0, command_none,      NULL,                     NULL                    }
};

/* parse "/command" */
static int
translatecommand( char **cmd)
{
  int result;
  int cut = 0;
  int maxcut = 0;

  /* We do only want to allow Command abbrevation to
     the next newline, so that /VRES won't expand to /V RES */

  while( (*cmd)[maxcut] && ((*cmd)[maxcut] != 0x20) && ((*cmd)[maxcut] != '\n')) maxcut++;
  if( maxcut ) maxcut--;

  /* Repeatedly scan command table for command, with growing abbrevation cut off */
  do {
      /* Looks ugly, needs rewrite for better understanding */
      for( result = 0;
             (result != COMMAND_NONE) &&
             (strncasecmp(*cmd, commandtable[result].name, commandtable[result].len -
               ((commandtable[result].len - maxcut - cut > 0) ? cut : 0)));
           result++);
  } while ((cut < commandtable[0].len) && (commandtable[result].number == COMMAND_NONE) && (++cut));

  /* Just leave the tail... */
  (*cmd) += commandtable[result].len;

  /* ... whose start may be affected by abbrevation */
  if( commandtable[result].number !=  COMMAND_NONE )
      (*cmd) -= cut;

  return result;
}

/* handle thought */
static void
dothink( char *tail, char nice )
{
  while( *tail == ' ' ) tail++;

  /* send users message to server */
  snprintf (tmpstr, TMPSTRSIZE, ".%c %s", nice, tail);
  networkoutput (tmpstr);

  /* show action in channel window */
  snprintf (tmpstr, TMPSTRSIZE, nice == 'O' ? getformatstr(FS_TXPUBNTHOUGHT) : getformatstr(FS_TXPUBTHOUGHT), tail);
  writechan (tmpstr);
}


/* handle action */
static void
doaction( char *tail )
{
  while( *tail == ' ' ) tail++;

  if( *tail ) {
      /* send users message to server */
      snprintf (tmpstr, TMPSTRSIZE, ".a %s", tail);
      networkoutput (tmpstr);

      /* show action in channel window */
      snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_TXPUBACTION), own_nick_get(), tail);
      writechan (tmpstr);
  } else {
      /* missing action */
      msgout( "  You do nothing. " );
  }
}

/* handle private message outgoing */
static void
privatemessagetx ( char *tail ) {
  char *mesg;

  /* find nick */
  while( *tail==' ') tail++;

  /* find message */
  mesg = tail;
  while ( *mesg && *mesg!=' ') mesg++;

  /* check for nick && message */
  if(*tail && *mesg) {

      /* terminate nick, move to rel start */
      *mesg++ = '\0';

      /* form message and send to server */
      snprintf (tmpstr, TMPSTRSIZE, ".m %s %s", tail, mesg);
      networkoutput (tmpstr);

      /* show message in private window */
      snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_TXPRIVMSG), tail, mesg);
      writepriv (tmpstr, 0);

      /* note we messaged someone */
      ul_private_action(tail);

  } else {
      /* Bump user to fill in missing parts */
      msgout( *tail ? "  Won't send empty message. ":"  Recipient missing. " );
  }
}

/* handle line entered by user */
void
handleline (char *line)
{
#ifdef DEBUG
  /* debugging? log users input! */
  fprintf (stderr, "=| %s\n", line);
#endif

  switch ( line[0] )
  {
  case '.':
      switch ( line[1] ) {
      case 'm': /* sending a private message? */
          privatemessagetx( line+2 );
          break;
      case 'a': /* Do an action */
          doaction( line+2 );
          break;
      case '.':
          /* .. on start of line is public */
          if( line[2] != 'm' ) {
              output_default( line );
          } else {
              /* oopsi, "..m " detected */
              /* dunno what to do */
              flushout( );
              writeout("? You probably misstyped ?");
              writeout(" ");
              writeout(line );
              showout( );
          }
          break;
      case 'o':
      case 'O':
          dothink( line + 2, line[1] );
          break;
      case 'x':
          /* inform vchat-client, that the following connection
             drop was intentional */
          ownquit = 1; /* fallthrough intended */
      default:
          /* generic server command, send to server, show to user */
          snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_COMMAND), line);
          writechan (tmpstr);
          networkoutput (line);
          break;
      }
      break;
  case '/':
      line++;
      commandtable[translatecommand(&line)].handler(line);
      break;
  default:
      output_default( line );
      break;
  }
}

static void
output_default(char *line ) {
      /* prepare for output on display */
      snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_TXPUBMSG), own_nick_get(), line);

      /* send original line to server */
      networkoutput (line);

      /* output message to channel window */
      writechan (tmpstr);
}

/* handle a "/user " request */
static void
command_user(char *tail)
{
  while( *tail == ' ') tail++;
  if( *tail ) {
      char * out = ul_match_user( tail);
      if( *out ) {
          snprintf( tmpstr, TMPSTRSIZE, getformatstr(FS_USMATCH), tail, out);
      } else {
          snprintf( tmpstr, TMPSTRSIZE, getformatstr(FS_ERR), "  No user matched that regex. ");
      }
  } else {
      snprintf( tmpstr, TMPSTRSIZE, getformatstr(FS_ERR), "  Which user? ");
  }
  msgout( tmpstr );
}

/* handle a "/msg " request */
static void
command_pm (char *tail)
{
  privatemessagetx( tail );
}

static void
command_format(char *line) {
  struct stat testexist;
  char * tildex = NULL;

  flushout();
  while( *line==' ') line++;
  if(line) {
    tildex = tilde_expand( line );
    if(tildex && !stat(tildex, &testexist ))
      loadformats(tildex);
    else {
#define BUFSIZE 4096
      char buf[BUFSIZE];
      snprintf( buf, BUFSIZE, "~/.vchat/sample-%s.fmt", line );
      free(tildex);
      tildex = tilde_expand( line );
      if(tildex && !stat(tildex, &testexist ))
        loadformats(tildex);
    }
    writeout("  Sort of done.  ");
  } else {
    writeout("  Forgot to specify format file.  ");
  }
  free(tildex);
  showout();
}

/* handle a help request */
static void
command_help (char *line) {
  flushout( );
  while( *line==' ') line++;
  if( *line ) { /* Get help on command */
      int i;
      if( ( i = translatecommand( &line ) ) != COMMAND_NONE ) {
          snprintf( tmpstr, TMPSTRSIZE, "Help on command: %s", commandtable[i].name);
          writeout( tmpstr );
          writeout(" ");
          if( commandtable[i].short_help && !commandtable[i].help )
              writeout(commandtable[i].short_help );
          line = commandtable[i].help;
          if( line ) {
            while( *line ) {
              char *tmp = tmpstr;
              while( *line && (*line != '\n') )
                  *tmp++ = *line++;
              *tmp = '\0'; if( *line == '\n') line++;
              writeout ( tmpstr );
            }
          }
      } else {
          command_help( " " );
      }
  } else {      /* Get overall help */
      int i;
      for( i = 0; commandtable[i].number != COMMAND_NONE; i++ ) {
          if( commandtable[i].short_help ) 
              writeout( commandtable[i].short_help );
      }
  }
  showout();
}

/* handle an unknown command */
static void
command_none(char *line) {
    snprintf(tmpstr, TMPSTRSIZE, "  Unknown client command: %s ", line);
    msgout(tmpstr);
}

/* handle a "/flt " request */
static void
command_flt(char *tail){
  char colour;
  while(*tail==' ') tail++;
  colour = *tail++;
  while( colour && *tail == ' ') tail++;
  if( colour && *tail) {
      addfilter( colour, tail);
  }
}

/* handle a "/clflt " request */
static void
command_clflt (char *tail) {
  while( *tail == ' ') tail++;
  clearfilters( *tail );
}

/* handle a "/rmflt " request */
static void
command_rmflt (char *tail) {
  while( *tail == ' ') tail++;
  removefilter( tail );
}

/* list filters */
static void
command_lsflt (char *tail) {
  listfilters();
}

/* handle a "/me " action */
static void
command_action(char *tail)
{
  doaction( tail);
}

/* handle a "/reconnect" request */
static void
command_reconnect(char *tail)
{
  status = 0;
  wantreconnect = 1;
  ownquit = 0;
}

/* handle a "/quit " exit */
static void
command_quit(char *tail)
{
  /* send users message to server */
  snprintf (tmpstr, TMPSTRSIZE, ".x %s", tail);
  networkoutput (tmpstr);

  /* show action in channel window */
  writechan (tmpstr);

  /* Inform vchat-client, that the closing connection
     following is intended */
  status = 0;
  ownquit = 1;
}

/* print out version */
void
command_version(char *tail)
{
  /* output internal versions of all modules */
  flushout();
  writeout (vchat_cl_version);
  writeout (vchat_ui_version);
  writeout (vchat_io_version);
  writeout (vchat_us_version);
  writeout (vchat_cm_version);
  showout();
}

/* start or end a query */
void
command_query(char *tail)
{
  char *msg;
  while( *tail == ' ') tail++;

  // Check, if a message is to be sent in first query
  // Note: this is safe, since readline chops trailing spaces
  if((msg = strchr(tail, ' '))) {
    privatemessagetx( tail );
    *msg = 0;
  }

  // Do the ui stuff for query
  handlequery( tail );
}

void
command_dict(char *tail)
{
  ul_add_to_dict(tail);
}
