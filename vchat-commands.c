/*
 * vchat-client - alpha version
 * vchat-commands.c - handling of client commands
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
#include <string.h>

/* local includes */
#include "vchat.h"
#include "vchat-help.h"

/* version of this module */
unsigned char *vchat_cm_version = "$Id$";

/* our "/command " table */
enum {
COMMAND_VERSION,
COMMAND_FILTERS,
COMMAND_LSFLT,
COMMAND_RMFLT,
COMMAND_CLFLT,
COMMAND_HELP,
COMMAND_KEYS,
COMMAND_QUIT,
COMMAND_USER,
COMMAND_FLT,
COMMAND_PM,
COMMAND_ACTION,
COMMAND_PMSHORT,
COMMAND_PLAIN,
COMMAND_NONE
};

static void command_quit    ( unsigned char *tail);
static void command_user    ( unsigned char *tail);
static void command_pm      ( unsigned char *tail);
static void command_action  ( unsigned char *tail);
static void command_help    ( unsigned char *tail);
static void command_flt     ( unsigned char *tail);
static void command_lsflt   ( unsigned char *tail);
static void command_clflt   ( unsigned char *tail);
static void command_rmflt   ( unsigned char *tail);
       void command_version ( unsigned char *tail);
static void command_none    ( unsigned char *line);

static void output_default  ( unsigned char *tail);

/* commandentry defined in vchat.h */

static commandentry
commandtable[] = {
{ COMMAND_VERSION, "VERSION",   7, command_version, SHORT_HELPTEXT_VERSION, LONG_HELPTEXT_VERSION },
{ COMMAND_LSFLT,   "LSFLT",     5, command_lsflt,   NULL,                   LONG_HELPTEXT_LSFLT   },
{ COMMAND_RMFLT,   "RMFLT",     5, command_rmflt,   NULL,                   LONG_HELPTEXT_RMFLT   },
{ COMMAND_CLFLT,   "CLFLT",     5, command_clflt,   NULL,                   LONG_HELPTEXT_CLFLT   },
{ COMMAND_HELP,    "HELP",      4, command_help,    SHORT_HELPTEXT_HELP,    LONG_HELPTEXT_HELP    },
{ COMMAND_FILTERS, "FILTERS",   7, command_help,    SHORT_HELPTEXT_FILTERS, LONG_HELPTEXT_FILTERS },
{ COMMAND_KEYS,    "KEYS",      4, command_help,    SHORT_HELPTEXT_KEYS,    LONG_HELPTEXT_KEYS    },
{ COMMAND_QUIT,    "QUIT",      4, command_quit,    SHORT_HELPTEXT_QUIT,    LONG_HELPTEXT_QUIT    },
{ COMMAND_USER,    "USER",      4, command_user,    SHORT_HELPTEXT_USER,    LONG_HELPTEXT_USER    },
{ COMMAND_FLT,     "FLT",       3, command_flt,     NULL,                   LONG_HELPTEXT_FLT     },
{ COMMAND_PM,      "MSG",       3, command_pm,      SHORT_HELPTEXT_MSG,     LONG_HELPTEXT_MSG     },
{ COMMAND_ACTION,  "ME",        2, command_action,  SHORT_HELPTEXT_ME,      LONG_HELPTEXT_ME      },
{ COMMAND_PMSHORT, "M",         1, command_pm,      NULL,                   SHORT_HELPTEXT_MSG    },
{ COMMAND_PLAIN,   "/",         1, output_default,  NULL,                   NULL                  },
{ COMMAND_NONE,    "",          0, command_none,    NULL,                   NULL                  }
};

/* parse "/command" */
static int
translatecommand( unsigned char **cmd)
{
  int result;
  int cut = 0;
  int maxcut = 0;

  while( (*cmd)[maxcut] && ((*cmd)[maxcut] != 0x20) && ((*cmd)[maxcut] != '\n')) maxcut++;
  if( maxcut ) maxcut--;

  do {
      for( result = 0;
             (result != COMMAND_NONE) &&
             (strncasecmp(*cmd, commandtable[result].name, commandtable[result].len -
               ((commandtable[result].len - maxcut - cut > 0) ? cut : 0)));
           result++);
  } while ((cut < commandtable[0].len) && (commandtable[result].number == COMMAND_NONE) && (++cut));
  
  (*cmd) += commandtable[result].len;
  if( commandtable[result].number !=  COMMAND_NONE )
      (*cmd) -= cut;
      
  return result;
}

/* handle action */
static void
doaction( unsigned char *tail )
{
  while( *tail == ' ' ) tail++;
  
  if( *tail ) {
      /* send users message to server */
      snprintf (tmpstr, TMPSTRSIZE, ".a %s", tail);
      networkoutput (tmpstr);
          
      /* show action in channel window */
      snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_TXPUBACTION), nick, tail);
      writechan (tmpstr);
  } else {

      /* missing action */
      snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_BGTXPUBACTION));
      writechan (tmpstr);
  }
}

/* handle private message outgoing */
static void
privatemessagetx ( unsigned char *tail ) {
  unsigned char *mesg;
   
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
      writepriv (tmpstr);
          
      /* note we messaged someone */
      ul_msgto(tail);
          
  } else {
      
      /* missing nick or message body inform user */
      snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_BGPRIVMSG));
      writepriv (tmpstr);
  }
}

/* handle line entered by user */
void
handleline (unsigned char *line)
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
      case 'a':
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
      default:

          /* generic server command, send to server, show to user */
          snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_COMMAND), line);
          networkoutput (line);
          writechan (tmpstr);
          break;
      }
      break;
  case '/':
      line++;
      commandtable[translatecommand(&line)].handler(line);
      break;
  case '0':
      break;
  default:
      output_default( line );
      break;   
  }
}

static void
output_default( unsigned char *line ) {
      /* prepare for output on display */
      snprintf (tmpstr, TMPSTRSIZE, getformatstr(FS_TXPUBMSG), nick, line);
      
      /* send original line to server */
      networkoutput (line);
      
      /* output message to channel window */
      writechan (tmpstr);
}
 
/* handle a "/user " request */
static void
command_user( unsigned char *tail)
{
  while( *tail == ' ') tail++;
  if( strlen(tail) >= 3) {
      unsigned char * out = ul_matchuser( tail);
      if( *out ) {
          snprintf( tmpstr, TMPSTRSIZE, getformatstr(FS_USMATCH), tail, out);
      } else {
          snprintf( tmpstr, TMPSTRSIZE, getformatstr(FS_ERR), "No user matched that substring");
      }
  } else {
      snprintf( tmpstr, TMPSTRSIZE, getformatstr(FS_ERR), "Specify at least 3 characters to match users");
  }
  writechan( tmpstr );
}

/* handle a "/msg " request */
static void
command_pm (unsigned char *tail)
{
  privatemessagetx( tail );
}
 
/* handle a help request */
static void
command_help (unsigned char *line) {
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
              unsigned char *tmp = tmpstr;
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
command_none( unsigned char *line) {
    flushout( ); 
    snprintf(tmpstr, TMPSTRSIZE, "  Unknown client command: %s ", line);
    writeout(tmpstr);
    showout( );
}
 
/* handle a "/flt " request */
static void
command_flt( unsigned char *tail){
  unsigned char colour;
  while(*tail==' ') tail++;
  colour = *tail++;
  while( colour && *tail == ' ') tail++;
  if( colour && *tail) {
      addfilter( colour, tail);
  }
}  

/* handle a "/clflt " request */
static void
command_clflt ( unsigned char *tail) {
  while( *tail == ' ') tail++;
  clearfilters( *tail );
}
   
/* handle a "/rmflt " request */
static void
command_rmflt ( unsigned char *tail) {
  while( *tail == ' ') tail++;
  removefilter( tail );
}
 
/* list filters */
static void
command_lsflt ( unsigned char *tail) {
  listfilters();
}
 
/* handle a "/me " action */
static void
command_action( unsigned char *tail)
{
  doaction( tail);
}

/* handle a "/quit " exit */
static void
command_quit  ( unsigned char *tail)
{
  /* send users message to server */
  snprintf (tmpstr, TMPSTRSIZE, ".x %s", tail);
  networkoutput (tmpstr);
  
  /* show action in channel window */
  writechan (tmpstr);
}

/* print out version */
void
command_version( unsigned char *tail)
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
