/*
 * vchat-client - alpha version
 * vchat-client.c - main() and utility functions
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
#include <sys/types.h>
#include <sys/time.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <readline/readline.h>
#include <locale.h>
#include "vchat.h"

/* version of this module */
char *vchat_cl_version = "$Id$";

/* externally used variables */
/*   we're logged in */
unsigned int loggedin = 0;
/*   we run as long as this is true */
int status = 1;
/*   we set this, we WANT to quit */
int ownquit = 0;
/*   we set this, we DONT want to quit */
int wantreconnect = 0;
static int reconnect_delay = 6;
static time_t reconnect_time = 0;

/*   error string to show after exit */
char errstr[ERRSTRSIZE] = "\0";

/* locally global variables */
/* our list of filedescriptors */
static fd_set masterfds;

/* declaration of configuration array */
#include "vchat-config.h"

/* servers filedescriptor from vchat-protocol.c */
extern int serverfd;

void setnoption (char *, char *);

static void parsecfg(char *line) {
  int bytes;
  char *param=line;
  char *value=NULL;

  /* handle quotes value is empty, so we can use it */
  value = strchr(line,'#');
  if (value) { /* the line contains a cute little quote */
    value[0]='\0'; /* ignore the rest of the line */
  }

  /* now split the line into two parts */
  value = strchr(line,'=');
  if (!value) return; /* exit if strchr fails */
  value[0]='\0';
  value++;

  /* "trim" values */
  while ((value[0] == ' ')||(value[0] == '\t'))
    value++;
  bytes = strlen(value);
  while ((value[bytes-1] == ' ')||(value[bytes-1] == '\t')) {
    value[bytes-1] = '\0';
    bytes=strlen(value);
  }
  /* bytes should be strlen(value) */
  if ( value[bytes-1] == '"' ) value[bytes-1] = '\0';
  if ( value[0] == '"' ) value++;

  /* "trim" param */
  while ((param[0] == ' ')||(param[0] == '\t'))
    param++;
  bytes = strlen(param);
  while ((param[bytes-1] == ' ')||(param[bytes-1] == '\t')) {
    param[bytes-1] = '\0';
    bytes=strlen(param);
  }
  /* bytes should be strlen(param) */
  if ( param[bytes-1] == '\"' ) param[bytes-1] = '\0';
  if ( param[0] == '\"' ) param++;

  if ((!param)||(!value)) return; /* failsave */

  //fprintf(stderr,"\"%s\" -> \"%s\"\n",param,value);
  setnoption(param,value);
}

static void parseformats(char *line) {
  int i;
  char *tmp = NULL;  

  /* read a format line from file, syntax is
     FS_XXX = "formatstring"
  */

  while( *line == ' ') line++;

  if( strlen( line ) > TMPSTRSIZE ) return;

  if( *line != '#') /* allow to comment out the line */
      for (i = 0; formatstrings[i].formatstr; i++)
          if (!strncasecmp(formatstrings[i].idstring, line, strlen( formatstrings[i].idstring) ))
          {
              char *tail = line + strlen( formatstrings[i].idstring);
              while( *tail==' ' || *tail=='\t') tail++; /* and skip whitespaces */

              if( *tail++ == '=' )
              {
                  while( *tail==' ' || *tail=='\t') tail++;
                  if( *(tail++)=='\"' )
                  {
                      int j, k = 0, stringends = 0, backslash=0;
                      for ( j = 0; tail[j] && !stringends; j++)
                      {
                          switch( tail[j] ) {
                          case '^':
                              if ( tail[j+1] != '^' )
                                  tmpstr[k++] = 1;
                              break;
                          case '\\':
                              backslash=1-backslash;
                              tmpstr[k++] = '\\';
                              break;
                          case '\"':
                              if (backslash) k--; else stringends = 1;
                          default:
                              tmpstr[k++] = tail[j];
                              backslash = 0;
                          }
                      }

                      if ( stringends && ( (tmp = (char *)malloc( 1 + j )) != NULL ) )
                      {
                          memcpy( tmp, tmpstr, k);
                          tmp[k-1]=0;
                          formatstrings[i].formatstr = tmp;
                      }
                  }
              }
          }

}

/* UNUSED uncomment if needed 
static void parseknownhosts(char *line) {
}
*/

/* load config file */
void
loadcfg (char *file,void (*lineparser) (char *))
{
  FILE *fh;
#define BUFSIZE 4096
  char buf[BUFSIZE];     /* data buffer */
  char *tildex = NULL, *t;

  /* Check and expand filename then open file */
  if (!file) return;
  tildex = tilde_expand( file );
  if (!tildex) return;
  fh = fopen( tildex, "r" );
  free( tildex );

  if (!fh) {
    snprintf (errstr, TMPSTRSIZE, "Can't open config-file \"%s\": %s.", file, strerror(errno));
    return;
  }

  while ( fgets( buf, sizeof(buf), fh ) ) {
    if( ( t = strchr( buf, '\n' ) ) )
      *t = 0;
    lineparser(buf);
  }

  fclose(fh);
}

void
loadconfig (char *file)
{
  loadcfg(file,parsecfg);
}

void
loadformats (char *file)
{
  loadcfg(file,parseformats);
}

/* get-format-string */
char *
getformatstr (formtstr id)
{
  int i;
  for (i = 0; formatstrings[i].formatstr; i++)
      if (formatstrings[i].id == id) return formatstrings[i].formatstr;
  return NULL;
}

/* get-string-option, fetches *char-value of variable named by option */
char *
getstroption (confopt option)
{
  int i;
#ifdef DEBUG
  fprintf(stderr,"getstroption: %d\n",option);
#endif
  for (i = 0; configoptions[i].type != CO_NIL; i++)
    if ((configoptions[i].id == option) && (configoptions[i].type == CO_STR)) {
      if (!configoptions[i].value)
         return configoptions[i].defaultvalue;
       else
         return configoptions[i].value;
    }
  return NULL;
}

/* set-string-option, puts *char-value to variable named by option */
void
setstroption (confopt option, char *string)
{
  int i;
#ifdef DEBUG
  fprintf(stderr,"setstroption: %d to %s\n",option,string);
#endif
  for (i = 0; configoptions[i].type != CO_NIL; i++)
    if ((configoptions[i].id == option) && (configoptions[i].type == CO_STR)) {
      if (configoptions[i].value)
         free(configoptions[i].value);
      if (string)
         configoptions[i].value = strdup(string);
       else
         configoptions[i].value = NULL;
      if (configoptions[i].localvar.pstr)
         *configoptions[i].localvar.pstr = configoptions[i].value;
    }
}

/* set-named-option, puts string to variable named by name */
void
setnoption (char *name, char *string)
{
  int i;
#ifdef DEBUG
  fprintf(stderr,"setstrnoption: %s to %s\n",name,string);
#endif
  for (i = 0; configoptions[i].type != CO_NIL; i++)
    if (!strcmp(configoptions[i].varname,name)) {
      if (configoptions[i].type == CO_STR) {
        if (configoptions[i].value)
          free(configoptions[i].value);
        if (string)
          configoptions[i].value = strdup(string);
        else
          configoptions[i].value = NULL;
        if (configoptions[i].localvar.pstr)
           *configoptions[i].localvar.pstr = configoptions[i].value;
      } else if (configoptions[i].type == CO_INT) {
        configoptions[i].value = (char *)(uintptr_t)atoi(string);
        if (configoptions[i].localvar.pint)
           *configoptions[i].localvar.pint = (uintptr_t)configoptions[i].value;
      }
    }
}

/* get-integer-option, fetches int-value of variable named by option */
int
getintoption (confopt option)
{
  int i;
#ifdef DEBUG
  fprintf(stderr,"getintoption: %d\n",option);
#endif
  for (i = 0; configoptions[i].type != CO_NIL; i++)
    if ((configoptions[i].id == option) && (configoptions[i].type == CO_INT)) {
      if ((uintptr_t)configoptions[i].value == -1)
         return (uintptr_t) configoptions[i].defaultvalue;   
       else
         return (uintptr_t) configoptions[i].value;
    }
  return 0;
}

/* set-integer-option, puts int-value to variable named by option */
void
setintoption (confopt option, int value)
{
  int i;
#ifdef DEBUG
  fprintf(stderr,"setintoption: %d to %d\n",option,value);
#endif
  for (i = 0; configoptions[i].type != CO_NIL; i++)
    if ((configoptions[i].id == option) && (configoptions[i].type == CO_INT)) {
       configoptions[i].value = (char *)(uintptr_t)value;
       if (configoptions[i].localvar.pint)
          *configoptions[i].localvar.pint = (uintptr_t)configoptions[i].value;
    }
}

int quitrequest = 0;

/* cleanup-hook, for SIGINT */
void
cleanup (int signal)
{
  if( signal == SIGINT ) {
      switch( quitrequest >> 2 ) {
      case 0:
          flushout( );
          writeout( "  Press Ctrl+C twice now to confirm ");
          showout( );
          quitrequest+=4;
          return;
          break;
      case 1:
          flushout( );
          writeout( "  Press Ctrl+C twice now to confirm ");
          writeout( "  Press Ctrl+C once  now to confirm ");
          showout( );
          quitrequest+=4;
          return;
          break;
      default:
          break;
      }
  }
  /* restore terminal state */
  exitui ();
  /* clear userlist */
  ul_clear ();
  /* close server connection */
  if (serverfd > 0)
    close (serverfd);
  /* inform user if we where killed by signal */
  if (signal > 1)
    {
      fprintf (stderr, "vchat-client: terminated with signal %d.\n", signal);
    } else if (errstr[0])
      fputs   (errstr, stderr);
  /* end of story */
  exit (0);
}

static int oldseconds = 0;

void calleverysecond( void ) {
  /* timetriggered execution, don't rely on being called every 1000us */
  /* rather see it as a chance for being called 9 times in 10 seconds */
  /* so check time() */
  time_t now        = time( NULL );
  struct tm *mytime = localtime( &now );
  if( mytime->tm_sec < oldseconds ) {
      consoleline( NULL );
  }
  oldseconds = mytime->tm_sec;

  if(quitrequest)
      quitrequest--;
  if(outputcountdown && !--outputcountdown)
      hideout( );
  if( reconnect_time && ( time( NULL ) > reconnect_time ) )
      status = 0;
}

/* this function is called in the master loop */
void
eventloop (void)
{
  /* get fresh copy of filedescriptor list */
  fd_set readfds = masterfds;
  struct timeval tv = { 1, 0};

  switch (select (serverfd + 2, &readfds, NULL, NULL, &tv))
  {
  case -1:
      /* EINTR is most likely a SIGWINCH - ignore for now */
      if (errno != EINTR)
      {
          snprintf (tmpstr, TMPSTRSIZE, "Select fails, %s.", strerror(errno));
          strncpy(errstr,tmpstr,TMPSTRSIZE-2);
          errstr[TMPSTRSIZE-2] = '\0';
          strcat(errstr,"\n");
          writecf (FS_ERR,tmpstr);
          /* see this as an error condition and bail out */
          status = 0;
       }
       break;
  case 0:
      /* time out reached */
      calleverysecond();
      break;
  default:
      /* something to read from user & we're logged in or have a cert? */
      if (FD_ISSET (0, &readfds) )
        userinput ();

      /* something to read from server? */
      if (serverfd!=-1 && FD_ISSET (serverfd, &readfds))
        networkinput ();
      break;
  }
}

void usage( char *name) {
    printf   ("usage: %s [-C config-file] [-F formats] [-l] [-z] [-s host] [-p port] [-c channel] [-n nickname]\n",name);
    puts     ("   -C   load a second config-file, overriding the first one");
    puts     ("   -F   load format strings (skins) from this file");
    puts     ("   -l   local connect (no SSL)");
    puts     ("   -z   don't use certificate files");
    printf   ("   -s   set server (default \"%s\")\n",getstroption(CF_SERVERHOST));
    printf   ("   -p   set port (default %s)\n",getstroption(CF_SERVERPORT));
    printf   ("   -c   set channel (default %d)\n",getintoption(CF_CHANNEL));
    if (nick)
       printf("   -n   set nickname (default \"%s\")\n",nick);
    else
       puts  ("   -n   set nickname");
    printf   ("   -f   set from (default \"%s\")\n",getstroption(CF_FROM));
    puts     ("   -h   gives this help");
}

/* main - d'oh */
int
main (int argc, char **argv)
{
  int pchar;
  int cmdsunparsed = 1;

  setlocale(LC_ALL,"");

  loadconfig (GLOBAL_CONFIG_FILE);
  loadconfig (getstroption (CF_CONFIGFILE));

  /* parse commandline */
  while (cmdsunparsed) {
      pchar = getopt(argc,argv,"C:F:lzs:p:c:n:f:kKL:h");
#ifdef DEBUG
      fprintf(stderr,"parse commandline: %d ('%c'): %s\n",pchar,pchar,optarg);
#endif

      switch (pchar) {
          case -1 : cmdsunparsed = 0; break;
          case 'C': loadconfig(optarg); break;
          case 'F': setstroption(CF_FORMFILE,optarg); break;
          case 'l': setintoption(CF_USESSL,0); break;
          case 'z': setintoption(CF_USECERT,0); break;
          case 's': setstroption(CF_SERVERHOST,optarg); break;
          case 'p': setstroption(CF_SERVERPORT,optarg); break;
          case 'c': setintoption(CF_CHANNEL,strtol(optarg,NULL,10)); break;
          case 'n': setstroption(CF_NICK,optarg); break;
          case 'f': setstroption(CF_FROM,optarg); break;
          case 'h': usage(argv[0]); exit(0); break;
          default : usage(argv[0]); exit(1);
      }
  }

  if (optind < argc) { usage(argv[0]); exit(1); }

  loadformats(GLOBAL_FORMAT_FILE);
  loadformats(getstroption (CF_FORMFILE));

  /* install signal handler */
  signal (SIGINT, cleanup);
  signal (SIGHUP, cleanup);
  signal (SIGTERM, cleanup);
  signal (SIGQUIT, cleanup);

  /* initialize userinterface */
  initui ();

  while( status ) {
    /* add stdin to masterfds */
    FD_ZERO (&masterfds);
    FD_SET (0, &masterfds);

    /* attempt connection */
    if (vcconnect (getstroption(CF_SERVERHOST), getstroption(CF_SERVERPORT))) {
       snprintf (tmpstr, TMPSTRSIZE, "Could not connect to server, %s.", strerror(errno));
       strncpy(errstr,tmpstr,TMPSTRSIZE-2);
       errstr[TMPSTRSIZE-2] = '\0';
       strcat(errstr,"\n");
       writecf (FS_ERR,tmpstr);

      if( getintoption( CF_AUTORECONN ) ) {
        snprintf (tmpstr, TMPSTRSIZE, "reconnecting in %d seconds", reconnect_delay );
        writecf (FS_ERR, tmpstr);
        reconnect_delay = ( reconnect_delay * 15 ) / 10;
        reconnect_time = time( NULL ) + reconnect_delay;
      } else
        status = 0;
    } else {
      /* add serverfd to masterfds, reset reconnect delay */
      FD_SET (serverfd, &masterfds);
      reconnect_delay = 6;
      reconnect_time  = 0;
    }

    while (status)
      eventloop ();

    /* sanely close connection to server */
    vcdisconnect ();

    if( !ownquit && ( getintoption( CF_AUTORECONN ) || wantreconnect ) )
      status = 1;

    wantreconnect = 0;
  }

  /* call cleanup-hook without signal */
  cleanup (0);
  return 0;
}
