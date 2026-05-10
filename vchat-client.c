/*
 * vchat-client - beta version
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
#include <errno.h>
#include <locale.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <readline/readline.h>

#include "vchat-connection.h"
#include "vchat-user.h"
#include "vchat.h"

/* version of this module */
const char *vchat_cl_version =
    "vchat-client.c     $Id$";

/* externally used variables */
/*   we're logged in */
unsigned int loggedin = 0;
/*   we run as long as this is true */
int status = 1;
/*   we set this, we WANT to quit */
int ownquit = 0;
/*   we set this, we DONT want to quit */
int wantreconnect = 0;

#define RECONNECT_DELAY_INITIAL 6
#define RECONNECT_DELAY_MAX 600
static int reconnect_delay = RECONNECT_DELAY_INITIAL;
static time_t reconnect_time = 0;

/*   error string to show after exit */
char errstr[ERRSTRSIZE] = "\0";

/* declaration of configuration array */
#include "vchat-config.h"

void setnoption(const char *, char *);

static void parsecfg(char *line) {
  int bytes;
  char *param = line;
  char *value = NULL;

  /* handle quotes value is empty, so we can use it */
  value = strchr(line, '#');
  if (value) {       /* the line contains a cute little quote */
    value[0] = '\0'; /* ignore the rest of the line */
  }

  /* now split the line into two parts */
  value = strchr(line, '=');
  if (!value)
    return; /* exit if strchr fails */
  value[0] = '\0';
  value++;

  /* "trim" values */
  while ((value[0] == ' ') || (value[0] == '\t'))
    value++;
  bytes = strlen(value);
  while (bytes > 0 &&
         ((value[bytes - 1] == ' ') || (value[bytes - 1] == '\t'))) {
    value[--bytes] = '\0';
  }
  /* bytes should be strlen(value) */
  if (bytes > 0 && value[bytes - 1] == '"')
    value[--bytes] = '\0';
  if (value[0] == '"')
    value++;

  /* "trim" param */
  while ((param[0] == ' ') || (param[0] == '\t'))
    param++;
  bytes = strlen(param);
  while (bytes > 0 &&
         ((param[bytes - 1] == ' ') || (param[bytes - 1] == '\t'))) {
    param[--bytes] = '\0';
  }
  /* bytes should be strlen(param) */
  if (bytes > 0 && param[bytes - 1] == '\"')
    param[--bytes] = '\0';
  if (param[0] == '\"')
    param++;

  if (!*param)
    return; /* empty key - nothing to set */

  // fprintf(stderr,"\"%s\" -> \"%s\"\n",param,value);
  setnoption(param, value);
}

static void parseformats(char *line) {
  int i;
  char *tmp = NULL;

  /* read a format line from file, syntax is
     FS_XXX = "formatstring"
  */

  while (*line == ' ')
    line++;

  if (strlen(line) > TMPSTRSIZE)
    return;

  if (*line != '#') /* allow to comment out the line */
    for (i = 0; formatstrings[i].formatstr; i++)
      if (!strncasecmp(formatstrings[i].idstring, line,
                       strlen(formatstrings[i].idstring))) {
        char *tail = line + strlen(formatstrings[i].idstring);
        while (*tail == ' ' || *tail == '\t')
          tail++; /* and skip whitespaces */

        if (*tail++ == '=') {
          while (*tail == ' ' || *tail == '\t')
            tail++;
          if (*(tail++) == '\"') {
            int j, k = 0, stringends = 0, backslash = 0;
            for (j = 0; tail[j] && !stringends; j++) {
              switch (tail[j]) {
              case '^':
                if (tail[j + 1] != '^')
                  tmpstr[k++] = 1;
                break;
              case '\\':
                backslash = 1 - backslash;
                tmpstr[k++] = '\\';
                break;
              case '\"':
                if (backslash)
                  k--;
                else
                  stringends = 1;
              default:
                tmpstr[k++] = tail[j];
                backslash = 0;
              }
            }

            if (stringends && ((tmp = (char *)malloc(1 + j)) != NULL)) {
              memcpy(tmp, tmpstr, k);
              tmp[k - 1] = 0;
              formatstrings[i].formatstr = tmp;
            }
          }
        }
      }
}

/* load config file */
void loadcfg(char *file, int complain, void (*lineparser)(char *)) {
  FILE *fh;
#define BUFSIZE 4096
  char buf[BUFSIZE]; /* data buffer */
  char *tildex = NULL, *t;

  /* Check and expand filename then open file */
  if (!file)
    return;
  tildex = tilde_expand(file);
  if (!tildex)
    return;
  fh = fopen(tildex, "r");
  free(tildex);

  if (!fh) {
    if (complain)
      snprintf(errstr, TMPSTRSIZE, "Can't open config-file \"%s\": %s.", file,
               strerror(errno));
    return;
  }

  while (fgets(buf, sizeof(buf), fh)) {
    if ((t = strchr(buf, '\n')))
      *t = 0;
    lineparser(buf);
  }

  fclose(fh);
}

void loadconfig(char *file) { loadcfg(file, 1, parsecfg); }

void loadformats(char *file) { loadcfg(file, 0, parseformats); }

/* get-format-string */
char *getformatstr(formtstr id) {
  int i;
  for (i = 0; formatstrings[i].formatstr; i++)
    if (formatstrings[i].id == id)
      return formatstrings[i].formatstr;
  return NULL;
}

/* get-string-option, fetches *char-value of variable named by option */
char *getstroption(confopt option) {
  int i;
#ifdef DEBUG
  fprintf(stderr, "getstroption: %d\n", option);
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
void setstroption(confopt option, char *string) {
  int i;
#ifdef DEBUG
  fprintf(stderr, "setstroption: %d to %s\n", option, string);
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
void setnoption(const char *name, char *string) {
  int i;
#ifdef DEBUG
  fprintf(stderr, "setstrnoption: %s to %s\n", name, string);
#endif
  for (i = 0; configoptions[i].type != CO_NIL; i++)
    if (!strcmp(configoptions[i].varname, name)) {
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
int getintoption(confopt option) {
  int i;
#ifdef DEBUG
  fprintf(stderr, "getintoption: %d\n", option);
#endif
  for (i = 0; configoptions[i].type != CO_NIL; i++)
    if ((configoptions[i].id == option) && (configoptions[i].type == CO_INT)) {
      if ((intptr_t)configoptions[i].value == -1)
        return (intptr_t)configoptions[i].defaultvalue;
      else
        return (intptr_t)configoptions[i].value;
    }
  return 0;
}

/* set-integer-option, puts int-value to variable named by option */
void setintoption(confopt option, int value) {
  int i;
#ifdef DEBUG
  fprintf(stderr, "setintoption: %d to %d\n", option, value);
#endif
  for (i = 0; configoptions[i].type != CO_NIL; i++)
    if ((configoptions[i].id == option) && (configoptions[i].type == CO_INT)) {
      configoptions[i].value = (char *)(uintptr_t)value;
      if (configoptions[i].localvar.pint)
        *configoptions[i].localvar.pint = (uintptr_t)configoptions[i].value;
    }
}

/* Touched by the SIGINT handler (cleanup) and decremented by the main
 * eventloop in calleverysecond().  Must be sig_atomic_t so the read-
 * modify-write in the handler races safely against the main loop's
 * decrement, and volatile so the compiler doesn't cache the value
 * across the signal-handler boundary. */
volatile sig_atomic_t quitrequest = 0;

/* cleanup-hook, for SIGINT */
void cleanup(int signal) {
  if (signal == SIGINT) {
    switch (quitrequest >> 2) {
    case 0:
      flushout();
      writeout("  Press Ctrl+C twice now to confirm ");
      showout();
      quitrequest += 4;
      return;
      break;
    case 1:
      flushout();
      writeout("  Press Ctrl+C twice now to confirm ");
      writeout("  Press Ctrl+C once  now to confirm ");
      showout();
      quitrequest += 4;
      return;
      break;
    default:
      break;
    }
  }
  /* restore terminal state */
  exitui();
  /* clear userlist */
  ul_clear();
  vc_disconnect();

  /* inform user if we where killed by signal */
  if (signal > 1) {
    fprintf(stderr, "vchat-client: terminated with signal %d.\n", signal);
    if (!loggedin)
      dumpconnect();
  } else if (errstr[0]) {
    fputs(errstr, stderr);
    if (!loggedin)
      dumpconnect();
  }
  /* end of story */
  exit(0);
}

static int oldseconds = 0;

void calleverysecond(void) {
  /* timetriggered execution, don't rely on being called every 1000us */
  /* rather see it as a chance for being called 9 times in 10 seconds */
  /* so check time() */
  time_t now = time(NULL);
  struct tm *mytime = localtime(&now);
  if (mytime->tm_sec < oldseconds) {
    consoleline(NULL);
  }
  oldseconds = mytime->tm_sec;

  if (quitrequest)
    quitrequest--;
  if (outputcountdown && !--outputcountdown)
    hideout();
  if (reconnect_time && (time(NULL) > reconnect_time))
    status = 0;
}

/* this function is called in the master loop */
void eventloop(void) {
  int poll_result = vc_poll(1 /* second timeout */);

  switch (poll_result) {
  case -1:
    /* EINTR is most likely a SIGWINCH - ignore for now */
    if (errno != EINTR) {
      snprintf(tmpstr, TMPSTRSIZE, "Select fails, %s.", strerror(errno));
      strncpy(errstr, tmpstr, TMPSTRSIZE - 2);
      errstr[TMPSTRSIZE - 2] = '\0';
      strcat(errstr, "\n");
      writecf(FS_ERR, tmpstr);
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
    if (poll_result & 1)
      userinput();

    /* something to read from server? */
    if ((poll_result & 2) && vc_receive())
      status = 0;
    break;
  }
}

void usage(char *name) {
  printf("usage: %s [-C config-file] [-F formats] [-l] [-z] [-s host] [-p "
         "port] [-c channel] [-n nickname]\n",
         name);
  puts("   -C   load a second config-file, overriding the first one");
  puts("   -F   load format strings (skins) from this file");
  puts("   -l   local connect (no SSL)");
  puts("   -z   don't use certificate files");
  printf("   -s   set server (default \"%s\")\n", getstroption(CF_SERVERHOST));
  printf("   -p   set port (default %s)\n", getstroption(CF_SERVERPORT));
  printf("   -c   set channel (default %d)\n", getintoption(CF_CHANNEL));
  if (own_nick_get())
    printf("   -n   set nickname (default \"%s\")\n", own_nick_get());
  else
    puts("   -n   set nickname");
  printf("   -f   set from (default \"%s\")\n", getstroption(CF_FROM));
  puts("   -h   gives this help");
  puts("   -v   show module versions");
}

void versions() {
  puts(vchat_cl_version);
  puts(vchat_ui_version);
  puts(vchat_cn_version);
  puts(vchat_io_version);
  puts(vchat_us_version);
  puts(vchat_cm_version);
  puts(vchat_tls_version);
  puts(vchat_tls_version_external());
}

/* main - d'oh */
int main(int argc, char **argv) {
  int pchar;
  int cmdsunparsed = 1;

  setlocale(LC_ALL, "");

  loadconfig(GLOBAL_CONFIG_FILE);
  loadconfig(getstroption(CF_CONFIGFILE));

  /* parse commandline */
  while (cmdsunparsed) {
    pchar = getopt(argc, argv, "C:F:lzs:p:c:n:f:kKL:hv");
#ifdef DEBUG
    fprintf(stderr, "parse commandline: %d ('%c'): %s\n", pchar, pchar, optarg);
#endif

    switch (pchar) {
    case -1:
      cmdsunparsed = 0;
      break;
    case 'C':
      loadconfig(optarg);
      break;
    case 'F':
      setstroption(CF_FORMFILE, optarg);
      break;
    case 'l':
      setintoption(CF_USESSL, 0);
      break;
    case 'z':
      setintoption(CF_USECERT, 0);
      break;
    case 's':
      setstroption(CF_SERVERHOST, optarg);
      break;
    case 'p':
      setstroption(CF_SERVERPORT, optarg);
      break;
    case 'c':
      setintoption(CF_CHANNEL, strtol(optarg, NULL, 10));
      break;
    case 'n':
      own_nick_set(optarg);
      break;
    case 'f':
      setstroption(CF_FROM, optarg);
      break;
    case 'h':
      usage(argv[0]);
      exit(0);
      break;
    case 'v':
      versions();
      exit(0);
      break;
    default:
      usage(argv[0]);
      exit(1);
    }
  }

  if (optind < argc) {
    usage(argv[0]);
    exit(1);
  }

  loadformats(GLOBAL_FORMAT_FILE);
  loadformats(getstroption(CF_FORMFILE));

  /* install signal handlers via sigaction() so behaviour is identical
   * across Linux / *BSD / macOS - signal(2) has historically reset
   * handlers to SIG_DFL on delivery on some systems.  We also block
   * SIGINT/SIGHUP/SIGTERM/SIGQUIT during handler execution so the
   * handler can't be re-entered before it has updated its state.
   *
   * SA_RESTART matches the previous signal(2) behaviour on glibc
   * (BSD-style restart of interrupted syscalls). */
  {
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGQUIT);
    sa.sa_flags = SA_RESTART;

    sa.sa_handler = cleanup;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGQUIT, &sa, NULL);
  }

  /* initialize userinterface */
  initui();

  while (status) {
    /* attempt connection */
    if (vc_connect(getstroption(CF_SERVERHOST), getstroption(CF_SERVERPORT))) {
      snprintf(tmpstr, TMPSTRSIZE, "Could not connect to server, %s.",
               strerror(errno));
      strncpy(errstr, tmpstr, TMPSTRSIZE - 2);
      errstr[TMPSTRSIZE - 2] = '\0';
      strcat(errstr, "\n");
      writecf(FS_ERR, tmpstr);

      if (getintoption(CF_AUTORECONN)) {
        snprintf(tmpstr, TMPSTRSIZE, "reconnecting in %d seconds",
                 reconnect_delay);
        writecf(FS_ERR, tmpstr);
        reconnect_time = time(NULL) + reconnect_delay;
        reconnect_delay = (reconnect_delay * 15) / 10;
        if (reconnect_delay > RECONNECT_DELAY_MAX)
          reconnect_delay = RECONNECT_DELAY_MAX;
      } else
        status = 0;
    } else {
      /* reset reconnect delay */
      reconnect_delay = RECONNECT_DELAY_INITIAL;
      reconnect_time = 0;
    }

    while (status)
      eventloop();

    /* sanely close connection to server */
    vc_disconnect();

    if (!ownquit && (getintoption(CF_AUTORECONN) || wantreconnect))
      status = 1;

    wantreconnect = 0;
  }

  /* call cleanup-hook without signal */
  cleanup(0);
  return 0;
}
