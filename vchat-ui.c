/*
 * vchat-client - alpha version
 * vchat-ui.c - user-interface and readline handling
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
#include <ncurses.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <time.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <openssl/pem.h>
#include <regex.h>
#include "vchat.h"

/* version of this module */
unsigned char *vchat_ui_version = "$Id$";

/* externally used variables */
/*   current string in topic window */
unsigned char topicstr[TOPICSTRSIZE] = "[] VChat 0.16";
/*   current string in console window */
unsigned char consolestr[CONSOLESTRSIZE] = "[ Get help: .h for server /h for client commands";

static unsigned int    ui_init          = 0;

/* our windows */
static WINDOW         *console          = NULL;
static WINDOW         *input            = NULL;
static WINDOW         *topic            = NULL;
static WINDOW         *channel          = NULL;
static WINDOW         *private          = NULL;
static WINDOW         *output           = NULL;

static FILE           *vchat_logfile    = NULL;

/* our screen dimensions */
static int             screensx         = 0;
static int             screensy         = 0;
/* length of last input on line (for clearing) */
static int             lastlen          = 0;
/* current horizontal scrolling offset for input line */
static int             scroff           = 0;
/* cache for stepping value of horizontal scrolling */
unsigned int           hscroll          = 0;

static int             outputshown      = 0;
static int             outputwidth_desired = 0;

static int             privheight       = 0;
static int             privheight_desired = 0;
static int             privwinhidden    = 0;
int                    usetime          = 1;
int                    outputcountdown  = 0;

struct sb_entry {
  int                id;
  time_t             when;
  int                stamp;
  unsigned char     *what;
  struct sb_entry   *link;
};

struct sb_data {
  struct sb_entry   *entries;
  struct sb_entry   *last;
  int                count;
  int                scroll;
};

static struct sb_data *sb_pub          = NULL;
static struct sb_data *sb_priv         = NULL;
static struct sb_data *sb_out          = NULL;

/* Tells, which window is active */
static int             sb_win          = 0; /* 0 for pub, 1 for priv */

/*   struct to keep filter list */
struct filt {
  unsigned char        colour;
  unsigned int         id;
  unsigned char       *text;
  regex_t              regex;
  struct   filt       *next;
};

typedef struct filt    filt;

static filt           *filterlist   = NULL;
static int             filtertype   = 0;
static int             currentstamp = 0;

/* Prototype declarations */

static void resize           (int);
static void drawwin          (WINDOW *win, struct sb_data  *sb);
static int  writescr         (WINDOW *win, struct sb_entry *entry);
static int  testfilter       (             struct sb_entry *entry);
static int  gettextwidth     (char *textbuffer);
static void resize_output    (void);
static int  getsbeheight     (struct sb_entry *entry, const int xwidth, int needstime );
static int  getsbdataheight  (struct sb_data *data, const int xwidth, int needstime );
/* CURRENTLY UNUSED
static void writecolorized   (WINDOW *win, unsigned char *string);
*/

enum {
  RMFILTER_RMANDCONT,
  RMFILTER_RMANDSTOP,
  RMFILTER_KEEPANDCONT,
  RMFILTER_KEEPANDSTOP
};

/* readlines callback when a line is completed */
static void
linecomplete (unsigned char *line)
{
  int i;

  /* send linefeed, return pointer, reset cursors */
  waddch (input, '\n');
  wmove (input, 0, 0);
  rl_point = 0;
  scroff = 0;

  if (line) {
      i = strlen(line)-1;
      while (line[i] == ' ') line[i--]='\0';

      if (line[0] && strchr(line,' ') == NULL && line[i] == ':')
          line[i--] = '\0';

      /* empty line? nada. */
      if (!line[0])
	return;

      /* add line to history and have it handled in vchat-protocol.c */
      add_history (line);
      handleline (line);
      free (line);

      /* wipe input line and reset cursor */
      wmove (input, 0, 0);
      for (i = 0; i < input->_maxx; i++)
      waddch (input, ' ');
      wmove (input, 0, 0);
      wrefresh (input);
  }
}

/* redraw-callback for readline */
static void
vciredraw (void)
{
  int i;
  /* hscroll value cache set up? */
  if (!hscroll)
    {
      /* check config-option or set hardcoded default */
      hscroll = getintoption (CF_HSCROLL);
      if (!hscroll)
	hscroll = 5;
    }

  /* calculate horizontal scrolling offset */
  if (rl_point - scroff < 0)
    scroff = rl_point - 4;
  if (rl_point - scroff > input->_maxx)
    scroff = rl_point - input->_maxx + 2;
  if (rl_point - scroff > input->_maxx - (hscroll - 2))
    scroff += hscroll;
  else if (rl_point - scroff < input->_maxx - (hscroll + 2))
    scroff -= hscroll;
  if (scroff < 0)
    scroff = 0;

  /* wipe input line */
  wmove (input, 0, 0);
  for (i = 0; i < input->_maxx; i++)
  waddch (input, ' ');

  /* show current line, move cursor, redraw! */
  mvwaddnstr (input, 0, 0, &rl_line_buffer[scroff], input->_maxx);
  wmove (input, 0, rl_point - scroff);
  wrefresh (input);
}

/* called by the eventloop in vchat-client.c */
void
userinput (void)
{
  /* let readline handle what the user typed .. */
  rl_callback_read_char ();
}

static int
calcdrawcus (unsigned char * const str) {
  unsigned char *tmp = str;
  int zero = 0;
  while( *tmp && (*tmp!=' ') && (*tmp!='\n')) { if(*tmp==1) zero+=2; tmp++; }
  return (tmp - str) - zero;
}

static void
sb_flush ( struct sb_data *sb ) {
  struct sb_entry *now = sb->entries, *prev = NULL, *tmp;
  while( now ) {
      tmp  = (struct sb_entry*)((unsigned long)prev ^ (unsigned long)now->link);
      free(now->what );
      free(now);
      prev = now;
      now  = tmp;
  }
  sb->entries = NULL;
}

/*static void
sb_clear ( struct sb_data **sb ) {
  sb_flush(*sb);
  free( *sb );
  *sb = NULL;
}*/

static struct sb_entry*
sb_add (struct sb_data *sb, unsigned char *line, time_t when) {
  struct sb_entry *newone = malloc (sizeof(struct sb_entry));
  if( newone ) {
      if( sb->count == sb->scroll ) sb->scroll++;
      newone->id   = sb->count++;
      newone->when = when;
      newone->what = strdup(line);
      newone->link = sb->entries;
      newone->stamp= 0xffff;
      if( sb->entries )
          sb->entries->link = (struct sb_entry*)((unsigned long)sb->entries->link ^ (unsigned long)newone);
      else
          sb->last     = newone;
      sb->entries  = newone;
  }
  return newone;
}

void flushout ( )
{
  sb_flush(sb_out);
  writeout(" ");
  outputwidth_desired = 0;
  outputshown = 0;
}

void hideout( )
{
  if( outputshown ) {
      outputshown = 0;
      resize(0);
  }
}

void showout (void)
{
  writeout(" ");
  outputcountdown = 6;
  outputshown = 1;
  resize(0);
}

void writeout (unsigned char *str)
{
  int i;
  sb_add(sb_out,str,time(NULL));
  i = 1 + gettextwidth( str );
  if( i > outputwidth_desired ) outputwidth_desired = i;
}

int writechan (unsigned char *str) {
  struct sb_entry *tmp;
  int i = 0;
  time_t now = time(NULL);
  tmp = sb_add(sb_pub,str,now);

  if( getintoption( CF_KEEPLOG ) && vchat_logfile )
      fprintf( vchat_logfile, "%016llX0%s\n", (signed long long)now, str);

  if ( (sb_pub->scroll == sb_pub->count) && ((filtertype == 0) || ( testfilter(tmp)))) {
     i = writescr(channel, tmp);
     wnoutrefresh(channel);
  }
  consoleline(NULL);
  return i;
}

int writecf (formtstr id,unsigned char *str) {
  struct sb_entry *tmp;
  int i = 0;
  time_t now = time(NULL);
  snprintf(tmpstr,TMPSTRSIZE,getformatstr(id),str);
  tmp = sb_add(sb_pub,tmpstr,now);

  if( getintoption( CF_KEEPLOG ) && vchat_logfile )
      fprintf( vchat_logfile, "%016llX0%s\n", (unsigned long long)now, tmpstr);

  if ( (sb_pub->scroll == sb_pub->count) &&
       ((filtertype == 0) || ( testfilter(tmp)))) {
      i = writescr(channel, tmp);
      wnoutrefresh(channel);
  }
  consoleline(NULL);
  return i;
}

int writepriv (unsigned char *str, int maybeep) {
  int i = 0;
  if (private) {

      time_t now = time (NULL);
      struct sb_entry *tmp;
      tmp = sb_add(sb_priv,str,now);

      if( getintoption( CF_KEEPLOG ) && vchat_logfile ) {
          fprintf( vchat_logfile, "%016llX1%s\n", (unsigned long long)now, str);
      }

      if ( !privwinhidden && (sb_priv->scroll == sb_priv->count) &&
           ((filtertype == 0) || ( testfilter(tmp)))) {
          i = writescr(private, tmp);
      }
      if( privwinhidden ) {
          if( (maybeep != 0) && (getintoption( CF_BELLPRIV ) != 0 ))
            putchar( 7 );
          privheight_desired = privwinhidden;
          privwinhidden      = 0;
          resize(0);
      }
      wnoutrefresh(private);
      topicline(NULL);
  } else
      i = writechan( str );

  return i;
}

/* Get #if 's out of code */

#if NCURSES_VERSION_MAJOR >= 5

typedef struct {
    attr_t attr;
    short  pair;
} ncurs_attr;

#define WATTR_GET( win, orgattr ) wattr_get( win, &orgattr.attr, &orgattr.pair, NULL)
#define WATTR_SET( win, orgattr ) wattr_set( win,  orgattr.attr,  orgattr.pair, NULL)
#define BCOLR_SET( attr, colour ) attr->pair = colour;

#else

typedef struct {
    attr_t attr;
} ncurs_attr;

#define WATTR_GET( win, orgattr ) orgattr.attr = wattr_get(win);
#define WATTR_SET( win, orgattr ) wattr_set( win, orgattr.attr);
#define BCOLR_SET( attr, colour ) attr->attr = ((attr->attr) & ~A_COLOR) | COLOR_PAIR((colour));

#endif

/* 'A' - 'Z' attriute type */
static int attributes[] = { A_ALTCHARSET, A_BOLD, 0, A_DIM, 0, 0, 0, 0, A_INVIS, 0, 0, A_BLINK,
                     0, A_NORMAL, 0, A_PROTECT, 0, A_REVERSE, A_STANDOUT, 0, A_UNDERLINE,
                     0, 0, 1, 0, 0 };

static void
docolorize (unsigned char colour, ncurs_attr *attr, ncurs_attr orgattr) {
  if( colour== '0') {
      *attr = orgattr;
  } else if( ( colour > '0') && ( colour <= '9')) {
      BCOLR_SET( attr, colour - '0' );
  } else {
      unsigned char upc = colour & ( 0x20 ^ 0xff ); /* colour AND NOT 0x20 */
      attr_t        newattr;
      if( ( upc >= 'A') && ( upc<='Z' ) && ( newattr = attributes[upc - 'A']) )
          attr->attr = ( colour & 0x20 ) ? attr->attr | newattr : attr->attr & ~newattr;
  }
}  

/* draw arbitrary strings */
static int
writescr ( WINDOW *win, struct sb_entry *entry ) {
  unsigned char tmp [64];
  int charcount = 0;
  int i;
  int textlen   = strlen( entry->what );
  int timelen   = ((win == channel)||(win == private)) && usetime ?
      (int)strftime(tmp,64,getformatstr(FS_TIME),localtime(&entry->when)) : 0;
  unsigned char textbuffer[ textlen+timelen+1 ];
  ncurs_attr    attrbuffer[ textlen+timelen+1 ];
  ncurs_attr    orgattr;

  /* illegal window? return */
  if( !win || !(textlen+timelen)) return 0;

  /* store original attributes */
  WATTR_GET( win, orgattr);
  attrbuffer[ 0 ] = orgattr;
  
  /* copy time string */
  for( i = 0; i < timelen; i++ )
      if( tmp[ i ] == 1 ) {
          docolorize( tmp[++i], attrbuffer+charcount, orgattr);
      } else {
          attrbuffer[ charcount+1 ] = attrbuffer[ charcount ];
          textbuffer[ charcount++ ] = tmp[ i ];
      }

  timelen     = charcount;

  /* copy text */
  for( i = 0; i< textlen; i++ )
      if( entry->what[ i ] == 1 ) {
          docolorize( entry->what[++i], attrbuffer+charcount, orgattr);
      } else {
          attrbuffer[ charcount+1 ] = attrbuffer[ charcount ];
          textbuffer[ charcount++ ] = entry->what[ i ];
      }

  /* zero terminate text --- very important :) */
  textbuffer[ charcount ] = 0;

  /* hilite */
  if((win == channel)||(win == private)) { /* do not higlight bars */
      filt          *flt   = filterlist;
      unsigned char *instr = textbuffer;
      regmatch_t    match;
      int           j;

      while( flt ) {
          if ( (flt->colour != '-') && (flt->colour != '+')) {
              i = timelen;
              while( i < charcount ) {
                  if( regexec( &flt->regex, instr+i, 1, &match, 0 )) {
                      i = charcount;
                  } else {
                      for( j = i + match.rm_so; j < i + match.rm_eo; j++)
                          docolorize( flt->colour, attrbuffer+j, orgattr );
                      i += 1 + match.rm_so;
                  }
              }
          }
          flt = flt->next;
      }
  }

  if (win->_curx) waddch(win,'\n');

  for( i = 0; i < charcount; i++ ) {
      /* on start of line or attribute changes set new attribute */
      if( !i || memcmp( attrbuffer+i, attrbuffer+i-1, sizeof(ncurs_attr)))
          WATTR_SET( win, attrbuffer[i]);
      if( textbuffer[ i ] == ' ') {
          if ((calcdrawcus(textbuffer+i+1) + win->_curx > win->_maxx - 1)&&
              (calcdrawcus(textbuffer+i+1) < win->_maxx)) {
              /* line wrap found */
              WATTR_SET( win, orgattr);
              waddstr( win, "\n   ");
              WATTR_SET( win, attrbuffer[ i ]);
          }
      }
      /* plot character */
      waddch( win, textbuffer[ i ]);
  }

  /* restore old attributes */
  WATTR_SET (win, orgattr);

  return charcount;
}

static void
writelog_processentry ( FILE *file, struct sb_entry* entry )
{
  char *outtmp;
  int  outoff = 0;
  if( usetime ) {
      outtmp = tmpstr+64;
      strftime(outtmp,64,getformatstr(FS_TIME),localtime(&entry->when));
      while(*outtmp)
          if( *outtmp > 1 )
              tmpstr[outoff++] = *(outtmp++);
          else 
              if( *(++outtmp))
                  outtmp++;
  }

  outtmp = entry->what;
  while(*outtmp)
      while(*outtmp && ( outoff < TMPSTRSIZE-1) ) {
         if( *outtmp > 1 )
             tmpstr[outoff++] = *(outtmp++);
         else
             if( *(++outtmp))
                 outtmp++;
      tmpstr[outoff]=0; outoff = 0;
      fputs( tmpstr, file );
  }

  fputc( '\n', file);
}

void
writelog_i ( FILE *file)
{
  if( !private ) {
      writelog( file);
  } else {
      struct sb_entry *now1= sb_pub->last, *prev1 = NULL, *tmp;
      struct sb_entry *now2= sb_priv->last, *prev2 = NULL;
      fputs( "Interleaved messages:\n\n", file);
      while( now1 || now2 ) {
          int process;
          if( now1 && now2 ) {
              process = ( now1->when < now2->when ) ? 1 : 2;
          } else {
              process = now1 ? 1 : 2;
          }

          if( process == 1 ) {
              writelog_processentry( file, now1 );
              tmp = now1; now1 = (struct sb_entry*)((unsigned long)now1->link ^ (unsigned long)prev1); prev1 = tmp;
          } else {
              writelog_processentry( file, now2 );
              tmp = now2; now2 = (struct sb_entry*)((unsigned long)now2->link ^ (unsigned long)prev2); prev2 = tmp;
          }
      }
  }
}

void
writelog ( FILE *file )
{
  if( sb_pub->last ) {
      struct sb_entry *now = sb_pub->last, *prev = NULL, *tmp;
      fputs( "Public messages:\n\n", file);
      while( now ) {
          writelog_processentry( file, now );
          tmp = now; now = (struct sb_entry*)((unsigned long)now->link ^ (unsigned long)prev); prev = tmp;
      }
      putc( '\n', file );
  }
  if( private && sb_priv->last ) {
      struct sb_entry *now = sb_priv->last, *prev = NULL, *tmp;
      fputs( "Private messages:\n\n", file);
      while( now ) {
          writelog_processentry( file, now );
          tmp = now; now = (struct sb_entry*)((unsigned long)now->link ^ (unsigned long)prev); prev = tmp;
      }
  }
}

static void
resize_output ( )
{
  int outputwidth  = (outputwidth_desired + 7 > screensx) ? screensx - 7 : outputwidth_desired;
  int outputheight = getsbdataheight(sb_out, outputwidth-1, 0);

  if (outputheight + 5 > screensy ) outputheight = screensy - 5;
  wresize(output,outputheight,outputwidth);
  mvwin(output,(screensy-outputheight)>>1,(screensx-outputwidth)>>1);
  drawwin(output, sb_out);
}

static void
doscroll( int up ) {
  WINDOW *destwin = (sb_win && private) ? private : channel;
  struct sb_data *sb = (sb_win && private) ? sb_priv : sb_pub;
  struct sb_entry *now = sb->entries, *prev = NULL, *tmp;
  int lines = destwin->_maxy>>1;

  if( sb->scroll != sb->count )
      while( now && (now->id != sb->scroll) ) {
         tmp = now; now = (struct sb_entry*)((unsigned long)now->link ^ (unsigned long)prev); prev = tmp;
      }

  if( !up ) {
      prev = (struct sb_entry*)((unsigned long)now->link ^ (unsigned long)prev);
      tmp = now; now = (struct sb_entry*)((unsigned long)now->link ^ (unsigned long)prev); prev = tmp;
  }

  while( now && (lines > 0)) {
      if ( (!filtertype) || ( (now->stamp != currentstamp) && ( (now->stamp == (currentstamp | (1<<15))) || testfilter( now ) ) ) )
      {
          lines -= getsbeheight( now, destwin->_maxx, usetime );
      }
      tmp = now; now = (struct sb_entry*)((unsigned long)now->link ^ (unsigned long)prev); prev = tmp;
  }
  if( now )
      sb->scroll = now->id;
  else
      if( !up ) sb->scroll = sb->count;

  drawwin(destwin, sb);
  wnoutrefresh(destwin);
  if( sb_win && private ) topicline(NULL); else consoleline(NULL);
}


void
scrollup (void)
{
  doscroll( 1 );
}

void
scrolldown (void)
{
  doscroll( 0 );
}

void
scrollwin (vod)
{
    if (!sb_win && private && !privwinhidden) sb_win = 1;
    else sb_win = 0;
    topicline(NULL);
    consoleline(NULL);
}

void
growprivwin (vod) {
    if( private ) {
      if( privwinhidden)
          privwinhidden = 0;
      if( ++privheight_desired > screensy - 5)
          privheight_desired = screensy - 5;
      resize(0);
    }
}

void toggleprivwin (vod) {
  if( outputshown ) {
      outputshown = 0;
      resize(0);
  } else {
       if( private ) {
           if( privwinhidden ) {
               privheight_desired = privwinhidden;
               privwinhidden      = 0;
           } else {
               privwinhidden      = privheight_desired;
               privheight_desired = 1;
               sb_win             = 0;
               sb_priv->scroll    = sb_priv->count;
           }
        resize(0);
       }
  }
}

void
shrinkprivwin (vod) {
    if( private && !privwinhidden ) {
      if( --privheight_desired < 1) privheight_desired = 1;
      if(   privheight_desired > screensy - 5)  privheight_desired = screensy - 5;
      resize(0);
    }
}

/* nick completion callback for readline */
static char **
vcccomplete (char *text, int start, int end)
{
  char **matches;
  matches = (char **) NULL;
  /* are we at start of line, with no characters typed? message completion */
  if (start == 0 && end == 0)
    {
#ifdef OLDREADLINE
      matches = completion_matches (text, (CPFunction *) ul_mnickcomp);
#else
      matches = rl_completion_matches (text, (rl_compentry_func_t *) ul_mnickcomp);
#endif
      rl_attempted_completion_over = 1;
    }
  /* start of line? get matches for channel! */
  else if (start == 0)
    {
#ifdef OLDREADLINE
      matches = completion_matches (text, (CPFunction *) ul_cnickcomp);
#else
      matches = rl_completion_matches (text, (rl_compentry_func_t *) ul_cnickcomp);
#endif
      /* no, we want no 'normal' completion if started typing on the beginning
       * of the line */
      rl_attempted_completion_over = 1;
    }
  return (matches);
}

/* clear message window */
void
clearpriv ()
{
  WINDOW *dest = NULL;
  /* do we have a private window? */
  if (private)
      dest = private;
  else
      dest = channel;

  /* clear window, move cursor to bottom, redraw */
  wclear (dest);
  wmove (dest, dest->_maxy, dest->_maxx);
  wrefresh (dest);
}

/* clear channel window */
void
clearchan ()
{
  /* clear window, move cursor to bottom, redraw */
  wclear (channel);
  wmove (channel, channel->_maxy, channel->_maxx);
  wrefresh (channel);
}

/* Get window size */

void ttgtsz(int *x,int *y) {
#ifdef TIOCGSIZE
   struct ttysize getit;
#else
#ifdef TIOCGWINSZ
   struct winsize getit;
#endif
#endif

   *x=0; *y=0;
#ifdef TIOCGSIZE
   if(ioctl(1,TIOCGSIZE,&getit)!= -1) {
     *x=getit.ts_cols;
     *y=getit.ts_lines;
    }
#else
#ifdef TIOCGWINSZ
    if(ioctl(1,TIOCGWINSZ,&getit)!= -1) {
     *x=getit.ws_col;
     *y=getit.ws_row;
    }
#endif
#endif
 }

static void
redraw (void)
{
  sb_pub->scroll = sb_pub->count;
  sb_priv->scroll = sb_priv->count;

  resize(0);
}

/* resize display on SIGWINCH
   Nowadays used as our main redraw trigger engine */
void
resize (int signal)
{
  int xsize,ysize,topicheight=topic?1:0;

  ttgtsz(&xsize,&ysize);
  resizeterm(ysize,xsize);

  /* store screen-dimensions to local functions */
  getmaxyx (stdscr, screensy, screensx);

  /* desired height of PM window is user controllable,
     actual size depends on space available on screen */
  if (!privheight_desired)
    privheight_desired = getintoption(CF_PRIVHEIGHT);

  /* Leave at least 5 lines for input, console and
     pubchannel */
  if ( privheight_desired > screensy - 5)
      privheight = screensy - 5;
  else
      privheight = privheight_desired;

  /* check dimensions or bump user */
  if (screensy - privheight < 4)
    {
        fprintf (stderr, "vchat-client: screen to short (only %d rows, at least %d expected), bailing out.\n", screensy, privheight + 6);
        snprintf (errstr, ERRSTRSIZE, "vchat-client: screen to short (only %d rows, at least %d expected), bailing out.\n", screensy, privheight + 6);
        cleanup (0);
    }
  if (screensx < 14)
    {
        fprintf (stderr, "vchat-client: screen to thin (only %d cols, at least %d expected), bailing out.\n", screensx, 14);
        snprintf (errstr, ERRSTRSIZE, "vchat-client: screen to thin (only %d cols, at least %d expected), bailing out.\n", screensx, 14);
        cleanup (0);
    }

  /*****
   * Arrange windows on screen
   *****/

  /* console and input are always there and always 1 line tall */
  wresize(console,1,screensx);
  wresize(input,1,screensx);

  /* If we got a private window and it is not hidden, set its size */
  if (private && !privwinhidden)
      wresize(private,privheight,screensx);

  /* If oldschool vchat is not enabled, we have a topic line */
  if( topic )
      wresize(topic,1,screensx);

  /* public channel is always their and its height depends on:
     * existence and visibility of priv window
     * existence of a topic line (oldschool vchat style)
  */
  wresize(channel, ( !private || privwinhidden ) ? screensy - ( topicheight + 2 ) : screensy - (privheight + ( topicheight + 2 )), screensx);

  /* Console and input alway take bottommost lines */
  mvwin(console,screensy-2,0);
  mvwin(input,screensy-1,0);

  /* Private window always is top left */
  if(private && !privwinhidden)
      mvwin(private,0,0);

  /* Topic window may not exist without priv window, so it is
     safe to assume sane values for privwinhidden and privheight */
  if( topic )
      mvwin(topic,privwinhidden ? 0 : privheight, 0);

  /* chan window starts below private window and topic line */
  mvwin(channel, ( !private || privwinhidden ) ? topicheight : privheight + topicheight, 0);

  /*******
   * Now actual redraw starts, note, that we only fill
   * curses *WINDOW* buffers, changes reflect on screen
   * only, after they've been drawn to curses virtual
   * screen buffers by wnoutrefresh and this offscreen
   * buffer gets painted to terminal. This is triggered
   * by consoleline(), traditionally last window to be
   * drawn
   ******/

  /* pub channel is always there, paint scrollback buffers */
                  drawwin(channel, sb_pub);
  /* if priv exists and is visible, paint scrollback buffers */
  if(private && !privwinhidden )
                  drawwin(private, sb_priv);
  /* Send window's contents to curses virtual buffers */
                  wnoutrefresh(channel);
  if(private && !privwinhidden )
                  wnoutrefresh(private);

  /* Resize and draw our message window, render topic and
     console line */
  if(outputshown) resize_output();
  if(topic)       topicline(NULL);
                  consoleline(NULL);
  if(loggedin)    vciredraw();
}

static int
gettextwidth (char *textbuffer)
{
  int  width       = 0;

  do switch( *(textbuffer++) ) {
  case   1:
      if (!*(textbuffer++)) return width;
      break;  
  case   0:
      return width;
      break;
  default:   
      width++;
      break;   
  } while( 1 );
}

static int
getsbdataheight (struct sb_data *data, const int xwidth, int needstime )
{
  struct sb_entry *now = data->entries, *prev = NULL, *tmp;
  int height = 0;
  while( now ) {
      height += getsbeheight( now, xwidth, needstime);
      tmp = now; now = (struct sb_entry*)((unsigned long)now->link ^ (unsigned long)prev); prev = tmp;
  }
  return height;
}

static int
getsbeheight (struct sb_entry *entry, const int xwidth, int needstime )
{
  int curx = 0, lines = 1;
  char tmp[ 64 ], *textbuffer;

  if( needstime ) {
      int timelen = (int)strftime(tmp,64,getformatstr(FS_TIME),localtime(&entry->when));
      tmp[ timelen ] = 2;
      textbuffer=tmp;
  } else {
      textbuffer = entry->what;
  }

  do switch( *textbuffer++ ) {
  case ' ':
      if ((calcdrawcus(textbuffer) + curx > xwidth - 1) &&
          (calcdrawcus(textbuffer) < xwidth)) {
              lines++; curx = 4;
           } else {
               if( curx++ == xwidth ) {
                  curx = 0; lines++;
               }
           }
      break;
  case   1:
      if (!*textbuffer++) return lines;
      break;  
  case   0:
      return lines;
      break;
  case   2:
      textbuffer=entry->what;
      break;
  default:   
      if( curx++ == xwidth ) {
          curx = 0; lines++;
      }
      break;   
  } while( 1 );
 
}

/* Check, which kind of filter we have to apply:
   white or black listing. As white listing always
   superseeds black listing, a single white listing
   rule makes the whole filtering type 1.
   If no, or only colouring rules have been found,
   no line filtering applies.
*/
static int
analyzefilters( void ) {
  filt *filters = filterlist;
  int type = 0;

  /* Analyzefilters is only being called
     after filter list has changed. This
     also reflects in resetting the scroll
     offset */
  sb_pub->scroll = sb_pub->count;
  sb_priv->scroll = sb_priv->count;

  /* To avoid filtering the same line for
     identical filter sets, we keep a per
     line indicator, which ruleset we
     tested the line against. This Stamp
     is updated for each change to the
     filter list */
  if( ++currentstamp == 0x3fff ) currentstamp = 1;

  while( (type!=1) && filters ) {
      if( filters->colour == '-' ) type = 2;
      if( filters->colour == '+' ) type = 1;
      filters=filters->next;
  }
  return type;
}

static int
testfilter ( struct sb_entry* entry ) {
    int match = 0;
    filt *filters = filterlist;
    char filtercolour = filtertype == 2 ? '-' : '+';

    while( !match && filters ) {
        if( filters->colour == filtercolour )
            match = regexec( &filters->regex, entry->what, 0, NULL, 0 ) ? 0 : 1;
        filters=filters->next;
    }
    match = ( filtertype == 2 ) ? ( 1 - match ) : match;
    entry->stamp = (match << 15) | currentstamp;

    return match;
}

static void
drawwin (WINDOW *win, struct sb_data *sb )
{
  if (win) {
      struct sb_entry *now = sb->entries, *prev = NULL, *tmp;
      struct sb_entry *vis[win->_maxy + 1];
      int sumlines = 0, sumbuffers = 0;

      /* public scrollback */
      if( sb->scroll != sb->count )
          while( now && (now->id != sb->scroll) ) {
              tmp = now; now = (struct sb_entry*)((unsigned long)now->link ^ (unsigned long)prev); prev = tmp;
          }

      if( (win == output) || (filtertype == 0)) {
          while( now && (sumlines <= win->_maxy )) {
              sumlines += getsbeheight( now, win->_maxx, ((win == channel)||(win == private)) && usetime );
              vis[ sumbuffers++ ] = now;
              tmp = now; now = (struct sb_entry*)((unsigned long)now->link ^ (unsigned long)prev); prev = tmp;
          }
      } else {
          while( now && (sumlines <= win->_maxy )) {

              /* If stamp matches exactly, line has been filtered out, since top
                 bit off means hidden */
              if( now->stamp != currentstamp) {

                  /* If stamp matches and has top bit set, it has been identified
                     positively. Else stamp does not match and line has to be
                     tested against filters, which updates stamp. */
                  if( (now->stamp == (currentstamp | 0x8000) ) || testfilter( now ))
                  {
                      sumlines += getsbeheight( now, win->_maxx, ((win == channel)||(win == private)) && usetime );
                      vis[ sumbuffers++ ] = now;
                  }

              }
              tmp = now; now = (struct sb_entry*)((unsigned long)now->link ^ (unsigned long)prev); prev = tmp;
          }
      }

      /* If buffer is not completely filled, clear window */
      if( sumlines < win->_maxy + 1 )
          wclear(win);

      /* Move pointer to bottom to let curses scroll */
      wmove(win, win->_maxy, win->_maxx);

      /* Plot visible lines */
      while (sumbuffers--) writescr( win, vis[sumbuffers] );
  }
}

#ifdef OLDREADLINE
typedef int rl_command_func_t __P((int, int));
#endif

/* initialize curses and display */
void
initui (void)
{
  Keymap keymap;

  /* init curses */
  if (!ui_init) {
     initscr ();
     ui_init = 1;
  }

  /* install signalhandler */

  signal(SIGWINCH, resize);
  signal(SIGCONT, resize);

  /* set options */
  keypad (stdscr, TRUE);
  nonl ();
  cbreak ();

  /* color or monochome display? */
  if (has_colors ())
    {
      /* start color and set a colorset */
      start_color ();
      use_default_colors();
      init_pair (1, COLOR_RED, -1);
      init_pair (2, COLOR_GREEN, -1);
      init_pair (3, COLOR_YELLOW, -1);
      init_pair (4, COLOR_BLUE, -1);
      init_pair (5, COLOR_MAGENTA, -1);
      init_pair (6, COLOR_CYAN, -1);
      init_pair (7, COLOR_WHITE, -1);
      init_pair (8, COLOR_WHITE, COLOR_RED);
      init_pair (9, COLOR_WHITE, COLOR_BLUE);
    }
  else
    {
      /* monochrome, start color and set a colorset anyways */
      start_color ();
      init_pair (1, -1, -1);
      init_pair (2, -1, -1);
      init_pair (3, -1, -1);
      init_pair (4, -1, -1);
      init_pair (5, -1, -1);
      init_pair (6, -1, -1);
      init_pair (7, -1, -1);
      init_pair (8, -1, -1);
      init_pair (9, -1, -1);
    }

  /* store screen-dimensions to local functions */
  getmaxyx (stdscr, screensy, screensx);

  if (!privheight_desired) privheight_desired = getintoption(CF_PRIVHEIGHT);
  if ( privheight_desired > screensy - 5)  privheight = screensy - 5; else privheight = privheight_desired;

  /* check dimensions or bump user */
  if (screensy - privheight < 4)
    {
      fprintf (stderr, "vchat-client: screen to short (only %d rows, at least %d expected), bailing out.\n", screensy, privheight + 6);
      snprintf (errstr, ERRSTRSIZE, "vchat-client: screen to short (only %d rows, at least %d expected), bailing out.\n", screensy, privheight + 6);
      cleanup (0);
    }
  if (screensx < 14)
    {
      fprintf (stderr, "vchat-client: screen to thin (only %d cols, at least %d expected), bailing out.\n", screensx, 14);
      snprintf (errstr, ERRSTRSIZE, "vchat-client: screen to thin (only %d cols, at least %d expected), bailing out.\n", screensx, 14);
      cleanup (0);
    }

  /* setup our windows */
  console = newwin (1, screensx, screensy - 2, 0);
  input = newwin (1, screensx, screensy - 1, 0);
  if (privheight) private = newwin (privheight, screensx, 0, 0);
  if( private || getintoption(CF_USETOPIC))
      topic = newwin (1, screensx, privheight, 0);
  channel = newwin (screensy - (privheight+3), screensx, (privheight+1), 0);
  output  = newwin (1, screensx, 1, 0);

  /* promblems opening windows? bye! */
  if (!console || !input || (!topic && getintoption(CF_USETOPIC))|| !channel || !output || ( !private && privheight ))
    {
      fprintf (stderr, "vchat-client: could not open windows, bailing out.\n");
      cleanup (0);
    }

  /* Prepare our scrollback buffers */
  sb_pub  = (struct sb_data*)malloc( sizeof(struct sb_data));
  sb_out  = (struct sb_data*)malloc( sizeof(struct sb_data));
  if( privheight)
      sb_priv = (struct sb_data*)malloc( sizeof(struct sb_data));
  else
      sb_priv = sb_pub;

  memset( sb_pub,  0, sizeof(struct sb_data));
  memset( sb_priv, 0, sizeof(struct sb_data));
  memset( sb_out,  0, sizeof(struct sb_data));

  /* set colors for windows */
  if (has_colors()) {
     wattrset (console, COLOR_PAIR (9));
     wattrset (input, COLOR_PAIR (0));
     wbkgd (output, COLOR_PAIR(8));
     wbkgd (console, COLOR_PAIR (9));
     wbkgd (channel, COLOR_PAIR (0));
     wbkgd (input, COLOR_PAIR (0));
     if (private)
        wbkgd (private, COLOR_PAIR (0));
     if( topic ) {
         wattrset (topic, COLOR_PAIR (9));
         wbkgd (topic, COLOR_PAIR (9));
     }
  } else {
     wattron (console, A_REVERSE);
     wattron (output, A_REVERSE);
     wbkgd(output, A_REVERSE);
     if( topic )
         wattron (topic, A_REVERSE);
  }

  /* set some options */
  scrollok (channel, TRUE);
  if (private)
     scrollok (private, TRUE);
  scrollok (input, TRUE);
  scrollok (output, TRUE);
  //idlok(channel,TRUE);
  wtimeout (input, 100);

  /* setup readlines display */
  /* FIXME: present only in newer readline versions
  rl_set_screen_size (1, screensx);
  */

  /* use our callback to draw display */
  rl_redisplay_function = vciredraw;

  /* get keymap, throw out unwanted binding */
  keymap = rl_get_keymap ();
  rl_unbind_command_in_map ("clear-screen", keymap);
  rl_unbind_command_in_map ("complete", keymap);
  rl_unbind_command_in_map ("possible-completions", keymap);
  rl_unbind_command_in_map ("insert-completions", keymap);

  /* bind CTRL-L to clearmsg() */
  rl_bind_key ('J'-'@', (rl_command_func_t *) clearpriv);
  rl_bind_key ('O'-'@', (rl_command_func_t *) clearchan);
  rl_bind_key ('L'-'@', (rl_command_func_t *) redraw);
  rl_bind_key ('B'-'@', (rl_command_func_t *) scrollup);
  rl_bind_key ('P'-'@', (rl_command_func_t *) scrollup);
  rl_bind_key ('F'-'@', (rl_command_func_t *) scrolldown);
  rl_bind_key ('N'-'@', (rl_command_func_t *) scrolldown);
  rl_bind_key ('R'-'@', (rl_command_func_t *) scrollwin);
  rl_bind_key ('T'-'@', (rl_command_func_t *) shrinkprivwin);
  rl_bind_key ('G'-'@', (rl_command_func_t *) growprivwin);
  rl_bind_key ('X'-'@', (rl_command_func_t *) toggleprivwin);

  /* bind TAB to menu complete from readline */
  rl_bind_key ('\t', (rl_command_func_t *) rl_menu_complete);

  /* application name for .inputrc - err, we don't load it */
  rl_readline_name = "vchat-client";

  /* set up nick completion functions .. */
  rl_ignore_completion_duplicates = 0;
#ifdef OLDREADLINE
  rl_completion_entry_function = (Function *) ul_nickcomp;
  rl_attempted_completion_function = vcccomplete;
#else
  rl_completion_entry_function = (rl_compentry_func_t *) ul_nickcomp;
  rl_attempted_completion_function = (rl_completion_func_t *) vcccomplete;
#endif

  /* .. and 'line completed' callback */
#ifdef OLDREADLINE
  rl_callback_handler_install ("", linecomplete);
#else
  rl_callback_handler_install ("", (rl_vcpfunc_t *) linecomplete);
#endif
/*
  writeout( ">> Ctrl-X <<");

  if (errstr[0] != '\0') {
     writeout(errstr);
     writeout( " ");
  }

  writeout (vchat_cl_version);
  writeout (vchat_ui_version);
  writeout (vchat_io_version);
  writeout (vchat_us_version);
  writeout (vchat_cm_version);
  showout( );
*/

  if( getintoption( CF_KEEPLOG ) ) {
      unsigned char *logfile = getstroption( CF_LOGFILE );
      if( logfile && *logfile ) {
          if( *logfile == '~' )
              logfile = tilde_expand( logfile );
          vchat_logfile = fopen( logfile, "r+" );
          if( vchat_logfile ) {
              time_t    now;
              long long now_;
              char      dst;
              int       lenstr;
              while( !feof( vchat_logfile)) {
                  if( (fscanf( vchat_logfile, "%016llX%c", (unsigned long long*)&now_, &dst)) &&
                      ((dst == '0') || (dst == '1')))
                  {
                      now = (time_t)now_;
                      if(fgets(tmpstr, TMPSTRSIZE, vchat_logfile)) {
                          lenstr = strlen( tmpstr );
                          tmpstr[lenstr-1] = '\0';
                          sb_add( dst == '0' ? sb_pub : sb_priv, tmpstr, now);
                      }
                  } else
                      while( !feof( vchat_logfile) && ( fgetc( vchat_logfile ) != '\n'));
              }
          }
      }
  }

  resize(0);  
}

/* render colorized line to window */
/* DOES NOT WRAP !!!
   CURRENTLY UNUSED
   Enable, when needed

static void
writecolorized( WINDOW *win, unsigned char *string) {
  ncurs_attr old_att, new_att;
  int        i;

  WATTR_GET( win, old_att );
  new_att = old_att;
  for( i = 0; string[ i ]; i++ )
      if( string[ i ] == 1 ) {
          docolorize( string[++i], &new_att, old_att);
      } else {
          WATTR_SET( win, new_att );
          waddch( win, string[ i ] );
     }
  WATTR_SET( win, old_att );
}
*/

/* render consoleline to screen */
void
consoleline (unsigned char *message)
{
  /* clear console, set string (or default), redraw display */
  int i;
  ncurs_attr old_att, new_att;

  memset( &new_att, 0, sizeof(new_att));
  BCOLR_SET( (&new_att), 8 );
  wmove (console, 0, 0);
  WATTR_GET( console, old_att);
  if(sb_pub->scroll!=sb_pub->count) WATTR_SET( console, new_att);

  for (i = 0; i < console->_maxx; i++)
     waddch (console, ' ');

  if( !message && usetime )
  {
      char date[10];
      time_t now = time(NULL);
      strftime( date, sizeof(date), getformatstr(FS_CONSOLETIME), localtime(&now));
      snprintf( tmpstr, TMPSTRSIZE, "%s%s", date, consolestr);
      mvwaddnstr (console, 0, 0, tmpstr, console->_maxx);
  } else {
      mvwaddnstr (console, 0, 0, message ? message : consolestr, console->_maxx);
  }

  snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_SBINF),sb_pub->scroll,sb_pub->count);
  mvwaddstr (console, 0, console->_maxx - (strlen(tmpstr)-1),tmpstr);
  if (sb_win == 0) mvwaddch (console, 0, console->_maxx,'*');

  WATTR_SET( console, old_att);

  wnoutrefresh(console);
  if(outputshown) {
      redrawwin(output);
      wnoutrefresh(output);
  }
  wnoutrefresh(input);
  doupdate();
}

/* render topicline to screen */
void
topicline (unsigned char *message)
{
  int i;
  ncurs_attr old_att, new_att;

  if( !topic )
      return;

  memset( &new_att, 0, sizeof(new_att));
  BCOLR_SET( (&new_att), 8 );

  /* clear topic, set string (or default), redraw display */
  wmove (topic, 0, 0);

  WATTR_GET( topic, old_att);
  if( private && (sb_priv->scroll!=sb_priv->count))
      WATTR_SET( topic, new_att);

  for (i = 0; i < topic->_maxx; i++)
     waddch (topic, ' ');
  mvwaddnstr (topic, 0, 0, message ? message : topicstr, topic->_maxx);
  if (private) {
     snprintf(tmpstr,TMPSTRSIZE,getformatstr(FS_SBINF),sb_priv->scroll,sb_priv->count);
     mvwaddstr (topic, 0, topic->_maxx - (strlen(tmpstr)-1),tmpstr);
     if (sb_win == 1) mvwaddch (topic, 0, topic->_maxx,'*');
  }
  WATTR_SET( topic, old_att);

  wnoutrefresh(topic);
  if(outputshown) {
      redrawwin(output);
      wnoutrefresh(output);
  }
  wnoutrefresh(input);
  doupdate();
}

/* end userinterface */
void
exitui (void)
{
  if (ui_init) {
     rl_callback_handler_remove ();
     endwin ();
     ui_init = 0;
     if( vchat_logfile )
         fclose( vchat_logfile );
  }
}

/* prompt for a nick */
/* FIXME: must not be called when used rl_callback_read_char()/userinput()
 * before */
void
nickprompt (void)
{
  if (nick)
    return;

  /* prompt user for nick unless he enters one */
  consoleline("Please enter your nickname:");
  while (!nick || !nick[0])
    {
      if (nick)
	free (nick);
      nick = readline("");
    }
  setstroption(CF_NICK,nick);

  /* try to get readlines stats clean again */
  //rl_free_line_state ();
  rl_point = 0;
  rl_done = 0;
  rl_line_buffer[0] = 0;
  lastlen = 23;

  /* wipe input line and reset cursor */
  rl_kill_full_line(0,0);
  wclear(input);

  /* reset consoleline */
  consoleline(NULL);
}

/* special callback for readline, doesn't show the characters */
static void
vcnredraw (void)
{
  int i;
  unsigned char *passbof="-*-*-*-*-*-*-";

  /* wipe input line and reset cursor */
  wmove(input, 0, 0);
  for (i = 0; i < input->_maxx; i++)
  waddch(input, ' ');
  wmove(input, 0, 0);

  /* draw as many stars as there are characters */
  mvwaddnstr(input, 0, 0, &passbof[rl_point%2], 12);
  wmove(input, 0, input->_maxx);
  wrefresh(input);
}

/* passphrase callback for OpenSSL */
/* FIXME: must not be called when used rl_callback_read_char()/userinput()
 * before */
int
passprompt (char *buf, int size, int rwflag, void *userdata)
{
  int i;
  unsigned char *passphrase = NULL;
  
  /* use special non-revealing redraw function */
  /* FIXME: passphrase isn't protected against e.g. swapping */
  rl_redisplay_function = vcnredraw;

  /* prompt user for non-empty passphrase */
  consoleline("Please enter PEM passphrase for private key:");
  while (!passphrase || !passphrase[0])
    {
      if (passphrase)
	free (passphrase);
      passphrase = readline ("");
    }

  /* reset redrawing function to default, reset consoleline */
  rl_redisplay_function = vciredraw;
  consoleline(NULL);

  /* copy passphrase to buffer */
  strncpy (buf, passphrase, size);

  /* try to get readlines stats clean again */
  //rl_free_line_state ();
  rl_point = 0;
  rl_done = 0;
  rl_line_buffer[0] = 0;
  lastlen = 23;
  
  /* wipe input line and reset cursor */
  wmove (input, 0, 0);
  for (i = 0; i < input->_maxx; i++)
  waddch (input, ' ');
  wmove (input, 0, 0);
  wrefresh (input);

  /* return passphrase to OpenSSL */
  return strlen (buf);
}

/* Filter stuff */
static int
check_valid_colour( char colour ) {
  return !( (colour !='-')&&(colour !='+') && (colour < '0' || colour > '9') &&
            (colour < 'A' || colour > 'Z' || !attributes[ colour-'A' ]) &&
            (colour < 'a' || colour > 'z' || !attributes[ colour-'a' ]));
}


/* scans filterlist and removes possible matches
   test functions may return:
     RMFILTER_RMANDCONT
     RMFILTER_RMANDSTOP
     RMFILTER_KEEPANDCONT
     RMFILTER_KEEPANDSTOP
   returns number of removed entries
*/
static int
removefromfilterlist( int(*test)(filt *flt, void *data, char colour), void *data, char colour) {
  filt **flt = &filterlist, *tmp;
  int    removed = 0, stop = 0;
  
  while( *flt && !stop ) {
      switch( test( *flt, data, colour ) ) {
      case RMFILTER_RMANDSTOP:  /* remove */
          stop = 1;
      case RMFILTER_RMANDCONT:
          snprintf( tmpstr, TMPSTRSIZE, "  Removed ID: [% 3d] Color: [%c] Regex: [%s] ", (*flt)->id, (*flt)->colour, (*flt)->text);
          writeout(tmpstr);
          /* Release regex.h resources */
          regfree( &((*flt)->regex));
          /* free ASCII text memory */
          free( (*flt)->text);
          /* unlink from list */
          tmp = *flt;
          *flt = (*flt)->next;
          /* free filter block itself */
          free( tmp );
          /* reflect changes on whole screen */
          removed++;
          break;
      case RMFILTER_KEEPANDSTOP: /* don't remove but stop scanning */
          stop = 1;
          break;
      default:
          /* advance in list */
          if( *flt ) flt = &((*flt)->next);
          break;
      }
  }
  /* return number of removed items */
  return removed;
}

static int
test_clear( filt *flt, void *data, char c ) {
  if( !c || ( c == flt->colour ) || ( (c == '*') && (flt->colour != '-') && (flt->colour != '+') ) )
      return RMFILTER_RMANDCONT;
  else
      return RMFILTER_KEEPANDCONT;
}

static int
test_simplerm( filt *flt, void *data, char colour) {
  if( !strcmp( flt->text, (char*)data))
      return test_clear(flt, NULL, colour);
  else
      return RMFILTER_KEEPANDCONT;
}

static int
test_numericrm( filt *flt, void *data, char colour) {
  if( flt->id == (long)data)
      return test_clear(flt, NULL, colour);
  else
      return RMFILTER_KEEPANDCONT;
}

/* clears filter list */
void
clearfilters( char colour ) {
  flushout( );
  if( removefromfilterlist( test_clear, NULL, colour ) ) {
      /* There actually WERE items removed */
      filtertype = analyzefilters( );
  } else {
      writeout("  No matches on filter list. ");
  }
  showout();
}

/* removes filter pattern */
void
removefilter( unsigned char *tail ) {
  int rmv = 0, val;
  char* end;

  flushout( );

  rmv = removefromfilterlist( test_simplerm, (void *)tail, 0 );
  if(!rmv) {
      val = strtol((char*)tail, &end, 10);
      if( (tail != (unsigned char*)end) && (!*end) )
      rmv = removefromfilterlist( test_numericrm, (void *)val, 0);
  }

  if( rmv ) {
      /* There actually WERE items removed */
      filtertype = analyzefilters( );
  } else {
      snprintf( tmpstr, TMPSTRSIZE, "  Not on filter list: %s ", tail);
      writeout( tmpstr );
  }
  showout();
}

static unsigned int uniqueidpool = 1;

/* returns unique id for filter pattern or 0 for failure */
unsigned int
addfilter( char colour, unsigned char *regex ) {
  filt *newflt = malloc( sizeof(filt)), **flt = &filterlist;

  if( !newflt ) return 0;
  flushout( );

  /* check colour validity */
  if( !check_valid_colour( colour ) ){
      free( newflt );
      writeout( "  Not a valid colour code. " );
      showout( );
      return 0;
  }

  if( regcomp( &newflt->regex, regex, REG_ICASE | REG_EXTENDED | REG_NEWLINE) ) {
      /* couldn't compile regex ... print error, return */
      free( newflt );

      snprintf( tmpstr, TMPSTRSIZE, "  %s ", regex);
      writeout( " Bad regular expression: ");
      writeout( tmpstr );
      showout( );
      return 0;
  } else {
      int len = strlen(regex) + 1;
      /* grab id from ID pool an increase free ID counter */
      newflt->id     = uniqueidpool++;
      newflt->colour = colour;
      newflt->next   = NULL;
      /* take a copy of plain regex text for later identification by user */
      newflt->text   = malloc( len );
      memcpy( newflt->text, regex, len );
  }

  /* append new filter to filterlist */
  while( *flt ) flt=&((*flt)->next);
  *flt = newflt;

  filtertype = analyzefilters( );

  if ( colour == '-' ) {
      snprintf( tmpstr, TMPSTRSIZE, "  \"%s\" successfully added to ignorance list. ( ID = %d). ", (*flt)->text, (*flt)->id);
  } else if( colour == '+' ) {
      snprintf( tmpstr, TMPSTRSIZE, "  \"%s\" successfully added to zoom list. ( ID = %d). ", (*flt)->text, (*flt)->id);
  } else {
      snprintf( tmpstr, TMPSTRSIZE, "  \"%s\" successfully added to hilitelist. (ID = %d). ", (*flt)->text, (*flt)->id);
  }
  writeout(tmpstr );
  showout( );

  return newflt->id;
}

void
listfilters( void ) {
  filt  *flt = filterlist;
  int     shownhi = 0, shownign = 0, shownzoom = 0;

  flushout( );

  while( flt ) {
      if( (flt->colour != '-') && (flt->colour != '+')) {
          if(!shownhi) {
              writeout(" Your hilites:");
              shownhi = 1;
          }
          snprintf( tmpstr, TMPSTRSIZE, "  ID: [% 3d] Color: [%c] Regex: [%s]", flt->id, flt->colour, flt->text);
          writeout( tmpstr );
      }
      flt = flt->next;
  }

  flt = filterlist;

  while( flt ) {
      if( flt->colour == '-') {
          if(!shownign) {
              if(shownhi) writeout(" ");
              writeout(" You do ignore:");
              shownign = 1;
          }
          snprintf( tmpstr, TMPSTRSIZE, "  ID: [% 3d]            Regex: [%s]", flt->id, flt->text);
          writeout( tmpstr );
      }
      flt = flt->next;
  }

  flt = filterlist;

  while( flt ) {
      if( flt->colour == '+') {
          if(!shownzoom) {
              if(shownhi || shownign) writeout(" ");
              writeout(" On your whitelist:");
              shownzoom = 1;
          }
          snprintf( tmpstr, TMPSTRSIZE, "  ID: [% 3d]            Regex: [%s]", flt->id, flt->text);
          writeout( tmpstr );
      }
      flt = flt->next;
  }

  if( !shownign && !shownhi && !shownzoom) {
      writeout("  No entries on your filter list. ");
  }
  showout();
}
