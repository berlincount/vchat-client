/*
 * vchat-client

*/

#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <sys/time.h>
#include <regex.h>
#include <readline/readline.h>

#include "vchat.h"
#include "vchat-user.h"

/* version of this module */
char *vchat_us_version = "vchat-user.c     $Id$";

typedef struct
{
  char     *nick;
  enum {   UL_NONE = 0x00, UL_ME = 0x01, UL_IN_MY_CHAN = 0x02, UL_NOT_IN_LIST = 0x04 } flags;
  uint64_t last_public;
  uint64_t last_private;
} user;
static user    *g_users;       //< all users, incl self
static size_t   g_users_count; //< number of users in list
static char    *g_nick;        //< own nick
static int      g_channel;     //< own channel
unsigned int    ul_case_first = 0;

static char   **g_dict;
static size_t   g_dict_len;

static int ul_nick_lookup( const char *nick, int *exact_match ) {
  int i;

  *exact_match = 1;
  for( i=0; i<g_users_count; ++i )
    if( !strcasecmp( g_users[i].nick, nick ) )
      return i;
  *exact_match = 0;
  return i;
}

static int64_t ul_now() {
  struct timeval now;
  gettimeofday(&now,(struct timezone*) 0);
  return ((uint64_t)now.tv_sec * 1000) + ((uint64_t)now.tv_usec / 1000 );
}

/* own nick and channel setters/getters */
void own_nick_set( char *nick ) {
  if( nick ) {
    int base;
    if( g_nick )
      base = ul_rename( g_nick, nick );
    else
      base = ul_add( nick, 0 );
    if( base >= 0 ) {
      g_users[base].flags |= UL_ME;
      g_nick = g_users[base].nick;
    }
  } else
    ul_del( g_nick );

  setstroption(CF_NICK, nick);
}

void own_channel_set( int channel ) {
  if( channel != g_channel ) {
    /* Remove all users from my chan, will be re-set on join message */
    int i;
    for( i=0; i<g_users_count; ++i )
      g_users[i].flags &= ~UL_IN_MY_CHAN;
  }

  g_channel = channel;
}

char const *own_nick_get( ) {
  return g_nick;
}

int own_nick_check( char *nick ) {
  if( !g_nick ) return -1;
  return !strncasecmp(g_nick,nick,strlen(g_nick) );
}

int own_channel_get( ) {
  return g_channel;
}

/* Add/remove/rename */
int ul_add(char *name, int in_my_chan_flag ) {

  /* Test if user is already known */
  int exact_match, base = ul_nick_lookup( name, &exact_match );
  if( !exact_match ) {
    /* Make space for new user */
    user * new_users = realloc( g_users, sizeof( user ) * ( 1 + g_users_count ) );
    if( !new_users ) return -1;

    /* Copy the tail */
    g_users = new_users;
    memmove( g_users + base + 1, g_users + base, ( g_users_count - base ) * sizeof( user ) );
    g_users[base].nick         = strdup( name );
    g_users[base].flags        = UL_NONE;
    g_users[base].last_public  = 0;
    g_users[base].last_private = 0;

    g_users_count++;
  }

  g_users[base].flags &= ~UL_NOT_IN_LIST;
  switch( in_my_chan_flag ) {
    case 1: g_users[base].flags |= UL_IN_MY_CHAN; break;
    case 0: g_users[base].flags &= ~UL_IN_MY_CHAN; break;
    case -1: default: break;
  }

  return base;
}

int ul_del(char *name) {
  /* Test if user is already known */
  int exact_match, base = ul_nick_lookup( name, &exact_match );
  if( !exact_match ) return -1;

  /* Release the name buffer */
  free( g_users[base].nick );
  if( g_users[base].flags & UL_ME ) g_nick = 0;

  /* Copy the tail */
  memmove( g_users + base, g_users + base + 1, ( g_users_count - base - 1 ) * sizeof( user ) );

  /* Shrink user list, realloc to a smaller size never fails */
  g_users = realloc( g_users, sizeof( user ) * --g_users_count );
  return 0;
}

int ul_rename(char *oldname, char *newname) {
  /* Ensure user */
  int base = ul_add( oldname, -1 );
  if( base >= 0 ) {
    free( g_users[base].nick );
    g_users[base].nick = strdup( newname );
    if( g_users[base].flags & UL_ME )
      g_nick = g_users[base].nick;
    if( g_users[base].flags & UL_IN_MY_CHAN )
      ul_public_action(newname);
  }
  return base;
}

void ul_clear() {
  int i;
  for( i=0; i<g_users_count; ++i )
    free( g_users[i].nick );
  free( g_users );
  g_nick = 0;
}

void ul_rebuild_list( ) {
  int i;
  for( i=0; i<g_users_count; ++i )
    g_users[i].flags |= UL_NOT_IN_LIST;
}

void ul_clean() {
  int i;
  for( i=0; i<g_users_count; ++i ) {
    if( g_users[i].flags & UL_NOT_IN_LIST ) {
      ul_del( g_users[i].nick );
      --i;
    }
  }
}

/* Seting state */
void ul_leave_chan(char *name) {
  /* Ensure user and kick him off the channel */
  ul_add(name, 0);
}

void ul_enter_chan(char *name) {
  /* Ensure user and put him on the channel */
  int base = ul_add(name, 1);
  if( base >= 0 )
    ul_public_action(name);

  /* Reflect in UI */
  if( own_nick_check( name ) )
    ownjoin( g_channel );
}

void ul_private_action(char *name) {
  /* Ensure user and keep channel state */
  int base = ul_add(name, -1);
  if( base >= 0 )
    g_users[base].last_private = ul_now();
}

void ul_public_action(char *name) {
  /* Ensure user and put him on the channel */
  int base = ul_add(name, 1);
  if( base >= 0 )
    g_users[base].last_public = ul_now();
}

void ul_add_to_dict(char *dict_items) {
  char *i;
  for(i=strtok(dict_items," ");i;i=strtok(0," ")) {
    g_dict = realloc( g_dict, sizeof(char*) * ( 1 + g_dict_len ) );
    if( !g_dict ) exit(1);
    g_dict[g_dict_len++] = strdup(i);
  }
}

/* Finding users ul_finduser? */
char * ul_match_user(char *regex) {
  char    *dest = tmpstr;
  int      i;
  regex_t  preg;

  *dest = 0;
  if( !regcomp( &preg, regex,  REG_ICASE | REG_EXTENDED | REG_NEWLINE)) {

    /* does the username match? */
    /* XXX overflow for too many matches */
    for( i=0; i<g_users_count; ++i )
      if( !regexec( &preg, g_users[i].nick, 0, NULL, 0)) /* append username to list */
        dest += snprintf ( dest, 256, " %s", g_users[i].nick);

  }
  regfree( &preg );
  return tmpstr;
}

static int ul_compare_private( const void *a, const void *b ) {
  const user *_a = (const user *)a, *_b = (const user *)b;
  if( _a->last_private > _b->last_private ) return -1;
  return 1;
}

static int ul_compare_begin_of_line_ncase( const void *a, const void *b ) {
  const user *_a = (const user *)a, *_b = (const user *)b;
  size_t tmpstr_len;
  int a_i, b_i;

  /* First ensure that users in current channel win */
  if( !(_a->flags & UL_IN_MY_CHAN ) ) return  1;
  if( !(_b->flags & UL_IN_MY_CHAN ) ) return -1;

  tmpstr_len = strlen( tmpstr );
  a_i = strncasecmp( _a->nick, tmpstr, tmpstr_len );
  b_i = strncasecmp( _b->nick, tmpstr, tmpstr_len );

  if(  a_i &&  b_i ) return  0; // Both nicks dont match
  if( !a_i &&  b_i ) return -1; // a matches insensitive, b doesnt
  if(  a_i && !b_i ) return  1; // b matches insensitive, a doesnt

  /* From here both nicks match the prefix, ensure that own_nick
     always appears last */
  if( _a->flags & UL_ME ) return  1;
  if( _b->flags & UL_ME ) return -1;

  /* Now the user with the most recent public activity wins */
  if( _a->last_public > _b->last_public ) return -1;

  return 1;
}

static int ul_compare_begin_of_line_case( const void *a, const void *b ) {
  const user *_a = (const user *)a, *_b = (const user *)b;
  size_t tmpstr_len;
  int a_i, b_i, a_s, b_s;

  /* First ensure that users in current channel win */
  if( !(_a->flags & UL_IN_MY_CHAN ) ) return  1;
  if( !(_b->flags & UL_IN_MY_CHAN ) ) return -1;

  tmpstr_len = strlen( tmpstr );
  a_i = strncasecmp( _a->nick, tmpstr, tmpstr_len );
  a_s = strncmp    ( _a->nick, tmpstr, tmpstr_len );
  b_i = strncasecmp( _b->nick, tmpstr, tmpstr_len );
  b_s = strncmp    ( _b->nick, tmpstr, tmpstr_len );

  if(  a_i &&  b_i ) return  0; // Both nicks dont match at all
  if( !a_i &&  b_i ) return -1; // a matches insensitive, b doesnt
  if(  a_i && !b_i ) return  1; // b matches insensitive, a doesnt

  if( !a_s &&  b_s ) return -1; // a matches sensitive, b doesnt
  if(  a_s && !b_s ) return  1; // b matches sensitive, a doesnt

  /* From now we know that both match with same quality, ensure
     that own nick always appears last */
  if( _a->flags & UL_ME ) return  1;
  if( _b->flags & UL_ME ) return -1;

  /* Now the user with the most recent public activity wins */
  if( _a->last_public > _b->last_public ) return -1;

  return 1;
}

static int ul_compare_middle_ncase( const void *a, const void *b ) {
  const user *_a = (const user *)a, *_b = (const user *)b;

  /* Ensure that own nick appears last in list */
  if( _a->flags & UL_ME ) return 1;
  if( _b->flags & UL_ME ) return -1;

  return strcasecmp( _a->nick, _b->nick );
}

static int ul_compare_middle_case( const void *a, const void *b ) {
  const user *_a = (const user *)a, *_b = (const user *)b;
  size_t tmpstr_len;
  int a_s, b_s;

  /* Ensure that own nick appears last in list */
  if( _a->flags & UL_ME ) return 1;
  if( _b->flags & UL_ME ) return -1;

  tmpstr_len = strlen( tmpstr );
  a_s = strncmp( _a->nick, tmpstr, tmpstr_len );
  b_s = strncmp( _b->nick, tmpstr, tmpstr_len );

  if( !a_s &&  b_s ) return -1; // a matches sensitive, b doesnt
  if(  a_s && !b_s ) return  1; // b matches sensitive, a doesnt

  /* From now both strings either both or both dont match
     decide their position by case insensitive match */
  return strcasecmp( _a->nick, _b->nick );
}

/* Nick completion function for readline */
char **ul_complete_user(char *text, int start, int end ) {
  char **result = 0;
  int    i, result_count = 0, dict_result_count = 0;

  /* Never want readline to complete filenames */
  rl_attempted_completion_over = 1;

  /* Check for amount of custom dict matches */
  if( end && ( start != end ) )
    for( i=0; i<g_dict_len; ++i )
      if( !strncasecmp( g_dict[i], text+start, end-start ) )
        ++dict_result_count;

  /* Prepare return array ... of max g_users_count (char*)
     Plus least common prefix in [0] and null terminator
   */
  result = malloc( sizeof(char*) * ( 2 + g_users_count + dict_result_count ) );
  if( !result ) return 0;

  if( start == 0 && end == 0 ) {
    /* Completion on begin of line yields list of everyone we
       were in private conversation, sorted by time of last .m */
    qsort( g_users, g_users_count, sizeof(user), ul_compare_private );
    for( i=0; i<g_users_count; ++i )
      if( g_users[i].last_private ) {
        snprintf( tmpstr, TMPSTRSIZE, ".m %s", g_users[i].nick );
        result[++result_count] = strdup(tmpstr);
      }
    /* No common prefix */
    if( result_count ) result[0] = strdup("");

  } else if( start == 0 && end > 0 ) {
    /* Completion on begin of line with some chars already typed yields
       a list of everyone in channel, matching prefix, sorted by last
       public activity */
    snprintf( tmpstr, end + 1, "%s", text );
    if( ul_case_first )
      qsort( g_users, g_users_count, sizeof(user), ul_compare_begin_of_line_case );
    else
      qsort( g_users, g_users_count, sizeof(user), ul_compare_begin_of_line_ncase );

    for( i=0; i<g_users_count; ++i )
      if( ( g_users[i].flags & UL_IN_MY_CHAN ) && !strncasecmp( g_users[i].nick, tmpstr, end ) ) {
        snprintf( tmpstr, TMPSTRSIZE, "%s:", g_users[i].nick );
        result[++result_count] = strdup(tmpstr);
      }

    /* Copy matches from personal dict to the end */
    for( i=0; i<g_dict_len; ++i )
      if( !strncasecmp( g_dict[i], tmpstr, end-start ) ) {
        snprintf( tmpstr, TMPSTRSIZE, "%s:", g_dict[i] );
        result[++result_count] = strdup(tmpstr);
      }

    /* Copy common prefix */
    if( result_count ) result[0] = strndup(text, end);
  } else if( start != end ) {
    /* Completion in the middle of the line most likely is a .m XY<TAB>
       and thus should complete all users, sorted alphabetically without
       preferences. */
    snprintf( tmpstr, end - start + 1, "%s", text );
    if( ul_case_first )
      qsort( g_users, g_users_count, sizeof(user), ul_compare_middle_case );
    else
      qsort( g_users, g_users_count, sizeof(user), ul_compare_middle_ncase );

    for( i=0; i<g_users_count; ++i )
      if( !strncasecmp( g_users[i].nick, tmpstr, end - start ) )
        result[++result_count] = strdup(g_users[i].nick);

    /* Copy matches from personal dict to the end */
    for( i=0; i<g_dict_len; ++i )
      if( !strncasecmp( g_dict[i], tmpstr, end-start ) )
        result[++result_count] = strdup(g_dict[i]);

    /* Copy common prefix */
    if( result_count ) result[0] = strndup(text, end - start);
  } /* else: completion of an empty word in the middle yields nothing */

  if( !result_count ) {
    free( result );
    result = 0;
  } else
    result[++result_count] = 0;

  return result;
}
