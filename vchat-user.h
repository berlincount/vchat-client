/*
 * vchat-user.h
 * User list handling
 *
 * Author:  Dirk Engling <erdgeist@erdgeist.org>
 * License: Beerware
*/
#ifndef __VCHAT_USER_H__
#define __VCHAT_USER_H__

extern char *vchat_us_version;

/* own nick and channel */
void        own_channel_set( int channel );
int         own_channel_get( );
void        own_nick_set( char *nick );
char const *own_nick_get( );
int         own_nick_check( char * nick );

/* Add/remove/rename */
int ul_add(char *name, int chan_flag); /* -1: keep, 0: notinchan, 1: inchan */
int ul_del(char *name);
int ul_rename(char *oldname, char *newname);
void ul_clear();
void ul_rebuild_list();
void ul_clean();

/* Seting state */
void ul_leave_chan(char *name);
void ul_enter_chan(char *name);
void ul_private_action(char *name);
void ul_public_action(char *name);

/* Finding users ul_finduser */
char *ul_match_user(char *regex);

/* Nick completion function for readline */
char **ul_complete_user(char *text, int start, int end );

#endif
