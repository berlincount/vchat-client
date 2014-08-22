/*
 * vchat-client - alpha version
 * vchat-messages.h - declaration of servermessage array
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

/* servermessage array with structure as defined in vchat.h */

servermessage servermessages[] = {
/* 100 <message...>
   Informational message for human consumption */
  {"100", SM_INFO, NULL, NULL},
/* 110 <channel> <nick> <fromhost>
   User status summary */
  {"110", SM_USERINFO, NULL, NULL},
/* 111 <date> <time> <code> <message>
   Server log information */
  {"111", SM_INFO, NULL, NULL},
/* 112 <information>
   Server user information */
  {"112", SM_USERINFO, NULL, NULL},
/* 113 <ignore-info>
   Ignore command confirmation */
  {"113", SM_IGNORE, NULL, NULL},
/* 114 <nick> changed the channel topic to <topic>
   Channel topic change confirmation */
  {"114", SM_CHANNEL, topicchange, NULL},
/* 115 <channel> <topic>
   Channel status information */
  {"115", SM_CHANNEL, topicinfo, NULL},
/* 116 <nick> <from> <server> <userinfo>
   User status information */
  {"116", SM_USERINFO, NULL, NULL},
/* 117 <nick> <statistics>
   User statistics information */
  {"117", SM_USERINFO, NULL, NULL},
/* 118 <nick> <action>
   User action information */
  {"118", SM_CHANNEL, pubaction, NULL},
/* 119 <nicks>
   Userlist */
  {"119", SM_USERINFO, receivenicks, NULL},
/* 122 <url>
   URL List */
  {"122", SM_USERINFO, NULL, NULL},
/* 123 <user login [user logout]>
   User Login / Logout Information */
  {"123", SM_USERINFO, NULL, NULL},
/* 124 <nick> <thoughts>
   User thoughts information */
  {"124", SM_CHANNEL, pubthoughts, NULL},
/* 169 <encoding>
   List of known encodings */
  {"169", SM_INFO, NULL, NULL},
/* 201 <protocol> <server-name>
   Server signon */
  {"201", SM_IGNORE, serverlogin, NULL},
/* 211 <nickname>
   User signon */
  {"211", SM_USERINFO, usersignon, NULL},
/* 212 <nickname>
   User signon (self) */
  {"212", SM_INFO, justloggedin, NULL},
/* 221 <nickname>
   User signoff */
  {"221", SM_USERINFO, usersignoff, NULL},
/* 231 <nickname>
   Channel departure */
  {"231", SM_CHANNEL, userleave, NULL},
/* 232 <nickname>
   Channel join */
  {"232", SM_CHANNEL, userjoin, NULL},
/* 241 <oldnick> <newnick>
   Nickname change */
  {"241", SM_USERINFO, usernickchange, NULL},
/* 269 Encoding set to <encoding>
   answer to .e */
  {"269", SM_INFO, NULL, NULL},
/* 120 <registered nick> */
  {"120", SM_INFO, login, NULL},
/* 121 You're not logged in */
  {"121", SM_INFO, anonlogin, NULL},
/* 301 Message truncated */
  {"301", SM_ERROR, NULL, NULL},
/* 302 Message too long */
  {"302", SM_ERROR, NULL, NULL},
/* 303 No protocol lines matched expression.  */
  {"303", SM_ERROR, NULL, NULL},
/* 304 Already in that channel */
  {"304", SM_ERROR, NULL, NULL},
/* 305 Still there? */
  {"305", SM_INFO, idleprompt, NULL},
/* 401 Character set failure, syntax error */
  {"401", SM_ERROR, nickerr, NULL},
/* 402 Uninterpretible command */
  {"402", SM_ERROR, NULL, NULL},
/* 403 Not logged in */
  {"403", SM_ERROR, nickerr, NULL},
/* 404 Already logged in */
  {"404", SM_ERROR, NULL, NULL},
/* 405 This is already the topic */
  {"405", SM_ERROR, NULL, NULL},
/* 411 Nickname in use */
  {"411", SM_ERROR, nickerr, NULL},
/* 412 Nickname not found (private message not sent) */
  {"412", SM_ERROR, pmnotsent, NULL},
/* 413 Channel not found */
  {"413", SM_ERROR, NULL, NULL},
/* 414 Access violation */
  {"414", SM_ERROR, NULL, NULL},
/* 415 Nickname reserved */
  {"415", SM_ERROR, nickerr, NULL},
/* 469 I'm very sorry, FNORD is not know to this system, try .E for a * list */
  {"469", SM_ERROR, NULL, NULL},
/* 501 Disconnected by own request */
  {"501", SM_INFO, NULL, NULL},
/* 502 Disconnected by operator */
  {"502", SM_INFO, NULL, NULL},
/* END OF MESSAGES */
  {"", SM_IGNORE, NULL, NULL}
};
