/*
 * vchat-client - alpha version
 * vchat-config.h - declaration of configuration array and default values
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

#ifndef GLOBAL_CONFIG_FILE
# define GLOBAL_CONFIG_FILE "/etc/vchatrc"
#endif

#ifndef GLOBAL_FORMAT_FILE
# define GLOBAL_FORMAT_FILE "/etc/vchatformats"
#endif

/* configuration array with structure as defined in vchat.h */
extern unsigned int usessl;
extern unsigned int usetime;
extern unsigned int hscroll;

static volatile configoption configoptions[] = {
/* config-option   type    name in file  default value       value       localvar  */
  {CF_NICK,        CO_STR, "nick",       NULL,               NULL,       { .pstr = &nick }   },
  {CF_FROM,        CO_STR, "from",       "vc-alpha-0.16",    NULL,       { NULL }  },
  {CF_SERVERHOST,  CO_STR, "host",       "pulse.flatline.de",NULL,       { NULL }  },
  {CF_SERVERPORT,  CO_STR, "port",       "2325",             NULL,       { NULL }   },
  {CF_CIPHERSUITE, CO_STR, "ciphers",    "HIGH:MEDIUM",      NULL,       { NULL }  },
  {CF_CONFIGFILE,  CO_STR, "conffile",   "~/.vchat/config",  NULL,       { NULL }  },
  {CF_CERTFILE,    CO_STR, "certfile",   "~/.vchat/cert",    NULL,       { NULL }  },
  {CF_KEYFILE,     CO_STR, "keyfile",    "~/.vchat/key",     NULL,       { NULL }  },
  {CF_FORMFILE,    CO_STR, "formatfile", "~/.vchat/formats", NULL,       { NULL }  },
  {CF_ENCODING,    CO_STR, "encoding",   NULL,               NULL,       { .pstr = &encoding }},
  {CF_USESSL,      CO_INT, "usessl",     (char *) 1,         (char *)-1, { .pint = &usessl }  },
  {CF_USECERT,     CO_INT, "usecert",    (char *) 1,         (char *)-1, { NULL }  },
  {CF_USETIME,     CO_INT, "usetime",    (char *) 1,         (char *)-1, { .pint = &usetime } },
  {CF_USETOPIC,    CO_INT, "usetopicbar",(char *) 1,         (char *)-1, { NULL }  },
  {CF_PRIVHEIGHT,  CO_INT, "messages",   (char *) 0,         (char *)-1, { NULL }  },
  {CF_HSCROLL,     CO_INT, "hscroll",    (char *) 5,         (char *)-1, { .pint = &hscroll } },
  {CF_CHANNEL,     CO_INT, "channel",    (char *) 0,         (char *)-1, { NULL }  },
  {CF_SCROLLBPRIV, CO_INT, "privscrollb",(char *) 2048,      (char *)-1, { NULL }  },
  {CF_SCROLLBACK,  CO_INT, "scrollback", (char *) 8192,      (char *)-1, { NULL }  },
  {CF_SCROLLBPRIVT,CO_INT, "privscrollt",(char *) 0,         (char *)-1, { NULL }  },
  {CF_SCROLLBACKT, CO_INT, "scrolltime", (char *) 86400,     (char *)-1, { NULL }  },
  {CF_BELLPRIV,    CO_INT, "bellonpm",   (char *) 0,         (char *)-1, { NULL }  },
  {CF_NIL,         CO_NIL, NULL,         NULL,               NULL,       { NULL }  },
};

/*
choose option with \001 +
0 - default colorpair for window
1 - colorpair 1 RED
2 - colorpair 2 GREEN
3 - colorpair 3 YELLOW
4 - colorpair 4 BLUE
5 - colorpair 5 MAGENTA
6 - colorpair 6 CYAN
7 - colorpair 7 WHITE
8 - colorpair 8 WHITE on RED
9 - colorpair 9 WHITE on BLUE
aA - alternate charset on/off
bB - bold on/off
dD - dim on/off
iI - invisible on/off
lL - blink on/off
nN - normal on/off
pP - protected on/off
rR - reverse on/off
sS - standout on/off
uU - underlined on/off
*/

#define FE( ID, STRING) { ID, #ID, STRING }

static formatstring formatstrings[] = {
/* format-string    string */
  FE( FS_PLAIN,        "%s"),
  FE( FS_CHAN,         "%s"),
  FE( FS_PRIV,         "%s"),
  FE( FS_SERV,         "\0012%s"),
  FE( FS_GLOB,         "\0012%s"),
  FE( FS_DBG,          "\0013%s"),
  FE( FS_ERR,          "\0011%s"),
  FE( FS_ERR_STRING,   "\0011%s %s"),
  FE( FS_IDLE,         "\0018%s"),
  FE( FS_TIME,         "\0015[%H:%M]\0010 "),
  FE( FS_CONSOLETIME,  "[%H:%M] "),
  FE( FS_TOPICW,       "[ Channel %d: %s"),
  FE( FS_NOTOPICW,     "[ Channel %d has no topic"),
  FE( FS_CONSOLE,      "%s@%s:%d, use .h to get help "),
  FE( FS_CONNECTED,    "\0012# Connected to '\0016%s\0012', port \0016%d\0012 ..."),
  FE( FS_TOPIC,        "\0012# Channel \0016%d\0012 topic is: '\0010%s\0012'"),
  FE( FS_NOTOPIC,      "\0012# Channel \0016%d\0012 has no topic"),
  FE( FS_CHGTOPIC,     "\0012# \0016%s\0012 changes topic to: '\0010%s\0012'"),
  FE( FS_USMATCH,      "\0012# Users matching \"%s\":%s"),
  FE( FS_USONLINE,     "\0012# Users online: %s"),
  FE( FS_SIGNON,       "\0012# \0016%s\0012 %s"),
  FE( FS_SIGNOFF,      "\0012# \0016%s\0012 %s"),
  FE( FS_JOIN,         "\0012# \0016%s\0012 %s \0016%d"),
  FE( FS_LEAVE,        "\0012# \0016%s\0012 %s \0016%d"),
  FE( FS_NICKCHANGE,   "\0012# \0016%s\0012 \0016%s\0012 %s"),
  FE( FS_UNKNOWNMSG,   "?? unknown message: %s"),
  FE( FS_BOGUSMSG,     "?? bogus message: %s"),
  FE( FS_RXPUBURL,     "\0015[\0016%s\0015]\0010 %s"),
  FE( FS_MYPUBURL,     "\0015[\0016\001u%s\001U\0015]\0010 %s"),
  FE( FS_RXPUBMSG,     "\0015<\0016%s\0015>\0010 %s"),
  FE( FS_MYPUBMSG,     "\0015<\0016\001u%s\001U\0015>\0010 %s"),
  FE( FS_TXPUBMSG,     "\0015<\0016\001b%s\001B\0015>\0010 %s"),
  FE( FS_RXPRIVMSG,    "\0015*\0016%s\0015*\0010 %s"),
  FE( FS_TXPRIVMSG,    "\0015-> *\0016%s\0015*\0010 %s"),
  FE( FS_BGPRIVMSG,    "\0011! Bogus message, not sent."),
  FE( FS_PUBACTION,    "\0015*\0010 \0016%s\0010 %s"),
  FE( FS_TXPUBACTION,  "\0015*\0010 \0016\001b%s\001B\0010 %s"),
  FE( FS_TXPUBTHOUGHT, ".o( \0014%s\0010 )"),
  FE( FS_TXPUBNTHOUGHT,".oO( \0014%s\0010 )"),
  FE( FS_PUBTHOUGHT,   "\0015*\0010 \0016\001b%s\001B\0010 %s"),
  FE( FS_BGTXPUBACTION,"\0011! No action taken."),
  FE( FS_COMMAND,      "\0012## command: %s"),
  FE( FS_LOCALCOMMAND, "\0012## local command (not executed yet): %s"),
  FE( FS_BOGUSCOMMAND, "\0012## bogus command (not executed or sent): %s"),
  FE( FS_SBINF,        " [%d/%d] "),
  FE( FS_MISSTYPED,    "\0011* Probably misstyped? Not sent: %s"),
  FE( FS_UNKNCMD,      "\0011* Unknown client command: %s"),
  FE( FS_BADREGEX,     "\0011* Could not compile regex: %s"),
  FE( FS_PLAIN,        NULL)
};
