/*
 * vchat-client - alpha version
 * vchat.h - includefile with glue structures an functions
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

/* user structure */
struct user;
typedef struct user user;
/* userlist from vchat-user.c */
extern user *nicks;

/* servermessage types */
typedef enum { SM_IGNORE, SM_INFO, SM_USERINFO, SM_CHANNEL, SM_ERROR } smtype;

/* servermessage structure */
struct servermessage
{
  unsigned char id[4]; /* three-character message id */
  smtype type;         /* message type */
  void (*funct) (unsigned char *); /* function used by client */
  void (*hook) (unsigned char *);  /* function hook for scripting */
};
typedef struct servermessage servermessage;

/* configuration types and variable numbers */
typedef enum { CO_NIL, CO_STR, CO_INT } conftype;
typedef enum { CF_NIL, CF_NICK, CF_FROM, CF_SERVERHOST, CF_SERVERPORT,
CF_CIPHERSUITE, CF_CONFIGFILE, CF_CERTFILE, CF_KEYFILE, CF_FORMFILE, CF_LOGFILE,
CF_USESSL, CF_USECERT, CF_PRIVHEIGHT, CF_HSCROLL, CF_CHANNEL, CF_USETIME,
CF_USETOPIC, CF_SCROLLBPRIV, CF_SCROLLBACK, CF_SCROLLBPRIVT, CF_SCROLLBACKT,
CF_KEEPLOG, CF_ENCODING } confopt;

/* format strings */
typedef enum { FS_PLAIN, FS_CHAN, FS_PRIV, FS_SERV, FS_GLOB, FS_DBG, FS_ERR,
FS_IDLE, FS_TIME, FS_CONSOLETIME, FS_TOPICW, FS_NOTOPICW, FS_CONSOLE, FS_CONNECTED,
FS_TOPIC, FS_NOTOPIC, FS_CHGTOPIC, FS_USONLINE, FS_USMATCH, FS_SIGNON, FS_SIGNOFF,
FS_JOIN, FS_LEAVE, FS_NICKCHANGE, FS_UNKNOWNMSG, FS_BOGUSMSG, FS_RXPUBURL,
FS_MYPUBURL, FS_RXPUBMSG, FS_MYPUBMSG, FS_TXPUBMSG, FS_RXPRIVMSG, FS_TXPRIVMSG,
FS_BGPRIVMSG, FS_PUBTHOUGHT, FS_TXPUBTHOUGHT, FS_TXPUBNTHOUGHT, FS_PUBACTION,
FS_TXPUBACTION, FS_BGTXPUBACTION, FS_COMMAND, FS_LOCALCOMMAND, FS_BOGUSCOMMAND,
FS_SBINF, FS_MISSTYPED, FS_UNKNCMD, FS_BADREGEX, FS_ERR_STRING } formtstr;

/* configoption structure */
struct configoption
{
  confopt id;
  conftype type;
  unsigned char *varname;
  unsigned char *defaultvalue;
  unsigned char *value;
  unsigned char **localvar;
};

typedef struct configoption configoption;

/* format strings */
struct formatstring
{
  formtstr id;
  unsigned char *idstring;
  unsigned char *formatstr;
};
typedef struct formatstring formatstring;

/* static tmpstr in all modules */
#define TMPSTRSIZE 1024
static unsigned char tmpstr[TMPSTRSIZE];

extern unsigned char *nick;
extern int chan;

extern unsigned int loggedin;

/* vchat-client.c */
#define ERRSTRSIZE 1024
extern unsigned char errstr[];
extern unsigned char *vchat_cl_version;
void cleanup(int signal);

/*   configuration helper funktions from vchat-client.c */
unsigned char *getformatstr (formtstr id);
unsigned char *getstroption (confopt option);
void setstroption (confopt option, unsigned char *string);
int getintoption (confopt option);
void setintoption (confopt option, int value);

/* vchat-user.c */
extern unsigned char *vchat_us_version;

/*   add / delete user */
void ul_add (unsigned char *nick, int ignored);
void ul_del (unsigned char *nick, int ignored);

/*   clear userlist */
void ul_clear ();

/*   channel join / leave */
void ul_join (unsigned char *nick, int channel);
void ul_leave (unsigned char *nick, int channel);

/*   nickchange */
void ul_nickchange (unsigned char *oldnick, unsigned char *newnick);

/*   place user in channel */
void ul_moveuser (unsigned char *nick, int channel);

/*   message nick completion */
void ul_msgto (unsigned char *nick);
void ul_msgfrom (unsigned char *nick);

/*   nick-completion for vchat-ui.c */
unsigned char *ul_nickcomp (const unsigned char *text, int state);
unsigned char *ul_cnickcomp (const unsigned char *text, int state);
unsigned char *ul_mnickcomp (const unsigned char *text, int state);

/*   try to find user by substring */
unsigned char *ul_matchuser ( unsigned char *substr);

/* vchat-ui.c */
extern unsigned char *vchat_ui_version;

/*   topic and console strings */
#define TOPICSTRSIZE 1024
#define CONSOLESTRSIZE 1024
extern unsigned char topicstr[];
extern unsigned char consolestr[];
extern unsigned char *encoding;

/*   init / exit functions */
void initui (void);
void exitui (void);

/*   called from eventloop in vchat-client.c */
void userinput (void);

/*   display various messages */
int   writechan (unsigned char *str);
int   writepriv (unsigned char *str);
void  writeout  (unsigned char *str);
void  showout   (void);
void  flushout  (void);
#define  msgout(STR) {flushout();writeout(STR);showout();}
void  hideout   (void);
int   writecf   (formtstr id, unsigned char *str);
void  writelog  (FILE *file);
void  writelog_i(FILE *file);

extern int outputcountdown;

/*   update console / topic window */
void consoleline (unsigned char *);
void topicline (unsigned char *);

/*   prompt for nick or password */
void nickprompt (void);
int passprompt (char *buf, int size, int rwflag, void *userdata);

/*   filter functions */
void         refilterscrollback( void);

unsigned int addfilter        ( char colour, unsigned char *regex );
void         removefilter     ( unsigned char *line );
void         listfilters      ( void );
void         clearfilters     ( char colour );

/* vchat-protocol.c */
extern unsigned char *vchat_io_version;

/*   connect/disconnect */
int  vcconnect    (unsigned char *server, unsigned int port);
void vcdisconnect ();

/*   network I/O */
void networkinput (void);
void networkoutput (unsigned char *);

/*   helpers for vchat-user.c */
void ownjoin (int channel);
void ownleave (int channel);
void ownnickchange (unsigned char *newnick);

/* vchat-commands.c */
extern unsigned char *vchat_cm_version;
void   command_version ( unsigned char *tail);

/*   user input */
void handleline (unsigned char *);

/* struct for defining "/command" handlers */
typedef struct {
  int            number;
  unsigned char  name[8];
  int            len;
  void         (*handler)(unsigned char *);
  unsigned char *short_help;
  unsigned char *help;
} commandentry;
