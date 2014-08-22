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

/* servermessage types */
typedef enum { SM_IGNORE, SM_INFO, SM_USERINFO, SM_CHANNEL, SM_ERROR } smtype;

/* servermessage structure */
struct servermessage
{
  char id[4];             /* three-character message id */
  smtype type;            /* message type */
  void (*funct) (char *); /* function used by client */
  void (*hook) (char *);  /* function hook for scripting */
};
typedef struct servermessage servermessage;

/* configuration types and variable numbers */
typedef enum { CO_NIL, CO_STR, CO_INT } conftype;
typedef enum { CF_NIL, CF_NICK, CF_FROM, CF_SERVERHOST, CF_SERVERPORT,
CF_CIPHERSUITE, CF_CONFIGFILE, CF_CERTFILE, CF_KEYFILE, CF_FORMFILE,
CF_LOGINSCRIPT, CF_FINGERPRINT, CF_USESSL, CF_IGNSSL, CF_VERIFYSSL, CF_USECERT,
CF_PRIVHEIGHT, CF_PRIVCOLLAPS, CF_HSCROLL, CF_CHANNEL, CF_USETIME, CF_USETOPIC,
CF_SCROLLBPRIV, CF_SCROLLBACK, CF_SCROLLBPRIVT, CF_SCROLLBACKT, CF_ENCODING,
CF_BELLPRIV, CF_CASEFIRST, CF_AUTORECONN, CF_KEEPALIVE } confopt;

/* format strings */
typedef enum { FS_PLAIN, FS_CHAN, FS_PRIV, FS_SERV, FS_GLOB, FS_DBG, FS_ERR,
FS_IDLE, FS_TIME, FS_CONSOLETIME, FS_TOPICW, FS_NOTOPICW, FS_CONSOLE, FS_CONNECTED, FS_CANTCONNECT,
FS_TOPIC, FS_NOTOPIC, FS_CHGTOPIC, FS_USONLINE, FS_USMATCH, FS_SIGNON, FS_SIGNOFF,
FS_JOIN, FS_LEAVE, FS_NICKCHANGE, FS_UNKNOWNMSG, FS_BOGUSMSG, FS_RXPUBURL,
FS_MYPUBURL, FS_RXPUBMSG, FS_MYPUBMSG, FS_TXPUBMSG, FS_RXPRIVMSG, FS_TXPRIVMSG,
FS_BGPRIVMSG, FS_PUBTHOUGHT, FS_TXPUBTHOUGHT, FS_TXPUBNTHOUGHT, FS_PUBACTION,
FS_TXPUBACTION, FS_BGTXPUBACTION, FS_COMMAND, FS_LOCALCOMMAND, FS_BOGUSCOMMAND,
FS_SBINF, FS_MISSTYPED, FS_UNKNCMD, FS_BADREGEX, FS_ERR_STRING } formtstr;

/* configoption structure */
struct configoption
{
  confopt  id;
  conftype type;
  char    *varname;
  char    *defaultvalue;
  char    *value;
  union {
    char **pstr;
    unsigned int   *pint;
  } localvar;
};

typedef struct configoption configoption;

/* format strings */
struct formatstring
{
  formtstr id;
  char    *idstring;
  char    *formatstr;
};
typedef struct formatstring formatstring;

/* static tmpstr in all modules */
#define TMPSTRSIZE 1024
static char tmpstr[TMPSTRSIZE];

extern unsigned int loggedin;
extern unsigned int want_tcp_keepalive;

/* vchat-client.c */
#define ERRSTRSIZE 1024
extern char errstr[];
extern const char *vchat_cl_version;
void loadcfg (char *file,int complain,void (*lineparser) (char *));
void loadformats (char *file);
void cleanup(int signal);

/*   configuration helper funktions from vchat-client.c */
char *getformatstr (formtstr id);
char *getstroption (confopt option);
void setstroption (confopt option, char *string);
int getintoption (confopt option);
void setintoption (confopt option, int value);

/* vchat-ui.c */
extern const char *vchat_ui_version;

/*   topic and console strings */
#define TOPICSTRSIZE 1024
#define CONSOLESTRSIZE 1024
extern char topicstr[];
extern char consolestr[];
extern char *encoding;

/*   init / exit functions */
void initui (void);
void exitui (void);

/*   called from eventloop in vchat-client.c */
void userinput (void);

/*   display various messages */
int   writechan (char *str);
int   writepriv (char *str, int maybeep );
void  writeout  (const char *str);
void  showout   (void);
void  flushout  (void);
#define  msgout(STR) {flushout();writeout(STR);showout();}
void  hideout   (void);
int   writecf   (formtstr id, char *str);

extern int outputcountdown;

/*   update console / topic window */
void consoleline (char *);
void topicline (char *);

/*   prompt for nick or password */
void nickprompt (void);
int passprompt (char *buf, int size, int rwflag, void *userdata);

/*   filter functions */
void         refilterscrollback( void);

unsigned int addfilter        ( char colour, char *regex );
void         removefilter     ( char *line );
void         listfilters      ( void );
void         clearfilters     ( char colour );

void         handlequery      ( char *line );

/* vchat-protocol.c */
extern const char *vchat_io_version;

/*   connect/disconnect */
int  vcconnect    (char *server, char *port);
void vcdisconnect ();

/*   network I/O */
void networkinput (void);
void networkoutput (char *);

/*   helpers for vchat-user.c */
void ownjoin (int channel);
void ownleave (int channel);
void ownnickchange (char *newnick);

/* vchat-commands.c */
extern const char *vchat_cm_version;
void   command_version ( char *tail);

/*   user input */
void handleline (char *);

/* struct for defining "/command" handlers */
typedef struct {
  int     number;
  char   name[10];
  int    len;
  void (*handler)(char *);
  char  *short_help;
  char  *help;
} commandentry;

/* vchat-ssl.c */
extern const char *vchat_ssl_version;
extern const char *vchat_ssl_version_external;
void vchat_ssl_get_version_external();
