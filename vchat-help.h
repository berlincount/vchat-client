/*
 * vchat-client - alpha version
 * vchat-help.h - definitions for help on comands
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

/* Help strings */

#define SHORT_HELPTEXT_VERSION "/VERSION              Prints out version number of all modules"
#define LONG_HELPTEXT_VERSION  NULL
#define SHORT_HELPTEXT_CONFIG  "/CONFIG               This feature is not implemented, yet"
#define LONG_HELPTEXT_CONFIG   NULL
#define SHORT_HELPTEXT_HELP    "/HELP  [COMMAND]      Display this help, or help on COMMAND"
#define LONG_HELPTEXT_HELP     NULL
#define SHORT_HELPTEXT_RMFLT   "/RMFLT [REGEX | ID]   Remove regex or id from filter list"
#define LONG_HELPTEXT_RMFLT     SHORT_HELPTEXT_RMFLT
#define SHORT_HELPTEXT_CLFLT   "/CLFLT (C)            Remove all filter rules (matching C)"
#define LONG_HELPTEXT_CLFLT    SHORT_HELPTEXT_CLFLT
#define SHORT_HELPTEXT_LSFLT   "/LSFLT (C)            List all filter rules (matching C)"
#define LONG_HELPTEXT_LSFLT    SHORT_HELPTEXT_LSFLT
#define SHORT_HELPTEXT_FLT     "/FLT   C REGEX        Add regex to filter list"
#define LONG_HELPTEXT_FLT      SHORT_HELPTEXT_FLT "\n       C may be       +  - zoom,     -  - ignore,\n\
                      0  - default,  1  - red,     2  - green,\n\
                      3  - yello,    4  - blue,    5  - magenta,\n\
                      6  - magenta,  7  - white,   8  - white/red\n\
                      9  - blue/red, aA - alt,     bB - bold\n\
                      dD - dim,      iL - invis,   lL - blink\n\
                      nN - normal,   pP - protect, rR - reverse,\n\
                      sS - standout, uU - underline"
#define SHORT_HELPTEXT_KEYS    "/HELP  KEYS           Show summary of key commands"
#define LONG_HELPTEXT_KEYS     " - -   List of Commands:\n\
      ^J  - clear private window\n\
      ^O  - clear channel window\n\
      ^L  - redraw screen/scroll to bottom\n\
      ^F  - scroll window up\n\
      ^B  - scroll window down\n\
      ^R  - change active window\n\
            (watch the *)\n\
      ^T  - shrink private window size\n\
      ^G  - grow private window size\n\
      ^X  - switch off message window or\n\
            toggle private window\n\
      TAB - nick completion"
#define SHORT_HELPTEXT_QUIT      "/QUIT  [REASON]       Leave the chat for reason Reason"
#define LONG_HELPTEXT_QUIT       NULL
#define SHORT_HELPTEXT_USER      "/USER  REGEX          Lists all users matching regex REGEX"
#define LONG_HELPTEXT_USER       NULL
#define SHORT_HELPTEXT_DICT      "/DICT  ITEM [...]     Add space separated items to the user completion dict"
#define LONG_HELPTEXT_DICT       NULL
#define SHORT_HELPTEXT_MSG       "/M[SG] USER MESSAGE   Send private message to user USER"
#define LONG_HELPTEXT_MSG        NULL
#define SHORT_HELPTEXT_ME        "/ME    ACTION         Let the user do an action"
#define LONG_HELPTEXT_ME         NULL
#define SHORT_HELPTEXT_M         SHORT_HELPTEXT_MSG
#define LONG_HELPTEXT_M          LONG_HELPTEXT_MSG
#define SHORT_HELPTEXT_FILTERS   "/HELP  FILTERS        Show summary of filter commands"
#define LONG_HELPTEXT_FILTERS    SHORT_HELPTEXT_FLT "\n" SHORT_HELPTEXT_RMFLT "\n" SHORT_HELPTEXT_LSFLT "\n" SHORT_HELPTEXT_CLFLT
#define LONG_HELPTEXT_RECONNECT  NULL
#define SHORT_HELPTEXT_RECONNECT "/RECONNECT            Forces client to reconnect"

