#pragma once

#include <stdint.h>

int   vc_connect(const char *host, const char *port);
void  vc_sendmessage(const char *message);
void  vc_receive();
int   vc_poll();
void  vc_disconnect();
