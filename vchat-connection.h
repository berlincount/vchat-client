#pragma once

#include <stdint.h>

int     vc_connect(const char *host, const char *port);
void    vc_sendmessage(const char *message);
ssize_t vc_receivemessage(char *buffer, size_t size);
int     vc_poll();
void    vc_disconnect();
