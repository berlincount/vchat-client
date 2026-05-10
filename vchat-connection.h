/*
 * vchat-connection.h
 * Connection handling
 *
 * Author:  Dirk Engling <erdgeist@erdgeist.org>
 * License: Beerware
*/
#ifndef __VCHAT_CONNECTION_H__
#define __VCHAT_CONNECTION_H__

#include <stdint.h>

extern const char *vchat_cn_version;

int vc_connect(const char *host, const char *port);
void vc_sendmessage(const char *message);
int vc_receive();
int vc_poll(int);
void vc_disconnect();

const char *vchat_tls_version_external();

#endif
