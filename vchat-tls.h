#pragma once

/* prototypes */

typedef int (*vc_askpass_cb_t)(char *, int, int, void *);
struct vc_x509store_t {
  char *cafile;
  char *capath;
  char *crlfile;
  vc_askpass_cb_t askpass_callback;
  char *certfile;
  char *keyfile;
  int flags;
};
typedef struct vc_x509store_t vc_x509store_t;

void vc_init_x509store(vc_x509store_t *);
void vc_x509store_set_pkeycb(vc_x509store_t *, vc_askpass_cb_t);
void vc_x509store_setflags(vc_x509store_t *, int);
void vc_x509store_setkeyfile(vc_x509store_t *, char *);
void vc_x509store_setcertfile(vc_x509store_t *, char *);
void vc_x509store_setcafile(vc_x509store_t *, char *);
void vc_x509store_clearflags(vc_x509store_t *, int);
void vc_x509store_setcapath(vc_x509store_t *, char *);
void vc_x509store_setcrlfile(vc_x509store_t *, char *);
void vc_cleanup_x509store(vc_x509store_t *s);

int vc_tls_connect(int serverfd, vc_x509store_t *);
ssize_t vc_tls_sendmessage(const void *buf, size_t size);
ssize_t vc_tls_receivemessage(void *buf, size_t size);
void vc_tls_cleanup();

#define VC_X509S_USE_CAFILE                        0x01
#define VC_X509S_USE_CAPATH                        0x02
#define VC_X509S_USE_CERTIFICATE                   0x04
#define VC_X509S_SSL_VERIFY_NONE                   0x10
#define VC_X509S_SSL_VERIFY_PEER                   0x20
#define VC_X509S_SSL_VERIFY_FAIL_IF_NO_PEER_CERT   0x40
#define VC_X509S_SSL_VERIFY_CLIENT_ONCE            0x80
#define VC_X509S_SSL_VERIFY_MASK                   0xF0

