
/* prototypes */

struct vc_x509store_t;
typedef struct vc_x509store_t vc_x509store_t;
typedef int (*vc_askpass_cb_t)(char *, int, int, void *);

vc_x509store_t *vc_init_x509store();
void vc_x509store_set_pkeycb(vc_x509store_t *, vc_askpass_cb_t);
void vc_x509store_setflags(vc_x509store_t *, int);
void vc_x509store_setkeyfile(vc_x509store_t *, char *);
void vc_x509store_setcertfile(vc_x509store_t *, char *);
int  vc_connect_ssl(BIO **conn, vc_x509store_t * );

#define VC_X509S_NODEF_CAFILE                      0x01
#define VC_X509S_NODEF_CAPATH                      0x02
#define VC_X509S_USE_CERTIFICATE                   0x04
#define VC_X509S_SSL_VERIFY_NONE                   0x10
#define VC_X509S_SSL_VERIFY_PEER                   0x20
#define VC_X509S_SSL_VERIFY_FAIL_IF_NO_PEER_CERT   0x40
#define VC_X509S_SSL_VERIFY_CLIENT_ONCE            0x80
#define VC_X509S_SSL_VERIFY_MASK                   0xF0

