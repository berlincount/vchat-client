
/* types */

typedef int (*vc_x509verify_cb_t)(int, X509_STORE_CTX *);
typedef int (*vc_askpass_cb_t)(char *, int, int, void *);
typedef struct {
   char                 *cafile;
   char                 *capath;
   char                 *crlfile;
   vc_x509verify_cb_t   callback;
   vc_askpass_cb_t      askpass_callback;
   STACK_OF(X509)       *certs;
   STACK_OF(X509_CRL)   *crls;
   char                 *use_certfile;
   STACK_OF(X509)       *use_certs;
   char                 *use_keyfile;
   EVP_PKEY             *use_key;
   int                  flags;
   int                  ignore_ssl;
} vc_x509store_t;

/* prototypes */

BIO * vc_connect(char *, int , int, vc_x509store_t *, SSL_CTX **);
BIO * vc_connect_ssl(char *, int, vc_x509store_t *, SSL_CTX **);
SSL_CTX * vc_create_sslctx( vc_x509store_t *);
void vc_init_x509store(vc_x509store_t *);
void vc_cleanup_x509store(vc_x509store_t *);
void vc_x509store_setcafile(vc_x509store_t *, char *); 
void vc_x509store_setcapath(vc_x509store_t *, char *); 
void vc_x509store_setcrlfile(vc_x509store_t *, char *); 
void vc_x509store_setkeyfile(vc_x509store_t *, char *); 
void vc_x509store_setcertfile(vc_x509store_t *, char *); 
void vc_x509store_addcert(vc_x509store_t *, X509 *);
void vc_x509store_setcb(vc_x509store_t *, vc_x509verify_cb_t);
void vc_x509store_set_pkeycb(vc_x509store_t *, vc_askpass_cb_t); 
void vc_x509store_setflags(vc_x509store_t *, int);
void vc_x509store_setignssl(vc_x509store_t *, int);
void vc_x509store_clearflags(vc_x509store_t *, int);
int vc_verify_cert(X509 *, vc_x509store_t *);
int vc_verify_cert_hostname(X509 *, char *);
int vc_verify_callback(int, X509_STORE_CTX *);
X509_STORE * vc_x509store_create(vc_x509store_t *);

#define VC_X509S_NODEF_CAFILE                      0x01
#define VC_X509S_NODEF_CAPATH                      0x02 
#define VC_X509S_USE_CERTIFICATE                   0x04
#define VC_X509S_SSL_VERIFY_NONE                   0x10
#define VC_X509S_SSL_VERIFY_PEER                   0x20
#define VC_X509S_SSL_VERIFY_FAIL_IF_NO_PEER_CERT   0x40
#define VC_X509S_SSL_VERIFY_CLIENT_ONCE            0x80
#define VC_X509S_SSL_VERIFY_MASK                   0xF0

