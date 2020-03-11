#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>

#ifndef array_size
#define array_size(a) (sizeof(a)/sizeof(*(a)))
#endif

struct iana_ciphersuite_mapping {
  uint32_t id;
  const char *alias;
  const char *name;
};

struct iana_ciphersuite_mapping export1024[] = {
  {0x60,"EXP1024-RC4-MD5",             "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"},
  {0x61,"EXP1024-RC2-CBC-MD5",         "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"},
  {0x62,"EXP1024-DES-CBC-SHA",         "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"},
  {0x63,"EXP1024-DHE-DSS-DES-CBC-SHA", "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"},
  {0x64,"EXP1024-RC4-SHA",             "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"},
  {0x65,"EXP1024-DHE-DSS-RC4-SHA",     "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"},
};

struct iana_ciphersuite_mapping gost89[] = {
  {0x80,"GOST94-GOST89-GOST89",        "TLS_GOSTR341094_WITH_28147_CNT_IMIT"},
  {0x81,"GOST2001-GOST89-GOST89",      "TLS_GOSTR341001_WITH_28147_CNT_IMIT"},
  {0x82,"GOST94-NULL-GOST94",          "TLS_GOSTR341001_WITH_NULL_GOSTR3411"},
  {0x83,"GOST2001-GOST89-GOST89",      "TLS_GOSTR341094_WITH_NULL_GOSTR3411"},
};

/* sslv2 cipher suites */
struct iana_ciphersuite_mapping sslv2[] = {
  {0x000000,"NULL-MD5",                "SSL_NULL_WITH_MD5"},
  {0x010080,"RC4-MD5",                 "SSL_RC4_128_WITH_MD5"},
  {0x020080,"EXP-RC4-MD5",             "SSL_RC4_128_EXPORT40_WITH_MD5"},
  {0x030080,"RC2-CBC-MD5",             "SSL_RC2_128_CBC_WITH_MD5"},
  {0x040080,"EXP-RC2-CBC-MD5",         "SSL_RC2_128_CBC_EXPORT40_WITH_MD5"},
  {0x050080,"IDEA-CBC-MD5",            "SSL_IDEA_128_CBC_WITH_MD5"},
  {0x060040,"DES-CBC-MD5",             "SSL_DES_64_CBC_WITH_MD5"},
  {0x060140,"DES-CBC-SHA",             "SSL_DES_64_CBC_WITH_SHA"},
  {0x0700c0,"DES-CBC3-MD5",            "SSL_DES_192_EDE3_CBC_WITH_MD5"},
  {0x0701c0,"DES-CBC3-SHA",            "SSL_DES_192_EDE3_CBC_WITH_SHA"},
  {0x080080,"RC4-64-MD5",              "SSL_RC4_128_WITH_MD5"},
  {0xff0800,"DES-CFB-M1",              "SSL_DES_64_CFB64_WITH_MD5_1"},
};

void
ssl_init(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10001000L
  OpenSSL_add_ssl_algorithms();
  OpenSSL_add_all_algorithms();	
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests(); 
#else
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
#endif  
}

void
ssl_version(char *str, int size)
{
  long version = SSLeay();
  unsigned char major = (version >> 28) & 0xFF;
  unsigned char minor = (version >> 20) & 0xFF;
  unsigned char patch = (version >> 12) & 0XFF;
  unsigned char dev   = (version >>  4) & 0XFF;
  snprintf(str, size, "%d.%d.%d%c", major, minor, patch, 'a' + dev - 1);
}

int
main(int argc, char *argv[])
{
  const SSL_METHOD *meth = TLS_client_method();
  int min_version = 0, max_version = 0;
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;
  STACK_OF(SSL_CIPHER) *sk = NULL;

  ssl_init();

  for (int i = 0; i < array_size(export1024); i++)
    printf("0x%.8x,%s,,,,,,,,%s\n", i, export1024[i].alias, export1024[i].name);

  for (int i = 0; i < array_size(gost89); i++)
    printf("0x%.8x,%s,,,,,,,,%s\n", i, gost89[i].alias, gost89[i].name);

  for (int i = 0; i < array_size(export1024); i++)
    printf("0x%.8x,%s,,,,,,,,%s\n", i, sslv2[i].alias, sslv2[i].name);

  ctx = SSL_CTX_new(meth);
  if (SSL_CTX_set_min_proto_version(ctx, min_version) == 0)
        goto err;
  if (SSL_CTX_set_max_proto_version(ctx, max_version) == 0)
        goto err;

  SSL_CTX_set_security_level(ctx, 0);
  SSL_CTX_set_cipher_list(ctx, "ALL");

  ssl = SSL_new(ctx);
  sk = SSL_get_ciphers(ssl);

  for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
    const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
    const char *p = SSL_CIPHER_get_name(c);

    uint16_t id = SSL_CIPHER_get_id(c);
    const char *v = SSL_CIPHER_get_version(c);
    int nid_kex = SSL_CIPHER_get_kx_nid(c);
    int nid_auth = SSL_CIPHER_get_auth_nid(c);
    int nid_digest = SSL_CIPHER_get_digest_nid(c);
    int nid_cipher = SSL_CIPHER_get_cipher_nid(c);

    int alg_bits = 0;
    int bits = SSL_CIPHER_get_bits(c, &alg_bits);

    const char *kex = OBJ_nid2ln(nid_kex); 
    const char *auth = OBJ_nid2ln(nid_auth); 
    const char *digest = OBJ_nid2ln(nid_digest);
    const char *cipher = OBJ_nid2ln(nid_cipher);

    int aead = SSL_CIPHER_is_aead(c);

    printf("0x%.8x,%s,%s,%s,%s,%s,%s,%d,%d,\n", 
           id, p, v, kex, auth, digest,cipher, alg_bits, aead);
  }

  printf("\n");
err: 
  return 0;
}
