#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>

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
    if (!p) 
      break;

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

    printf("0x%.4x,%s,%s,%s,%s,%s,%s,%d,%d\n", 
           id, p, v, kex, auth, digest,cipher, alg_bits, aead);
  }

  printf("\n");
err: 
  return 0;
}
