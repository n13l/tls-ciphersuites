#include <unordered_map>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>

#ifndef array_size
#define array_size(a) (sizeof(a)/sizeof(*(a)))
#endif

struct iana_mapping {
	uint32_t id;
	const char *alias;
	const char *name;
	const char *version;
} def{ .id = 0xffffffff };

std::unordered_multimap<uint32_t, struct iana_mapping&> mapping{};

void
insert(struct iana_mapping& iana)
{
	auto itr = mapping.equal_range(iana.id); 
	for (auto it = itr.first; it != itr.second; it++) { 
		auto cs = it->second;
		if (cs.id == iana.id && !strcmp(cs.alias, iana.alias))
			return;
	} 
	mapping.insert({iana.id, iana});
}

/* prefix with 03 - collision with TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 */
static struct iana_mapping qsh[] = {
  {0x13d001, "QSH", "TLS_QSH", "TLSv1.3"},
};

static struct iana_mapping export1024[] = {
  {0x60,"EXP1024-RC4-MD5",             "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5", "SSLv3"},
  {0x61,"EXP1024-RC2-CBC-MD5",         "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5", "SSLv3"},
  {0x62,"EXP1024-DES-CBC-SHA",         "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", "SSLv3"},
  {0x63,"EXP1024-DHE-DSS-DES-CBC-SHA", "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", "SSLv3"},
  {0x64,"EXP1024-RC4-SHA",             "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", "SSLv3"},
  {0x65,"EXP1024-DHE-DSS-RC4-SHA",     "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA", "SSLv3"},
};

static struct iana_mapping gost89[] = {
  {0x80,"GOST94-GOST89-GOST89",        "TLS_GOSTR341094_WITH_28147_CNT_IMIT"},
  {0x81,"GOST2001-GOST89-GOST89",      "TLS_GOSTR341001_WITH_28147_CNT_IMIT"},
  {0x82,"GOST94-NULL-GOST94",          "TLS_GOSTR341001_WITH_NULL_GOSTR3411"},
  {0x83,"GOST2001-NULL-GOST89",        "TLS_GOSTR341094_WITH_NULL_GOSTR3411"},
};

/* 
 * This section defines the following four TLS13_GOST cipher suites that can
 * be used to support Russian cryptographic algorithms:

 * CipherSuite TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L = {TBD1};
 * CipherSuite TLS_GOSTR341112_256_WITH_MAGMA_MGM_L = {TBD2};
 * CipherSuite TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S = {TBD3};
 * CipherSuite TLS_GOSTR341112_256_WITH_MAGMA_MGM_S = {TBD4};
 *
 * https://tools.ietf.org/id/draft-smyshlyaev-tls13-gost-suites-01.html#RFC8446
 */

static struct iana_mapping gost341112_256[] = {
  {0x130080,"", "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L", "TLSv1.3"},
  {0x130081,"", "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L", "TLSv1.3"},
  {0x130082,"", "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S", "TLSv1.3"},
  {0x130083,"", "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S", "TLSv1.3"},
};

/*tlsv12 cipher suites */
static struct iana_mapping tlsv12[] = {
  {0x0016,"EDH-RSA-DES-CBC3-SHA",      "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"},
};

/* sslv23 cipher suites */
static struct iana_mapping sslv23[] = {
  {0x0001,"NULL-MD5",                  "TLS_RSA_WITH_NULL_MD5", "SSLv2"},
  {0x0002,"NULL-SHA",                  "TLS_RSA_WITH_NULL_SHA", "SSLv2"},
  {0x0003,"EXP-RC4-MD5",               "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "SSLv2"},
  {0x0004,"RC4-MD5",                   "TLS_RSA_WITH_RC4_128_MD5", "SSLv2"},
  {0x0005,"RC4-SHA",                   "TLS_RSA_WITH_RC4_128_SHA", "SSLv2"},
  {0x0006,"EXP-RC2-CBC-MD5",           "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "SSLv2"},
  {0x0007,"IDEA-CBC-SHA",              "TLS_RSA_WITH_IDEA_CBC_SHA", "SSLv2"},
  {0x0008,"EXP-DES-CBC-SHA",           "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "SSLv2"},
  {0x0009,"DES-CBC-SHA",               "TLS_RSA_WITH_DES_CBC_SHA","SSLv2"},
  {0x000a,"DES-CBC3-SHA",              "TLS_RSA_WITH_3DES_EDE_CBC_SHA","SSLv2"},
  {0x000b,"EXP-DH-DSS-DES-CBC-SHA",    "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA","SSLv2"},
  {0x000c,"DH-DSS-DES-CBC-SHA",        "TLS_DH_DSS_WITH_DES_CBC_SHA","SSLv2"},
  {0x000d,"DH-DSS-DES-CBC3-SHA",       "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA","SSLv2"},
  {0x000e,"EXP-DH-RSA-DES-CBC-SHA",    "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", "SSLv2"},
  {0x030080,"RC2-CBC-MD5",             "TLS_RSA_WITH_RC2_CBC_40_MD5", "SSLv2"},
  {0x050080,"IDEA-CBC-MD5",            "SSL_IDEA_128_CBC_WITH_MD5", "SSLv2"},
  {0x060040,"DES-CBC-MD5",             "SSL_DES_64_CBC_WITH_MD5","SSLv2"},
  {0x0700c0,"DES-CBC3-MD5",            "SSL_DES_192_EDE3_CBC_WITH_MD5", "SSLv2"},
  {0x080080,"RC4-64-MD5",              "SSL_RC4_128_WITH_MD5", "SSLv2"},
  {0xff0800,"DES-CFB-M1",              "SSL_DES_64_CFB64_WITH_MD5_1","SSLv2"},
};


/* elastic cipher suites */
static struct iana_mapping elastic[] = {
  {0xfefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA", ""},
  {0xfeff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", ""},
};

void
ssl_init1()
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
ssl_version1(char *str, int size)
{
	long version = SSLeay();
	unsigned char major = (version >> 28) & 0xFF;
	unsigned char minor = (version >> 20) & 0xFF;
	unsigned char patch = (version >> 12) & 0XFF;
	unsigned char dev   = (version >>  4) & 0XFF;
	snprintf(str, size, "%d.%d.%d%c", major, minor, patch, 'a' + dev - 1);
}

void
parse(char *line, int maxsize)
{
	const char *name = "", *alias = "", *version = "";
	unsigned long id = 0xffffffff, index = 0;
	for (char *v = strtok(line, ","); v; v = strtok(NULL, ",")) {
		switch (index++) {
		case 0: id = strtol(v, NULL, 16); break;
		case 1: alias = v; break;
		case 2: name = v; break;
		case 3: version = v; break;
		}
	}

	if (id == 0xffffffff)
		return;

	struct iana_mapping* cs = new iana_mapping();
	cs->id = id;
	cs->name = strdup(name);
	cs->alias = strdup(alias);
	cs->version = strdup(version);
	insert(*cs);
}

void
load_mapping(const char *file)
{
	FILE *fp = fopen(file, "r");
	if (fp == NULL)
		return;
	char line[513];
	while (!feof(fp)) {
		fscanf(fp,"%512[^\n]\n", line);
		parse(line, 512);
	}

	fclose(fp);   
}

SSL_CIPHER *
lookup(STACK_OF(SSL_CIPHER) *sk, const char *name)
{
	for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
		const char *p = SSL_CIPHER_get_name(c);
		if (strcmp(p, name))
			continue;
	}

	return nullptr;
}

int
main(int argc, char *argv[])
{
	const SSL_METHOD *meth = TLS_client_method();
	int min_version = 0, max_version = 0;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	STACK_OF(SSL_CIPHER) *sk = NULL;

	if (argc > 1)
		load_mapping(argv[1]);

	ssl_init1();

	for (int i = 0; i < array_size(qsh); i++)
		insert(qsh[i]);
	for (int i = 0; i < array_size(export1024); i++)
		insert(export1024[i]);
	for (int i = 0; i < array_size(elastic); i++)
		insert(elastic[i]);
	for (int i = 0; i < array_size(gost89); i++)
		insert(gost89[i]);
	for (int i = 0; i < array_size(sslv23); i++)
		insert(sslv23[i]);
	for (int i = 0; i < array_size(tlsv12); i++)
		insert(tlsv12[i]);

	for (int i = 0; i < array_size(gost341112_256); i++)
		insert(gost341112_256[i]);

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
		const char *std = SSL_CIPHER_standard_name(c);

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

		struct iana_mapping *cs = new iana_mapping();
		cs->id = id;
		cs->name = std;
		cs->alias = p;
		cs->version = v == NULL ? "": v;
		insert(*cs);
	}

	for (auto it: mapping) {
		struct iana_mapping& cs = it.second;		
		printf("0x%.8x,%s,%s,%s\n", (int)cs.id, cs.alias, cs.name, cs.version);
	}

err: 
  return 0;
}
