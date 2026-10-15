/*
 * crypto.c - SHA-256 hashing and real ECDSA (secp256k1) signatures.
 *
 * Uses OpenSSL libcrypto. The EC_KEY API is flagged "deprecated" in
 * OpenSSL 3.x but remains fully supported; the spec explicitly names it,
 * so we silence the deprecation warnings to keep -Wall output clean.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include "libchain.h"

static void to_hex(const unsigned char *b, size_t n, char *out) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = h[b[i] >> 4]; out[2 * i + 1] = h[b[i] & 15]; }
    out[2 * n] = '\0';
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex string into bytes; returns byte count or -1 on error. */
static int from_hex(const char *s, unsigned char *out, size_t max) {
    size_t n = strlen(s);
    if (n % 2 || n / 2 > max) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)(hi * 16 + lo);
    }
    return (int)(n / 2);
}

/* SHA-256 of an arbitrary buffer, written as 64 lowercase hex chars. */
void sha256_hex(const void *data, size_t n, char out[HASH_LEN]) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data, n, md);
    to_hex(md, SHA256_DIGEST_LENGTH, out);
}

/*
 * Key generation: a fresh secp256k1 key pair.
 *   priv  <- hex of the DER (SEC1) private key structure
 *   pub   <- hex of the 33-byte compressed public key (on-chain identity)
 */
int crypto_keygen(char *priv, size_t pl, char *pub, size_t bl) {
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!k) return -1;
    if (!EC_KEY_generate_key(k)) { EC_KEY_free(k); return -1; }
    EC_KEY_set_conv_form(k, POINT_CONVERSION_COMPRESSED);
    unsigned char buf[300], *p = buf;
    int n = i2d_ECPrivateKey(k, &p);
    if (n <= 0 || (size_t)(2 * n + 1) > pl) { EC_KEY_free(k); return -1; }
    to_hex(buf, (size_t)n, priv);
    p = buf;
    n = i2o_ECPublicKey(k, &p);
    if (n <= 0 || (size_t)(2 * n + 1) > bl) { EC_KEY_free(k); return -1; }
    to_hex(buf, (size_t)n, pub);
    EC_KEY_free(k);
    return 0;
}

/*
 * Signing: digest = SHA-256(msg); signature = ECDSA_sign(digest) with the
 * private key; output is the DER-encoded signature in hex.
 */
int crypto_sign(const char *priv_hex, const char *msg, char *sig_hex, size_t sl) {
    unsigned char kb[300], md[SHA256_DIGEST_LENGTH], sig[128];
    int kn = from_hex(priv_hex, kb, sizeof kb);
    if (kn <= 0) return -1;
    const unsigned char *p = kb;
    EC_KEY *k = d2i_ECPrivateKey(NULL, &p, kn);
    if (!k) return -1;
    SHA256((const unsigned char *)msg, strlen(msg), md);
    unsigned int siglen = 0;
    int ok = ECDSA_sign(0, md, sizeof md, sig, &siglen, k);
    EC_KEY_free(k);
    if (!ok || (size_t)(2 * siglen + 1) > sl) return -1;
    to_hex(sig, siglen, sig_hex);
    return 0;
}

/* Verification against the signer's public key. Returns 1 if valid. */
int crypto_verify(const char *pub_hex, const char *msg, const char *sig_hex) {
    unsigned char pb[100], sig[128], md[SHA256_DIGEST_LENGTH];
    if (!pub_hex || !sig_hex || !*pub_hex || !*sig_hex) return 0;
    int pn = from_hex(pub_hex, pb, sizeof pb);
    int sn = from_hex(sig_hex, sig, sizeof sig);
    if (pn <= 0 || sn <= 0) return 0;
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!k) return 0;
    const unsigned char *p = pb;
    if (!o2i_ECPublicKey(&k, &p, pn)) { EC_KEY_free(k); return 0; }
    SHA256((const unsigned char *)msg, strlen(msg), md);
    int ok = ECDSA_verify(0, md, sizeof md, sig, sn, k);
    EC_KEY_free(k);
    return ok == 1;
}
