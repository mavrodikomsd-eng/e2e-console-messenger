#include "libmesh.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static char *b64enc(const unsigned char *in, size_t n) {
    size_t cap = sodium_base64_encoded_len(n, sodium_base64_VARIANT_ORIGINAL);
    char *s = malloc(cap);
    if (!s) return NULL;
    sodium_bin2base64(s, cap, in, n, sodium_base64_VARIANT_ORIGINAL);
    size_t l = strlen(s);
    if (l && s[l-1] == '\n') s[l-1] = '\0';
    return s;
}

static unsigned char *b64dec(const char *s, size_t *out_len) {
    size_t mlen = strlen(s) * 3 / 4 + 4;
    unsigned char *out = malloc(mlen);
    if (!out) return NULL;
    *out_len = 0;
    size_t actual = 0;
    int rc = sodium_base642bin(out, mlen, s, strlen(s), NULL, &actual,
                               NULL, sodium_base64_VARIANT_ORIGINAL);
    if (rc != 0) { free(out); return NULL; }
    *out_len = actual;
    return out;
}

LIBMESH_API extern int lm_load_or_create_identity(const char *path,
    char **seed_b64_alloc, char **pub_b64_alloc) {
    unsigned char seed[32], pub[32];
    FILE *f = fopen(path, "r");
    if (f) {
        char line[256];
        if (fgets(line, sizeof line, f)) {
            char s1[200], s2[200];
            if (sscanf(line, "%199s %199s", s1, s2) == 2) {
                size_t len1, len2;
                unsigned char *d1 = b64dec(s1, &len1);
                unsigned char *d2 = b64dec(s2, &len2);
                if (d1 && d2 && len1 == 32 && len2 == 32 &&
                    crypto_scalarmult_curve25519_base(pub, d1) == 0 &&
                    memcmp(pub, d2, 32) == 0) {
                    *seed_b64_alloc = strdup(s1);
                    *pub_b64_alloc = strdup(s2);
                    free(d1); free(d2); fclose(f);
                    return (*seed_b64_alloc && *pub_b64_alloc) ? 0 : -1;
                }
                free(d1); free(d2);
            }
        }
        fclose(f);
    }
    randombytes_buf(seed, sizeof seed);
    crypto_scalarmult_curve25519_base(pub, seed);
    char *sb = b64enc(seed, sizeof seed);
    char *pb = b64enc(pub, sizeof pub);
    if (!sb || !pb) { free(sb); free(pb); return -1; }
    FILE *wf = fopen(path, "w");
    if (!wf) { free(sb); free(pb); return -1; }
    fprintf(wf, "%s %s\n", sb, pb);
#ifndef _WIN32
    chmod(path, 0600);
#endif
    fclose(wf);
    *seed_b64_alloc = sb;
    *pub_b64_alloc = pb;
    return 0;
}

LIBMESH_API extern int lm_derive_key(const char *seed_b64,
    const char *peer_pub_b64, uint8_t out[32]) {
    if (!seed_b64 || !peer_pub_b64) return -1;
    size_t slen, publen;
    unsigned char *seed = b64dec(seed_b64, &slen);
    unsigned char *pub = b64dec(peer_pub_b64, &publen);
    if (!seed || !pub || slen != 32 || publen != 32) {
        free(seed); free(pub); return -1;
    }
    unsigned char shared[32];
    int rc = crypto_scalarmult_curve25519(shared, seed, pub);
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, shared, 32);
    crypto_hash_sha256_final(&st, out);
    sodium_memzero(shared, sizeof shared);
    free(seed); free(pub);
    return rc == 0 ? 0 : -1;
}
LIBMESH_API extern int lm_gcm_encrypt_b64(const uint8_t key[32],
    const uint8_t *plaintext, size_t plen, const uint8_t *aad, size_t aad_len,
    char **out_alloc) {
    unsigned char nonce[12];
    randombytes_buf(nonce, sizeof nonce);
    unsigned char *ct = malloc(plen + 16);
    if (!ct) return -1;
    unsigned long long clen = 0;
    int rc = crypto_aead_aes256gcm_encrypt(ct, &clen, plaintext, plen,
                                           aad, aad_len, NULL, nonce, key);
    if (rc != 0) { free(ct); return -1; }
    unsigned char *bundle = malloc(12 + (size_t)clen);
    if (!bundle) { free(ct); return -1; }
    memcpy(bundle, nonce, 12);
    memcpy(bundle + 12, ct, (size_t)clen);
    free(ct);
    char *b64 = b64enc(bundle, 12 + (size_t)clen);
    free(bundle);
    if (!b64) return -1;
    *out_alloc = b64;
    return 0;
}

LIBMESH_API extern int lm_gcm_decrypt_b64(const uint8_t key[32],
    const char *encoded, const uint8_t *aad, size_t aad_len,
    uint8_t **out_alloc, size_t *out_len) {
    if (!encoded || !out_alloc || !out_len) return -1;
    size_t dlen;
    unsigned char *data = b64dec(encoded, &dlen);
    if (!data || dlen < 12 + 16) { free(data); return -1; }
    const unsigned char *nonce = data;
    size_t clen = dlen - 12;
    unsigned char *ct = malloc(clen);
    if (!ct) { free(data); return -1; }
    unsigned long long plen = 0;
    int rc = crypto_aead_aes256gcm_decrypt(ct, &plen, NULL, data + 12, clen,
                                           aad, aad_len, nonce, key);
    free(data);
    if (rc != 0) { free(ct); return -1; }
    *out_alloc = ct;
    *out_len = (size_t)plen;
    return 0;
}

LIBMESH_API int lm_encrypt_to_peer(const char *our_seed_b64,
    const char *peer_pub_b64, const char *self_pub_b64,
    const uint8_t *plaintext, size_t plen, char **out_alloc) {
    uint8_t key[32];
    if (lm_derive_key(our_seed_b64, peer_pub_b64, key) != 0) return -1;
    int rc = lm_gcm_encrypt_b64(key, plaintext, plen,
                                (const uint8_t *)self_pub_b64,
                                self_pub_b64 ? strlen(self_pub_b64) : 0,
                                out_alloc);
    sodium_memzero(key, sizeof key);
    return rc;
}

LIBMESH_API int lm_argon2id(const char *password, const uint8_t salt[16],
    uint8_t out[32]) {
    int rc = crypto_pwhash(out, 32, password, strlen(password), salt,
                           65536, 2, crypto_pwhash_ALG_ARGON2ID13);
    return rc == 0 ? 0 : -1;
}

LIBMESH_API void lm_free(void *p) {
    free(p);
}

LIBMESH_API uint8_t *lm_frame_encode(uint8_t ftype, const uint8_t *payload,
    size_t plen, size_t *out_len) {
    size_t n = 5 + plen;
    uint8_t *buf = malloc(n);
    if (!buf) return NULL;
    buf[0] = ftype;
    buf[1] = (uint8_t)((plen >> 24) & 0xff);
    buf[2] = (uint8_t)((plen >> 16) & 0xff);
    buf[3] = (uint8_t)((plen >> 8) & 0xff);
    buf[4] = (uint8_t)(plen & 0xff);
    if (plen) memcpy(buf + 5, payload, plen);
    if (out_len) *out_len = n;
    return buf;
}

LIBMESH_API int lm_frame_decode(const uint8_t *buf, size_t buflen,
    uint8_t *ftype, uint8_t **payload, size_t *plen) {
    if (!buf || buflen < 5) return -1;
    size_t len = ((size_t)buf[1] << 24) | ((size_t)buf[2] << 16) |
                 ((size_t)buf[3] << 8) | (size_t)buf[4];
    if (5 + len > buflen) return -1;
    *ftype = buf[0];
    *payload = (uint8_t *)buf + 5;
    *plen = len;
    return 0;
}