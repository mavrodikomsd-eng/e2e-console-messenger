#ifndef LIBMESH_H
#define LIBMESH_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#  define LIBMESH_API __declspec(dllexport)
#else
#  define LIBMESH_API
#endif

#define LM_KEY_SIZE 32      /* X25519 private / AES-256 / shared */
#define LM_NONCE_SIZE 12
#define LM_TAG_SIZE 16
#define LM_AAD_SELF 1       /* bit: use own public key as AAD when encrypting */

/* ---- identity ---- */
/* Returns base64 seed and base64 public key for the client.
   If identity file exists and is valid, loads it; otherwise generates,
   writes it (with 0600 perms) and returns. On error returns nonzero.
   seed_b64_alloc/pub_b64_alloc must be freed with free(). */
LIBMESH_API int lm_load_or_create_identity(const char *path,
                                           char **seed_b64_alloc,
                                           char **pub_b64_alloc);

/* ---- ECDH key derivation: SHA-256(X25519(seed, peer_pub)) ---- */
/* seed_b64 / peer_pub_b64 are base64 strings. out[32] filled. Returns 0 ok. */
LIBMESH_API int lm_derive_key(const char *seed_b64,
                              const char *peer_pub_b64,
                              uint8_t out[32]);

/* ---- AES-256-GCM ---- */
/* Encrypts plaintext[plen] with aad (may be NULL), using key[32].
   Returns a newly allocated base64 string (nonce||ct||tag) in out_alloc.
   Returns 0 on success, nonzero on failure. */
LIBMESH_API int lm_gcm_encrypt_b64(const uint8_t key[32],
                                   const uint8_t *plaintext, size_t plen,
                                   const uint8_t *aad, size_t aad_len,
                                   char **out_alloc);

/* Decrypts a base64(nonce||ct||tag) string. Returned plaintext in out_alloc
   (NUL-terminated, may contain binary). out_len set on success. Returns 0 ok. */
LIBMESH_API int lm_gcm_decrypt_b64(const uint8_t key[32],
                                   const char *encoded,
                                   const uint8_t *aad, size_t aad_len,
                                   uint8_t **out_alloc, size_t *out_len);

/* Convenience: encrypt to a peer using ECDH + AAD = self public key. */
LIBMESH_API int lm_encrypt_to_peer(const char *our_seed_b64,
                                   const char *peer_pub_b64,
                                   const char *self_pub_b64,
                                   const uint8_t *plaintext, size_t plen,
                                   char **out_alloc);

/* ---- argon2id (for account passwords) ---- */
/* out[32]. Params: t=2, m=65536, p=1. Returns 0 ok. */
LIBMESH_API int lm_argon2id(const char *password,
                            const uint8_t salt[16],
                            uint8_t out[32]);

/* ---- frame encode/decode: [1 byte type][4 byte length BE][payload] ---- */
LIBMESH_API uint8_t *lm_frame_encode(uint8_t ftype, const uint8_t *payload,
                                     size_t plen, size_t *out_len);
/* Decodes one frame from a buffer. Returns 0 ok, -1 on malformed/short. */
LIBMESH_API int lm_frame_decode(const uint8_t *buf, size_t buflen,
                                uint8_t *ftype, uint8_t **payload,
                                size_t *plen);

/* Frees buffers returned by library in the same CRT that allocated them. */
LIBMESH_API void lm_free(void *p);

#endif