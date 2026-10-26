#ifndef TERA_CRYPT_H
#define TERA_CRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TeraCrypt TeraCrypt;

/* Four 128-byte handshake blocks. Encrypt and decrypt are separate streams. */
TeraCrypt *tera_crypt_new(
    const uint8_t client_key1[128],
    const uint8_t client_key2[128],
    const uint8_t server_key1[128],
    const uint8_t server_key2[128]);

void tera_crypt_decrypt(TeraCrypt *ctx, uint8_t *data, size_t len);
void tera_crypt_encrypt(TeraCrypt *ctx, uint8_t *data, size_t len);
void tera_crypt_free(TeraCrypt *ctx);

#ifdef __cplusplus
}
#endif

#endif
