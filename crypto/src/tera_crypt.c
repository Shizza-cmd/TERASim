#include "tera_crypt.h"

#include <stdlib.h>
#include <string.h>

typedef struct Cryptor {
    uint32_t buffer[3][58];
    int size[3];
    int pos1[3];
    int pos2[3];
    int flag[3];
    uint32_t sum[3];
    uint32_t change_data;
    int change_len;
} Cryptor;

struct TeraCrypt {
    Cryptor decrypt;
    Cryptor encrypt;
};

static uint32_t rotl32(uint32_t word, int bits) {
    return (word << bits) | (word >> (32 - bits));
}

/* SHA-1 as used by the classic TERA cryptor: the message schedule is not rotated. */
static void sha_digest(const uint8_t *message, size_t length, uint32_t out[5]) {
    uint32_t digest[5] = {
        0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u,
    };
    uint32_t bit_low = 0;
    uint32_t bit_high = 0;
    uint8_t block[64];
    int index = 0;
    size_t i;

    memset(block, 0, sizeof(block));

    for (i = 0; i < length; i++) {
        block[index++] = message[i];
        bit_low += 8;
        if (bit_low == 0) {
            bit_high++;
        }
        if (index == 64) {
            uint32_t w[80];
            uint32_t a, b, c, d, e;
            int t;
            for (t = 0; t < 16; t++) {
                w[t] = ((uint32_t)block[t * 4] << 24) | ((uint32_t)block[t * 4 + 1] << 16) |
                       ((uint32_t)block[t * 4 + 2] << 8) | (uint32_t)block[t * 4 + 3];
            }
            for (t = 16; t < 80; t++) {
                w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            }
            a = digest[0];
            b = digest[1];
            c = digest[2];
            d = digest[3];
            e = digest[4];
            for (t = 0; t < 80; t++) {
                uint32_t f, k, temp;
                if (t < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999u;
                } else if (t < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1u;
                } else if (t < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDCu;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6u;
                }
                temp = rotl32(a, 5) + f + e + w[t] + k;
                e = d;
                d = c;
                c = rotl32(b, 30);
                b = a;
                a = temp;
            }
            digest[0] += a;
            digest[1] += b;
            digest[2] += c;
            digest[3] += d;
            digest[4] += e;
            index = 0;
        }
    }

    block[index++] = 0x80;
    if (index > 56) {
        while (index < 64) {
            block[index++] = 0;
        }
        {
            uint32_t w[80];
            uint32_t a, b, c, d, e;
            int t;
            for (t = 0; t < 16; t++) {
                w[t] = ((uint32_t)block[t * 4] << 24) | ((uint32_t)block[t * 4 + 1] << 16) |
                       ((uint32_t)block[t * 4 + 2] << 8) | (uint32_t)block[t * 4 + 3];
            }
            for (t = 16; t < 80; t++) {
                w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            }
            a = digest[0];
            b = digest[1];
            c = digest[2];
            d = digest[3];
            e = digest[4];
            for (t = 0; t < 80; t++) {
                uint32_t f, k, temp;
                if (t < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999u;
                } else if (t < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1u;
                } else if (t < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDCu;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6u;
                }
                temp = rotl32(a, 5) + f + e + w[t] + k;
                e = d;
                d = c;
                c = rotl32(b, 30);
                b = a;
                a = temp;
            }
            digest[0] += a;
            digest[1] += b;
            digest[2] += c;
            digest[3] += d;
            digest[4] += e;
        }
        index = 0;
        memset(block, 0, 56);
    } else {
        while (index < 56) {
            block[index++] = 0;
        }
    }

    block[56] = (uint8_t)(bit_high >> 24);
    block[57] = (uint8_t)(bit_high >> 16);
    block[58] = (uint8_t)(bit_high >> 8);
    block[59] = (uint8_t)bit_high;
    block[60] = (uint8_t)(bit_low >> 24);
    block[61] = (uint8_t)(bit_low >> 16);
    block[62] = (uint8_t)(bit_low >> 8);
    block[63] = (uint8_t)bit_low;

    {
        uint32_t w[80];
        uint32_t a, b, c, d, e;
        int t;
        for (t = 0; t < 16; t++) {
            w[t] = ((uint32_t)block[t * 4] << 24) | ((uint32_t)block[t * 4 + 1] << 16) |
                   ((uint32_t)block[t * 4 + 2] << 8) | (uint32_t)block[t * 4 + 3];
        }
        for (t = 16; t < 80; t++) {
            w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
        }
        a = digest[0];
        b = digest[1];
        c = digest[2];
        d = digest[3];
        e = digest[4];
        for (t = 0; t < 80; t++) {
            uint32_t f, k, temp;
            if (t < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999u;
            } else if (t < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1u;
            } else if (t < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCu;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6u;
            }
            temp = rotl32(a, 5) + f + e + w[t] + k;
            e = d;
            d = c;
            c = rotl32(b, 30);
            b = a;
            a = temp;
        }
        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;
    }

    memcpy(out, digest, sizeof(digest));
}

static void cryptor_init(Cryptor *cryptor) {
    memset(cryptor, 0, sizeof(*cryptor));
    cryptor->size[0] = 55;
    cryptor->size[1] = 57;
    cryptor->size[2] = 58;
    cryptor->pos2[0] = 31;
    cryptor->pos2[1] = 50;
    cryptor->pos2[2] = 39;
}

static void cryptor_generate(Cryptor *cryptor, const uint8_t src[128]) {
    uint8_t buf[680];
    int i;
    for (i = 0; i < 680; i++) {
        buf[i] = src[i % 128];
    }
    buf[0] = 128;
    for (i = 0; i < 680; i += 20) {
        uint32_t sha[5];
        int j;
        sha_digest(buf, 680, sha);
        for (j = 0; j < 5; j++) {
            uint32_t word = sha[j];
            buf[i + j * 4] = (uint8_t)word;
            buf[i + j * 4 + 1] = (uint8_t)(word >> 8);
            buf[i + j * 4 + 2] = (uint8_t)(word >> 16);
            buf[i + j * 4 + 3] = (uint8_t)(word >> 24);
        }
    }
    for (i = 0; i < 55; i++) {
        cryptor->buffer[0][i] = (uint32_t)buf[i * 4] | ((uint32_t)buf[i * 4 + 1] << 8) |
                                ((uint32_t)buf[i * 4 + 2] << 16) | ((uint32_t)buf[i * 4 + 3] << 24);
    }
    for (i = 0; i < 57; i++) {
        int o = 220 + i * 4;
        cryptor->buffer[1][i] = (uint32_t)buf[o] | ((uint32_t)buf[o + 1] << 8) |
                                ((uint32_t)buf[o + 2] << 16) | ((uint32_t)buf[o + 3] << 24);
    }
    for (i = 0; i < 58; i++) {
        int o = 448 + i * 4;
        cryptor->buffer[2][i] = (uint32_t)buf[o] | ((uint32_t)buf[o + 1] << 8) |
                                ((uint32_t)buf[o + 2] << 16) | ((uint32_t)buf[o + 3] << 24);
    }
}

static void cryptor_apply(Cryptor *cryptor, uint8_t *data, int size) {
    int original = size;
    int pre = (size < cryptor->change_len) ? size : cryptor->change_len;
    int i;
    if (pre != 0) {
        for (i = 0; i < pre; i++) {
            data[i] ^= (uint8_t)(cryptor->change_data >> (8 * (4 - cryptor->change_len + i)));
        }
        cryptor->change_len -= pre;
        size -= pre;
    }

    for (i = pre; i < original - 3; i += 4) {
        int result = cryptor->flag[0] & cryptor->flag[1] |
                     cryptor->flag[2] & (cryptor->flag[0] | cryptor->flag[1]);
        int j;
        for (j = 0; j < 3; j++) {
            if (result == cryptor->flag[j]) {
                uint32_t t1 = cryptor->buffer[j][cryptor->pos1[j]];
                uint32_t t2 = cryptor->buffer[j][cryptor->pos2[j]];
                uint32_t t3 = (t1 <= t2) ? t1 : t2;
                uint32_t sum = t1 + t2;
                cryptor->sum[j] = sum;
                cryptor->flag[j] = (t3 > sum) ? 1 : 0;
                cryptor->pos1[j] = (cryptor->pos1[j] + 1) % cryptor->size[j];
                cryptor->pos2[j] = (cryptor->pos2[j] + 1) % cryptor->size[j];
            }
            data[i] ^= (uint8_t)cryptor->sum[j];
            data[i + 1] ^= (uint8_t)(cryptor->sum[j] >> 8);
            data[i + 2] ^= (uint8_t)(cryptor->sum[j] >> 16);
            data[i + 3] ^= (uint8_t)(cryptor->sum[j] >> 24);
        }
    }

    {
        int remain = size & 3;
        if (remain != 0) {
            int result = cryptor->flag[0] & cryptor->flag[1] |
                         cryptor->flag[2] & (cryptor->flag[0] | cryptor->flag[1]);
            int j;
            cryptor->change_data = 0;
            for (j = 0; j < 3; j++) {
                if (result == cryptor->flag[j]) {
                    uint32_t t1 = cryptor->buffer[j][cryptor->pos1[j]];
                    uint32_t t2 = cryptor->buffer[j][cryptor->pos2[j]];
                    uint32_t t3 = (t1 <= t2) ? t1 : t2;
                    uint32_t sum = t1 + t2;
                    cryptor->sum[j] = sum;
                    cryptor->flag[j] = (t3 > sum) ? 1 : 0;
                    cryptor->pos1[j] = (cryptor->pos1[j] + 1) % cryptor->size[j];
                    cryptor->pos2[j] = (cryptor->pos2[j] + 1) % cryptor->size[j];
                }
                cryptor->change_data ^= cryptor->sum[j];
            }
            for (j = 0; j < remain; j++) {
                data[original - remain + j] ^= (uint8_t)(cryptor->change_data >> (j * 8));
            }
            cryptor->change_len = 4 - remain;
        }
    }
}

static void shift_key(const uint8_t *src, int n, int forward, uint8_t *dst) {
    int i;
    for (i = 0; i < 128; i++) {
        if (forward) {
            dst[(i + n) % 128] = src[i];
        } else {
            dst[i] = src[(i + n) % 128];
        }
    }
}

static void xor_key(const uint8_t *a, const uint8_t *b, uint8_t *dst) {
    int i;
    for (i = 0; i < 128; i++) {
        dst[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

TeraCrypt *tera_crypt_new(
    const uint8_t client_key1[128],
    const uint8_t client_key2[128],
    const uint8_t server_key1[128],
    const uint8_t server_key2[128]) {
    TeraCrypt *ctx = (TeraCrypt *)calloc(1, sizeof(TeraCrypt));
    uint8_t tmp1[128];
    uint8_t tmp2[128];
    uint8_t decrypt_key[128];
    uint8_t encrypt_key[128];
    if (ctx == NULL) {
        return NULL;
    }

    cryptor_init(&ctx->decrypt);
    cryptor_init(&ctx->encrypt);

    /* Client 115.02 uses the later constants 67 / 29 / 41. The 2012 set was 31 / 17 / 79. */
    shift_key(server_key1, 67, 1, tmp1);
    xor_key(tmp1, client_key1, tmp2);
    shift_key(client_key2, 29, 0, tmp1);
    xor_key(tmp1, tmp2, decrypt_key);
    cryptor_generate(&ctx->decrypt, decrypt_key);

    shift_key(server_key2, 41, 1, tmp1);
    cryptor_apply(&ctx->decrypt, tmp1, 128);
    memcpy(encrypt_key, tmp1, 128);
    cryptor_generate(&ctx->encrypt, encrypt_key);
    return ctx;
}

void tera_crypt_decrypt(TeraCrypt *ctx, uint8_t *data, size_t len) {
    if (ctx == NULL || data == NULL || len == 0 || len > 0x7fffffff) {
        return;
    }
    cryptor_apply(&ctx->decrypt, data, (int)len);
}

void tera_crypt_encrypt(TeraCrypt *ctx, uint8_t *data, size_t len) {
    if (ctx == NULL || data == NULL || len == 0 || len > 0x7fffffff) {
        return;
    }
    cryptor_apply(&ctx->encrypt, data, (int)len);
}

void tera_crypt_free(TeraCrypt *ctx) {
    free(ctx);
}
