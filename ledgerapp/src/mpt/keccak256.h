/**
 * keccak256.h - minimal standalone Keccak-256
 * Source: public domain (https://github.com/brainhub/SHA3IUF)
 * Adapté pour usage standalone sans dépendances.
 *
 * En production Nano : remplacer par cx_keccak_256_hash() BOLOS SDK.
 */
#pragma once
#include <stdint.h>
#include <string.h>

#define KECCAK256_RATE  136   /* (1600 - 256*2) / 8 */
#define KECCAK256_DLEN  32

typedef struct {
    uint64_t state[25];
    uint8_t  buf[KECCAK256_RATE];
    uint32_t buf_len;
} keccak256_ctx_t;

static const uint64_t _keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const int _keccak_ro[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44,
};

static const int _keccak_pi[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1,
};

static inline uint64_t _rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static void _keccak_f(uint64_t s[25]) {
    for (int r = 0; r < 24; r++) {
        uint64_t bc[5], t;
        for (int i = 0; i < 5; i++)
            bc[i] = s[i] ^ s[i+5] ^ s[i+10] ^ s[i+15] ^ s[i+20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i+4)%5] ^ _rotl64(bc[(i+1)%5], 1);
            for (int j = 0; j < 25; j += 5) s[j+i] ^= t;
        }
        t = s[1];
        for (int i = 0; i < 24; i++) {
            int pi = _keccak_pi[i];
            uint64_t tmp = s[pi];
            s[pi] = _rotl64(t, _keccak_ro[i]);
            t = tmp;
        }
        for (int j = 0; j < 25; j += 5) {
            uint64_t b[5];
            for (int i = 0; i < 5; i++) b[i] = s[j+i];
            for (int i = 0; i < 5; i++)
                s[j+i] ^= (~b[(i+1)%5]) & b[(i+2)%5];
        }
        s[0] ^= _keccak_rc[r];
    }
}

static inline void keccak256_init(keccak256_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

static void keccak256_update(keccak256_ctx_t *ctx,
                             const uint8_t *data, uint32_t len) {
    while (len > 0) {
        uint32_t avail = KECCAK256_RATE - ctx->buf_len;
        uint32_t take  = len < avail ? len : avail;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take; len -= take;
        if (ctx->buf_len == KECCAK256_RATE) {
            for (int i = 0; i < KECCAK256_RATE/8; i++) {
                uint64_t w;
                memcpy(&w, ctx->buf + i*8, 8);
                ctx->state[i] ^= w;
            }
            _keccak_f(ctx->state);
            ctx->buf_len = 0;
        }
    }
}

static void keccak256_final(keccak256_ctx_t *ctx, uint8_t out[32]) {
    /* Padding Keccak (pas SHA3 : 0x01, pas 0x06) */
    ctx->buf[ctx->buf_len++] = 0x01;
    memset(ctx->buf + ctx->buf_len, 0, KECCAK256_RATE - ctx->buf_len);
    ctx->buf[KECCAK256_RATE - 1] |= 0x80;
    for (int i = 0; i < KECCAK256_RATE/8; i++) {
        uint64_t w;
        memcpy(&w, ctx->buf + i*8, 8);
        ctx->state[i] ^= w;
    }
    _keccak_f(ctx->state);
    for (int i = 0; i < 4; i++) {
        uint64_t w = ctx->state[i];
        /* little-endian */
        out[i*8+0] = (w >>  0) & 0xFF;
        out[i*8+1] = (w >>  8) & 0xFF;
        out[i*8+2] = (w >> 16) & 0xFF;
        out[i*8+3] = (w >> 24) & 0xFF;
        out[i*8+4] = (w >> 32) & 0xFF;
        out[i*8+5] = (w >> 40) & 0xFF;
        out[i*8+6] = (w >> 48) & 0xFF;
        out[i*8+7] = (w >> 56) & 0xFF;
    }
}
