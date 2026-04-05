// handler_bls12381.c
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX
//
// APDU handlers for BLS12-381 pairing-based verification:
//   0x60 — GROTH16_VERIFY  (chunked, 448 bytes)
//   0x61 — PLONK_VERIFY    (chunked, ~2146 bytes)
//   0x62 — PAIRING_TEST    (self-test, no input)

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../sw.h"
#include "os.h"
#include "buffer.h"
#include "../globals.h"
#include "handler_bls12381.h"
#include "send_response.h"
#include "zkn_errors.h"

#include "zkn_groth16.h"
#include "zkn_plonk.h"
#include "zkn_pairing_384.h"
#include "zkn_miller.h"
#include "zkn_final_exp_384.h"
#include "zkn_g1_384.h"
#include "zkn_g2_384.h"
#include "zkn_fp12_384.h"

#define P2_MORE  0x80
#define P2_LAST  0x00
#define MAX_PAYLOAD  2560

static uint8_t  g_payload[MAX_PAYLOAD];
static uint16_t g_payload_len;

/* ── GROTH16_VERIFY (0x60) ──────────────────────────────────────────── */

int handler_groth16_verify(uint8_t p1, uint8_t p2, buffer_t *cdata)
{
    ZKN_ERROR_INIT();

    if (p1 == 0) g_payload_len = 0;

    if (g_payload_len + cdata->size > MAX_PAYLOAD)
        return io_send_sw(SW_WRONG_DATA_LENGTH);

    memcpy(g_payload + g_payload_len, cdata->ptr, cdata->size);
    g_payload_len += cdata->size;

    if (p2 == P2_MORE) return io_send_sw(SW_OK);

    if (g_payload_len != ZKN_GROTH16_PROOF_LEN) {
        g_payload_len = 0;
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();
    int result = zkn_groth16_verify(g_payload, ctx);

    explicit_bzero(g_payload, g_payload_len);
    g_payload_len = 0;

    uint8_t out = (result == 1) ? 0x01 : 0x00;
    io_send_response_pointer(&out, 1, SW_OK);
    ZKN_ERROR_CLOSE_SEND();
}

/* ── PLONK_VERIFY (0x61) ────────────────────────────────────────────── */

int handler_plonk_verify(uint8_t p1, uint8_t p2, buffer_t *cdata)
{
    ZKN_ERROR_INIT();

    if (p1 == 0) g_payload_len = 0;

    if (g_payload_len + cdata->size > MAX_PAYLOAD)
        return io_send_sw(SW_WRONG_DATA_LENGTH);

    memcpy(g_payload + g_payload_len, cdata->ptr, cdata->size);
    g_payload_len += cdata->size;

    if (p2 == P2_MORE) return io_send_sw(SW_OK);

    if (g_payload_len < 2) {
        g_payload_len = 0;
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    const uint8_t *p = g_payload;
    uint8_t power = p[0], n_pub = p[1];
    p += 2;

    if (power > 28 || n_pub > ZKN_PLONK_MAX_PUB) {
        g_payload_len = 0;
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    uint16_t expected = 2 + 3*32 + 8*96 + 192 + 9*96 + 6*32 + n_pub*32;
    if (g_payload_len != expected) {
        g_payload_len = 0;
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    zkn_plonk_vk_t vk;
    vk.power = power; vk.n_public = n_pub;
    memcpy(vk.w, p, 32); p+=32; memcpy(vk.k1, p, 32); p+=32; memcpy(vk.k2, p, 32); p+=32;
    memcpy(vk.Qm,p,96);p+=96; memcpy(vk.Ql,p,96);p+=96; memcpy(vk.Qr,p,96);p+=96;
    memcpy(vk.Qo,p,96);p+=96; memcpy(vk.Qc,p,96);p+=96;
    memcpy(vk.S1,p,96);p+=96; memcpy(vk.S2,p,96);p+=96; memcpy(vk.S3,p,96);p+=96;
    memcpy(vk.X2,p,192);p+=192;

    zkn_plonk_proof_t proof;
    memcpy(proof.A,p,96);p+=96; memcpy(proof.B,p,96);p+=96; memcpy(proof.C,p,96);p+=96;
    memcpy(proof.Z,p,96);p+=96; memcpy(proof.T1,p,96);p+=96; memcpy(proof.T2,p,96);p+=96;
    memcpy(proof.T3,p,96);p+=96; memcpy(proof.Wxi,p,96);p+=96; memcpy(proof.Wxiw,p,96);p+=96;
    memcpy(proof.eval_a,p,32);p+=32; memcpy(proof.eval_b,p,32);p+=32;
    memcpy(proof.eval_c,p,32);p+=32; memcpy(proof.eval_s1,p,32);p+=32;
    memcpy(proof.eval_s2,p,32);p+=32; memcpy(proof.eval_zw,p,32);p+=32;

    uint8_t pub[ZKN_PLONK_MAX_PUB][ZKN_PLONK_FR_BYTES];
    for (int i = 0; i < n_pub; i++) { memcpy(pub[i], p, 32); p += 32; }

    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();
    int result = zkn_plonk_verify(&vk, &proof,
        (const uint8_t (*)[ZKN_PLONK_FR_BYTES])pub, n_pub, ctx);

    explicit_bzero(g_payload, g_payload_len);
    g_payload_len = 0;

    uint8_t out = (result == 1) ? 0x01 : 0x00;
    io_send_response_pointer(&out, 1, SW_OK);
    ZKN_ERROR_CLOSE_SEND();
}

/* ── PAIRING_TEST (0x62) ────────────────────────────────────────────── */

int handler_pairing_test(void)
{
    ZKN_ERROR_INIT();
    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();

    zkn_g1_384_t G1; zkn_g1_384_generator(&G1, ctx);
    zkn_g2_384_t G2; zkn_g2_384_generator(&G2, ctx);
    zkn_fp12_384_t one; zkn_fp12_384_one(&one, ctx);

    /* e(G1, G2) != 1 */
    zkn_fp12_384_t e1;
    zkn_miller_loop(&e1, &G1, &G2, ctx);
    zkn_final_exp(&e1, &e1, ctx);
    if (zkn_fp12_384_eq(&e1, &one)) {
        uint8_t out = 0x00;
        io_send_response_pointer(&out, 1, SW_OK);
        goto end;
    }

    /* e(2*G1, G2) == e(G1, 2*G2) */
    zkn_g1_384_t G1_2; zkn_g1_384_dbl(&G1_2, &G1, ctx);
    zkn_g2_384_t G2_2; zkn_g2_384_dbl(&G2_2, &G2, ctx);
    zkn_fp12_384_t e2, e3;
    zkn_miller_loop(&e2, &G1_2, &G2, ctx); zkn_final_exp(&e2, &e2, ctx);
    zkn_miller_loop(&e3, &G1, &G2_2, ctx); zkn_final_exp(&e3, &e3, ctx);

    {
        uint8_t out = zkn_fp12_384_eq(&e2, &e3) ? 0x01 : 0x00;
        io_send_response_pointer(&out, 1, SW_OK);
    }
    ZKN_ERROR_CLOSE_SEND();
}
