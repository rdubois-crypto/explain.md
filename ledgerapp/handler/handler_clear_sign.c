// handler_clear_sign.c — ZK Clear Signing with NBGL review
// SPDX-License-Identifier: MIT — Copyright (c) 2025 ZKNOX

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../sw.h"
#include "os.h"
#include "buffer.h"
#include "../globals.h"
#include "handler_clear_sign.h"
#include "send_response.h"
#include "zkn_errors.h"
#include "zkn_groth16.h"

extern void ui_menu_main(void);

#ifdef HAVE_NBGL
#include "nbgl_use_case.h"
#endif

#define P2_MORE        0x80
#define MAX_TEXT_LEN   128
#define MAX_CS_PAYLOAD 2048

/* ── Global state ─────────────────────────────────────────────── */

static uint8_t  g_cs_buf[MAX_CS_PAYLOAD];
static uint16_t g_cs_len;
static char     g_cs_text[MAX_TEXT_LEN + 1];
static uint16_t g_cs_text_len;
static uint16_t g_cs_proof_offset;

/* ── Groth16 verification ─────────────────────────────────────── */

static int do_verify_groth16(void)
{
    const uint8_t *p = g_cs_buf + g_cs_proof_offset;
    uint16_t remaining = g_cs_len - g_cs_proof_offset;
    if (remaining < 1) return 0;
    uint8_t n_pub = p[0]; p++; remaining--;
    if (n_pub > ZKN_GROTH16_MAX_PUB) return 0;

    uint16_t need = 96+192+192+192 + 96*(n_pub+1) + 96+192+96 + 32*n_pub;
    if (remaining < need) return 0;

    zkn_groth16_vk_generic_t vk;
    vk.n_public = n_pub;
    memcpy(vk.alpha, p, 96); p+=96;
    memcpy(vk.beta, p, 192); p+=192;
    memcpy(vk.gamma, p, 192); p+=192;
    memcpy(vk.delta, p, 192); p+=192;
    for (int i = 0; i <= n_pub; i++) { memcpy(vk.IC[i], p, 96); p+=96; }

    zkn_groth16_proof_generic_t proof;
    memcpy(proof.A, p, 96); p+=96;
    memcpy(proof.B, p, 192); p+=192;
    memcpy(proof.C, p, 96); p+=96;

    uint8_t pub[ZKN_GROTH16_MAX_PUB][32];
    for (int i = 0; i < n_pub; i++) { memcpy(pub[i], p, 32); p+=32; }

    return zkn_groth16_verify_generic(&vk, &proof,
        (const uint8_t(*)[32])pub, n_pub, zkn_bls12381_ctx());
}

/* ── NBGL review flow ─────────────────────────────────────────── */

#ifdef HAVE_NBGL

static nbgl_layoutTagValue_t g_pair;
static nbgl_layoutTagValueList_t g_pairList;

static void on_review_result(bool confirmed)
{
    if (confirmed) {
        int result = do_verify_groth16();
        uint8_t resp[1 + MAX_TEXT_LEN];
        resp[0] = (result == 1) ? 0x01 : 0x00;
        memcpy(resp + 1, g_cs_text, g_cs_text_len);
        explicit_bzero(g_cs_buf, g_cs_len);
        g_cs_len = 0;
        io_send_response_pointer(resp, 1 + g_cs_text_len, SW_OK);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        explicit_bzero(g_cs_buf, g_cs_len);
        g_cs_len = 0;
        io_send_sw(0x6985);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

static void display_clear_sign(void)
{
    g_pair.item  = "Intent";
    g_pair.value = g_cs_text;
    g_pairList.nbPairs = 1;
    g_pairList.pairs   = &g_pair;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &g_pairList,
                       NULL,
                       "Review ZK Clear Sign",
                       NULL,
                       "Sign intent",
                       on_review_result);
}

#else
/* Fallback without NBGL: verify immediately */
static void display_clear_sign(void)
{
    int result = do_verify_groth16();
    uint8_t resp[1 + MAX_TEXT_LEN];
    resp[0] = (result == 1) ? 0x01 : 0x00;
    memcpy(resp + 1, g_cs_text, g_cs_text_len);
    explicit_bzero(g_cs_buf, g_cs_len);
    g_cs_len = 0;
    io_send_response_pointer(resp, 1 + g_cs_text_len, SW_OK);
}
#endif

/* ── APDU handler ─────────────────────────────────────────────── */

int handler_clear_sign(uint8_t p1, uint8_t p2, buffer_t *cdata)
{
    if (p1 == 0) g_cs_len = 0;

    if (g_cs_len + cdata->size > MAX_CS_PAYLOAD)
        return io_send_sw(SW_WRONG_DATA_LENGTH);

    memcpy(g_cs_buf + g_cs_len, cdata->ptr, cdata->size);
    g_cs_len += cdata->size;

    if (p2 == P2_MORE)
        return io_send_sw(SW_OK);

    if (g_cs_len < 3)
        return io_send_sw(SW_WRONG_DATA_LENGTH);

    g_cs_text_len = (g_cs_buf[0] << 8) | g_cs_buf[1];
    if (g_cs_text_len > MAX_TEXT_LEN || g_cs_text_len + 2 > g_cs_len)
        return io_send_sw(SW_WRONG_DATA_LENGTH);

    memcpy(g_cs_text, g_cs_buf + 2, g_cs_text_len);
    g_cs_text[g_cs_text_len] = '\0';
    g_cs_proof_offset = 2 + g_cs_text_len;

    display_clear_sign();
    return 0;
}
