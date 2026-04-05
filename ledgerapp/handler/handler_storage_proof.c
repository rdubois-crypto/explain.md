// handler_storage_proof.c — MPT storage proof verification (2-slot long string)
// SPDX-License-Identifier: MIT — Copyright (c) 2025 ZKNOX
//
// INS=0x64, chunked:
//   storageHash(32) | nProofs(1) |
//     slot_0(32) | nNodes_0(1) | [nodeLen(2 BE) | nodeData]... |
//     slot_1(32) | nNodes_1(1) | [nodeLen(2 BE) | nodeData]... |
//   expectedHash(32)
//
// Verifies 2 MPT storage proofs (long string across 2 slots),
// reconstructs the 64-char hex string, converts to 32-byte hash,
// and compares with expectedHash.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../sw.h"
#include "os.h"
#include "buffer.h"
#include "../globals.h"
#include "handler_storage_proof.h"
#include "send_response.h"

#include "../zknox/mpt/storage_proof.h"

#ifdef HAVE_NBGL
#include "nbgl_use_case.h"
#endif

extern void ui_menu_main(void);

#define P2_MORE        0x80
#define MAX_SPF_PAYLOAD 8192
#define MAX_PROOF_NODES 20

static uint8_t  g_spf_buf[MAX_SPF_PAYLOAD];
static uint16_t g_spf_len;

/* ── Hex char to nibble ───────────────────────────────────────── */

static int hex_nibble(uint8_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ── Parse one proof from buffer, advance pointer ─────────────── */

static int parse_and_verify_one(
    const uint8_t *storage_hash,
    const uint8_t **pp, uint16_t *remaining,
    uint8_t value_out[32])
{
    const uint8_t *p = *pp;
    uint16_t rem = *remaining;

    if (rem < 33) return 0; /* slot(32) + nNodes(1) */
    const uint8_t *slot = p; p += 32; rem -= 32;
    uint8_t n_nodes = *p; p++; rem--;

    if (n_nodes == 0 || n_nodes > MAX_PROOF_NODES) return 0;

    const uint8_t *proof_nodes[MAX_PROOF_NODES];
    uint32_t       proof_lens[MAX_PROOF_NODES];

    for (uint8_t i = 0; i < n_nodes; i++) {
        if (rem < 2) return 0;
        uint16_t nlen = (p[0] << 8) | p[1];
        p += 2; rem -= 2;
        if (rem < nlen) return 0;
        proof_nodes[i] = p;
        proof_lens[i] = nlen;
        p += nlen; rem -= nlen;
    }

    *pp = p;
    *remaining = rem;

    return (spf_verify(storage_hash, slot,
                       proof_nodes, proof_lens, n_nodes,
                       value_out) == SPF_OK) ? 1 : 0;
}

/* ── Verify full payload ──────────────────────────────────────── */

static int do_verify(uint8_t *extracted_hash)
{
    const uint8_t *p = g_spf_buf;
    uint16_t rem = g_spf_len;

    if (rem < 33) return 0; /* storageHash(32) + nProofs(1) */
    const uint8_t *storage_hash = p; p += 32; rem -= 32;
    uint8_t n_proofs = *p; p++; rem--;

    if (n_proofs != 2) return 0; /* expect exactly 2 for long string */

    /* Verify both MPT proofs */
    uint8_t val0[32], val1[32];
    if (!parse_and_verify_one(storage_hash, &p, &rem, val0)) return 0;
    if (!parse_and_verify_one(storage_hash, &p, &rem, val1)) return 0;

    /* expectedHash (32 bytes) at the end */
    if (rem < 32) return 0;
    const uint8_t *expected = p;

    /* Reconstruct: val0(32) + val1(32) = 64 ASCII hex chars → 32 bytes */
    uint8_t hex_chars[64];
    memcpy(hex_chars,      val0, 32);
    memcpy(hex_chars + 32, val1, 32);

    uint8_t reconstructed[32];
    for (int i = 0; i < 32; i++) {
        int hi = hex_nibble(hex_chars[2 * i]);
        int lo = hex_nibble(hex_chars[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        reconstructed[i] = (uint8_t)((hi << 4) | lo);
    }

    memcpy(extracted_hash, reconstructed, 32);
    return (memcmp(reconstructed, expected, 32) == 0) ? 1 : 0;
}

/* ── NBGL display ─────────────────────────────────────────────── */

#ifdef HAVE_NBGL
static uint8_t g_spf_result;
static uint8_t g_spf_extracted[32];

static void spf_send_result(void)
{
    uint8_t resp[1 + 32];
    resp[0] = g_spf_result;
    memcpy(resp + 1, g_spf_extracted, 32);
    explicit_bzero(g_spf_buf, g_spf_len);
    g_spf_len = 0;
    io_send_response_pointer(resp, 33, SW_OK);
}

static void on_spf_review(bool confirmed)
{
    if (confirmed) {
        spf_send_result();
        nbgl_useCaseReviewStatus(
            g_spf_result ? STATUS_TYPE_TRANSACTION_SIGNED
                         : STATUS_TYPE_TRANSACTION_REJECTED,
            ui_menu_main);
    } else {
        explicit_bzero(g_spf_buf, g_spf_len);
        g_spf_len = 0;
        io_send_sw(0x6985);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED,
                                 ui_menu_main);
    }
}

static void display_spf_result(void)
{
    nbgl_useCaseChoice(NULL,
        g_spf_result ? "VK Hash Verified" : "VK Hash Mismatch",
        g_spf_result ? "Storage proof valid" : "Proof or hash invalid",
        "Continue", "Reject",
        on_spf_review);
}
#endif

/* ── APDU handler ─────────────────────────────────────────────── */

int handler_storage_proof(uint8_t p1, uint8_t p2, buffer_t *cdata)
{
    if (p1 == 0) g_spf_len = 0;

    if (g_spf_len + cdata->size > MAX_SPF_PAYLOAD)
        return io_send_sw(SW_WRONG_DATA_LENGTH);

    memcpy(g_spf_buf + g_spf_len, cdata->ptr, cdata->size);
    g_spf_len += cdata->size;

    if (p2 == P2_MORE)
        return io_send_sw(SW_OK);

#ifdef HAVE_NBGL
    g_spf_result = do_verify(g_spf_extracted) ? 0x01 : 0x00;
    display_spf_result();
    return 0;
#else
    uint8_t extracted[32];
    int result = do_verify(extracted);
    uint8_t resp[1 + 32];
    resp[0] = result ? 0x01 : 0x00;
    memcpy(resp + 1, extracted, 32);
    explicit_bzero(g_spf_buf, g_spf_len);
    g_spf_len = 0;
    io_send_response_pointer(resp, 33, SW_OK);
    return 0;
#endif
}
