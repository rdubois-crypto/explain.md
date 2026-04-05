// handler_poseidon.c
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX
//
// Poseidon-5 hash APDU handler.
// Takes 5 × 32-byte inputs from the APDU data and returns the requested
// Poseidon state element after permutation.
//
// APDU format:
//   CLA=E0  INS=09  P1=index  P2=00  Lc=A0  Data[160]
//   P1             = state index to return (0..5)
//   Data[0..31]    = input 0  (32 bytes, big-endian)
//   Data[32..63]   = input 1
//   Data[64..95]   = input 2
//   Data[96..127]  = input 3
//   Data[128..159] = input 4
//
// Response: 32 bytes — Poseidon state[index] (de-montgomerized, big-endian)

#include <stdint.h>
#include <stddef.h>

#include "../sw.h"
#include "os.h"
#include "cx.h"
#include "buffer.h"

#include "../globals.h"
#include "zkn_errors.h"
#include "zkn_poseidon_constants.h"
#include "zkn_poseidon_soft.h"
#include "handler_poseidon.h"

#include "send_response.h"

#ifdef ZKNOX
// BabyJubjub field prime
static const uint8_t bbjj_prime[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01};
int handler_poseidon(uint8_t index, buffer_t *cdata)
{
  ZKN_ERROR_INIT();

  if (index > 5)
  {
    return io_send_sw(SW_WRONG_P1P2);
  }

  // Validate: 5 × 32 bytes = 160 bytes minimum
  if (cdata->size < 160)
  {
    return io_send_sw(SW_WRONG_DATA_LENGTH);
  }

  const uint8_t *input = cdata->ptr;

  ZKN_CHECK(cx_bn_lock(32, 0));

  uint8_t out[32];
  poseidon_ctx_t Ctx;
  cx_bn_mont_ctx_t montctx;
  cx_bn_t modulus;
  cx_bn_t temp;

  ZKN_CHECK(cx_bn_alloc_init(&modulus, 32, bbjj_prime, 32));
  ZKN_CHECK(cx_bn_alloc_init(&temp, 32, bbjj_prime, 32));

  ZKN_CHECK(cx_mont_alloc(&montctx, 32));
  ZKN_CHECK(cx_mont_init(&montctx, modulus));

  ZKN_CHECK(Poseidon_alloc_init(&Ctx, 5, 5, &montctx));

  // Load 5 inputs from APDU payload (each 32 bytes, big-endian)
  for (size_t i = 0; i < 5; i++)
  {
    ZKN_CHECK(cx_bn_init(Ctx.state[i + 1], input + 32 * i, 32));
    ZKN_CHECK(cx_mont_to_montgomery(Ctx.state[i + 1], Ctx.state[i + 1], Ctx.mont));
  }

  Poseidon(&Ctx, 0, &temp, 1);

  // De-montgomerize and export requested state element
  ZKN_CHECK(cx_mont_from_montgomery(Ctx.state[index], Ctx.state[index], Ctx.mont));
  ZKN_CHECK(cx_bn_export(Ctx.state[index], out, 32));

  io_send_response_pointer(out, 32, SW_OK);

  ZKN_CHECK(cx_bn_destroy(&temp));
  ZKN_CHECK(cx_bn_unlock());
  ZKN_ERROR_CLOSE_SEND();
}
#endif // ZKNOX

#ifdef ZKNOX
// generate the i+1-th poseidon5 constant, ex: e00d00000101 = second constant
int handler_poseidon_get_constante(buffer_t *cdata)
{
  ZKN_ERROR_INIT();
  ZKN_CHECK(cx_bn_lock(32, 0));

  uint64_t out[4] = {1, 2, 3, 4};

  poseidon_ctx_t Ctx;
  cx_bn_mont_ctx_t montctx;
  cx_bn_t modulus;

  ZKN_CHECK(cx_bn_alloc_init(&modulus, 32, bbjj_prime, 32));

  ZKN_CHECK(cx_mont_alloc(&montctx, 32)); // allocate Montgomery context
  ZKN_CHECK(cx_mont_init(&montctx, modulus));

  ZKN_CHECK(Poseidon_alloc_init(&Ctx, 5, 5, &montctx));

  size_t nconstant = (size_t)cdata->ptr[0];
  for (size_t i = 0; i < nconstant; i++)
  {
    Poseidon_getNext_RC(&Ctx, out);
  }

  io_send_response_pointer((uint8_t *)out, 32, SW_OK);

  ZKN_CHECK(cx_bn_unlock());
  ZKN_ERROR_CLOSE_SEND(); // return sw error if any, or 0 if execution OK
}
#endif

#if defined(ZKNOX) && defined(RAILGUN)
// ── Poseidon-5 software Montgomery variant (no cx_bn) ──────────────
//
// Mirrors handler_poseidon (INS 0x42) but uses the zkn_mont256 / zkn_bn
// library instead of the Ledger SDK cx_bn pool.  This allows running Poseidon
// without locking the BN context and serves as a cross-validation reference.
//
// APDU format:
//   CLA=E0  INS=0x44  P1=index  P2=00  Lc=A0  Data[160]

int handler_poseidon_soft(uint8_t index, buffer_t *cdata)
{
    if (index > 5) {
        return io_send_sw(SW_WRONG_P1P2);
    }

    if (cdata->size < 160) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    const uint8_t *input = cdata->ptr;

    zkn_bn_mont_ctx_t montctx;
    zkn_bn_t modulus;

    int rc;

    rc = zkn_bn_alloc_init(&modulus, 32, bbjj_prime, 32);
    if (rc != ZKN_OK) return io_send_sw(SW_SIGNATURE_FAIL);

    rc = zkn_mont_alloc(&montctx, 32);
    if (rc != ZKN_OK) return io_send_sw(SW_SIGNATURE_FAIL);

    rc = zkn_mont_init(&montctx, modulus);
    if (rc != ZKN_OK) return io_send_sw(SW_SIGNATURE_FAIL);

    poseidon_soft_ctx_t ctx;

    rc = zkn_poseidon_init(&ctx, 5, 5, &montctx);
    if (rc != ZKN_OK) return io_send_sw(SW_SIGNATURE_FAIL);

    for (size_t i = 0; i < 5; i++) {
        rc = zkn_bn_init(ctx.state[i + 1], input + 32 * i, 32);
        if (rc != ZKN_OK) return io_send_sw(SW_SIGNATURE_FAIL);

        rc = zkn_mont_to_montgomery(ctx.state[i + 1], ctx.state[i + 1], &montctx);
        if (rc != ZKN_OK) return io_send_sw(SW_SIGNATURE_FAIL);
    }

    zkn_bn_t temp_out;
    rc = zkn_poseidon(&ctx, 0, &temp_out, 1);
    if (rc != ZKN_OK) return io_send_sw(SW_SIGNATURE_FAIL);

    rc = zkn_mont_from_montgomery(ctx.state[index], ctx.state[index], &montctx);
    if (rc != ZKN_OK) return io_send_sw(SW_SIGNATURE_FAIL);

    uint8_t out[32];
    rc = zkn_bn_export(ctx.state[index], out, 32);
    if (rc != ZKN_OK) return io_send_sw(SW_SIGNATURE_FAIL);

    return io_send_response_pointer(out, 32, SW_OK);
}
#endif // ZKNOX && RAILGUN
