// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX @+
//
// handler_blake512.c — APDU handler for BLAKE-512 original hash
//
// This handler exposes the pure-C BLAKE-512 (SHA-3 candidate) implementation
// via APDU INS=0x23. The existing BLAKE512_HASH (INS=0x08) uses the Ledger SDK's
// cx_blake2b which is BLAKE2b-512 — a different algorithm.
//
// This file is meant to be compiled alongside zkn_magicbox.c (add to Makefile SRC).

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../sw.h"
#include "os.h"
#include "cx.h"
#include "buffer.h"

#include "../globals.h"
#include "zkn_errors.h"
#include "zkn_blake512.h"
#include "zkn_tEdwards.h"
#include "zkn_eddsa.h"
#include "handler_blake512.h"

#include "send_response.h"

// APDU handler: BLAKE2b-512 (Ledger SDK cx_blake2b)
//
// reference sequence:0x01f2be6b2d4b290013a2e019885e0ec718dbd3d8ff68541e4d34f1727b1bb540
// expected: 0x480d65fda15f575e6740c9522bceb1ae96670c169becad5acb1c2599f07e8100
//             c80d65fda15f575e6740c9522bceb1ae96670c169becad5acb1c2599f07e8103
// e00800002001f2be6b2d4b290013a2e019885e0ec718dbd3d8ff68541e4d34f1727b1bb540
// for length=32 return the reverse troncated output as expected by ecdsa
int handler_blake512(buffer_t *cdata)
{
  uint8_t out[64];
  ZKN_ERROR_INIT();

  cx_blake2b_t state;

  if (cdata->size != 32)
  {

    // ZKN_CHECK(cx_blake2b_512_hash(cdata->ptr,  cdata->size, out));

    ZKN_CHECK(cx_hash_init_ex((cx_hash_t *)&state, CX_BLAKE2B, 64));         // init for a 64 bytes size output
    ZKN_CHECK(cx_hash_update((cx_hash_t *)&state, cdata->ptr, cdata->size)); // update with APDU payload
    ZKN_CHECK(cx_hash_final((cx_hash_t *)&state, out));                      // obtain blake512(payload) with 32 output bytes

    io_send_response_pointer(out, sizeof(out), SW_OK);
  }
  else
  {
    ZKN_CHECK(zkn_prv_hash(cdata->ptr, out, 32));
    io_send_response_pointer(out, 64, SW_OK);
  }

  ZKN_ERROR_CLOSE_SEND();
}

// APDU handler: BLAKE-512 original (circomlib / eddsa-babyjubjub)
//
// Input:  arbitrary-length data in APDU payload
// Output: 64-byte BLAKE-512 digest
//
// Test vector (from npm 'blake-hash'):
//   blake512("abc") = a...  (64 bytes)
//
// Note: unlike handler_blake512 which has a special 32-byte path
// for zkn_prv_hash, this handler always performs a straightforward hash.

int handler_blake512_original(buffer_t *cdata)
{
    uint8_t out[ZKN_BLAKE512_DIGEST_SIZE];
    ZKN_ERROR_INIT();

    ZKN_CHECK(zkn_blake512(cdata->ptr, cdata->size, out));

    io_send_response_pointer(out, ZKN_BLAKE512_DIGEST_SIZE, SW_OK);

    // Wipe output buffer (defense-in-depth, hash may be used on key material)
    explicit_bzero(out, sizeof(out));

    ZKN_ERROR_CLOSE_SEND();
}
