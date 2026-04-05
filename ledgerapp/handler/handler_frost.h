// handler_frost.h
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX
//
// FROST threshold signature protocol APDU handlers.

#ifndef _HANDLER_FROST_H
#define _HANDLER_FROST_H

#include <stdint.h>
#include "buffer.h"

// FROST_PARTIAL_SIG (0x20) — test partial signature computation
int handler_frost_partial_sig(buffer_t *cdata);

// FROST_INTERPOLATE (0x21) — polynomial interpolation
int handler_frost_interpolate(buffer_t *cdata);

// FROST_SPLIT (0x22) — secret splitting
int handler_frost_split(buffer_t *cdata);

// FROST_HASH (0x23) — FROST hash (H1..H5)
int handler_frost_hash(buffer_t *cdata);

// FROST_GROUP_COMMIT (0x24) — group commitment
int handler_frost_group_commit(buffer_t *cdata);

// FROST_BINDING_FACTOR (0x25) — binding factors
int handler_frost_binding_factor(buffer_t *cdata);

// FROST_INJECT (0x26) — inject FROST key material
int handler_frost_inject(buffer_t *cdata);

// FROST_COMMIT (0x27) — FROST commit (generate nonce commitments)
int handler_frost_commit(buffer_t *cdata);

// FROST_INJECT_COM1 (0x28) — inject commitments part 1
int handler_frost_inject_com1(buffer_t *cdata);

// FROST_INJECT_COM2 (0x29) — inject commitments part 2
int handler_frost_inject_com2(buffer_t *cdata);

// FROST_PARTIAL_SIGN (0x2A) — FROST partial sign (using stored state)
int handler_frost_partial_sign(buffer_t *cdata);

// FROST_RESET (0x2B) — reset FROST state
int handler_frost_reset(void);

// FROST_STATUS (0x2C) — return FROST status
int handler_frost_status(void);

// FROST_INJECT_NONCES (0x2D) — inject nonces for testing
int handler_frost_inject_nonces(buffer_t *cdata);

// FROST_ENCODE_TEST (0x2E) — encode commitment test
int handler_frost_encode_test(buffer_t *cdata);

#endif
