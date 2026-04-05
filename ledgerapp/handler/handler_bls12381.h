// handler_bls12381.h
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX

#ifndef _HANDLER_BLS12381_H
#define _HANDLER_BLS12381_H

#include "buffer.h"

// GROTH16_VERIFY (0x60) — BLS12-381 Groth16 proof verification (chunked)
int handler_groth16_verify(uint8_t p1, uint8_t p2, buffer_t *cdata);

// PLONK_VERIFY (0x61) — BLS12-381 PLONK proof verification (chunked)
int handler_plonk_verify(uint8_t p1, uint8_t p2, buffer_t *cdata);

// PAIRING_TEST (0x62) — BLS12-381 pairing engine self-test (no input)
int handler_pairing_test(void);

#endif
