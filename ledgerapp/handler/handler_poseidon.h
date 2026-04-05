// handler_poseidon.h
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX

#ifndef _HANDLER_POSEIDON_H
#define _HANDLER_POSEIDON_H

#include <stdint.h>
#include "buffer.h"
#include "../constants.h"

#ifdef ZKNOX
/**
 * Poseidon-5 hash handler.
 *
 * APDU format:
 *   CLA=E0  INS=0x42  P1=index  P2=00  Lc=A0  Data[160]
 *   P1             = state index to return (0..5)
 *   Data[0..31]    = input 0  (32 bytes, big-endian)
 *   Data[32..63]   = input 1
 *   Data[64..95]   = input 2
 *   Data[96..127]  = input 3
 *   Data[128..159] = input 4
 *
 * Response: 32 bytes — Poseidon state[index] (de-montgomerized, big-endian)
 */
int handler_poseidon(uint8_t index, buffer_t *cdata);
#endif // ZKNOX

#ifdef ZKNOX
// POSEIDON_GET_CONSTANTE (0x2E) — get i-th Poseidon5 round constant
int handler_poseidon_get_constante(buffer_t *cdata);
#endif

#if defined(ZKNOX) && defined(RAILGUN)
/**
 * Poseidon-5 hash handler — pure software Montgomery (zkn_bn, no cx_bn).
 * APDU: CLA=E0  INS=0x44  P1=index  P2=00  Lc=A0  Data[160]
 */
int handler_poseidon_soft(uint8_t index, buffer_t *cdata);
#endif

#endif
