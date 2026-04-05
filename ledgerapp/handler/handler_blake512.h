// handler_blake512.h
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX

#ifndef _HANDLER_BLAKE512_H
#define _HANDLER_BLAKE512_H

#include "buffer.h"

// BLAKE512 (0x04) — BLAKE2b-512 hash (Ledger SDK cx_blake2b)
int handler_blake512(buffer_t *cdata);

// BLAKE512_ORIGINAL (0x05) — BLAKE-512 original (circomlib eddsa-babyjubjub)
int handler_blake512_original(buffer_t *cdata);

#endif
