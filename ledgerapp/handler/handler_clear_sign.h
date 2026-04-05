// handler_clear_sign.h
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX
#ifndef _HANDLER_CLEAR_SIGN_H
#define _HANDLER_CLEAR_SIGN_H

#include "buffer.h"

// CLEAR_SIGN (0x63) — ZK clear signing: display text + verify Groth16
int handler_clear_sign(uint8_t p1, uint8_t p2, buffer_t *cdata);

#endif
