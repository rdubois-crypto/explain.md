// handler_sign.h
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX
//
// EdDSA-Poseidon sign APDU handlers.

#ifndef _HANDLER_SIGN_H
#define _HANDLER_SIGN_H

#include <stdint.h>
#include "buffer.h"
#include "../constants.h"

// SIGN (0x02) — EdDSA-Poseidon sign from BIP32 path (account + msg)
int handler_sign(buffer_t *cdata);

#ifdef ZKNOX
// SIGN_WITH_PRIVKEY (0x50) — EdDSA-Poseidon sign with raw privkey (curveID + prv + msg)
int handler_sign_with_privkey(buffer_t *cdata);
#endif

#ifdef RAILGUN
// SIGN_DISPLAY (0x12) — EdDSA-Poseidon blind-sign with UI approval
int handler_sign_display(buffer_t *cdata);
// Helper: called by validate after user approval for blind-sign
int handler_eddsa_poseidon_sign_stored(void);
#endif

#endif
