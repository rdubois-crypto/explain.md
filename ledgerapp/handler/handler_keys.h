// handler_keys.h
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX

#ifndef HANDLER_KEYS_H
#define HANDLER_KEYS_H

#include <stdint.h>
#include "buffer.h"
#include "types.h"

// SPENDING_PUBKEY (0x01) — derive BabyJubjub public key from BIP32 path
int handler_spending_pubkey(buffer_t *cdata);

// ETHEREUM_PUBKEY (0x03) — derive Ethereum secp256k1 public key from BIP32 path
int handler_ethereum_pubkey(buffer_t *cdata);

#ifdef RAILGUN
/**
 * Handler for VIEWING_PUBKEY command.
 * Derives public key based on key_type and format from APDU data.
 *
 * @param[in,out] cdata
 *   Command data with key_type, format, and optional account index.
 *
 * @return zero or positive integer if success, negative integer otherwise.
 */
int handler_viewing_pubkey(buffer_t *cdata);

/**
 * Handler for VIEWING_PRIVKEY APDU — direct export (no UI).
 * Data: account(4 BE)
 *
 * @return 0 on success, negative on error
 */
int handler_viewing_privkey(buffer_t *cdata);

/**
 * Handler for VIEW_PRIVKEY_DISPLAY APDU.
 * Shows UI approval screen; derives and returns key after user confirms.
 * Data: account(4 BE)
 *
 * @return 0 on success, negative on error
 */
int handler_view_privkey_display(buffer_t *cdata);
#endif // RAILGUN

#endif
