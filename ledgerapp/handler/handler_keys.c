// handler_keys.c
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX
//
// APDU handlers for public and private key derivation.
//
// handler_viewing_pubkey: derives and returns public keys
// handler_viewing_privkey: DEBUG ONLY — returns derived private keys
//   ⚠️  REMOVE handler_viewing_privkey BEFORE PRODUCTION BUILD / AUDIT.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "io.h"
#include "buffer.h"

#include "handler_keys.h"
#include "globals.h"
#include "types.h"
#include "sw.h"
#include "display.h"
#include "send_response.h"

#include "zkn_errors.h"
#include "zkn_keyderivation.h"
#include "zkn_tEdwards.h"
#include "zkn_eddsa.h"

// Read uint32 big-endian from buffer
static inline uint32_t read_u32_be(const uint8_t *buf)
{
  return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
         ((uint32_t)buf[2] << 8)  |  (uint32_t)buf[3];
}

/**
 * APDU format:
 *   CLA INS P1 P2 Lc Data
 *   Data[0..3] = account index (4 bytes, big-endian)
 *
 * Response:
 *   Ed25519 public key (32 bytes, raw)
 */
int handler_viewing_pubkey(buffer_t *cdata)
{
    uint8_t derived_priv[64];
    uint8_t chain_code[32];
    uint8_t pubkey[32];
    size_t pubkey_len = 0;
    zkn_error_t error;

    if (cdata->size < 4)
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    uint32_t account = read_u32_be(cdata->ptr);

    // Derive private key
    error = derive_private_key(KEY_TYPE_VIEWING, account, derived_priv, chain_code);
    if (error != ZKN_OK)
    {
        explicit_bzero(derived_priv, sizeof(derived_priv));
        return io_send_sw(error);
    }

    // Derive public key
    error = derive_public_key(KEY_TYPE_VIEWING, PUBKEY_FORMAT_RAW, derived_priv, pubkey, &pubkey_len);

    // Clear private key immediately
    explicit_bzero(derived_priv, sizeof(derived_priv));
    explicit_bzero(chain_code, sizeof(chain_code));

    if (error != ZKN_OK)
    {
        return io_send_sw(error);
    }

    // Send response
    return io_send_response_pointer(pubkey, pubkey_len, SW_OK);
}

/**
 * APDU format:
 *   CLA INS P1 P2 Lc Data
 *   Data[0..3] = account index (4 bytes, big-endian)
 *
 * Response:
 *   BabyJubjub public key (64 bytes, x||y)
 */
int handler_spending_pubkey(buffer_t *cdata)
{
    uint8_t derived_priv[64];
    uint8_t chain_code[32];
    uint8_t pubkey[PUBKEY_BABYJUBJUB_LEN];
    size_t pubkey_len = 0;
    zkn_error_t error;

    if (cdata->size < 4)
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    uint32_t account = read_u32_be(cdata->ptr);

    // Derive private key from BIP32 path: m/44'/1984'/account'/0'/0'
    error = derive_private_key(KEY_TYPE_SPENDING, account, derived_priv, chain_code);
    if (error != ZKN_OK)
    {
        explicit_bzero(derived_priv, sizeof(derived_priv));
        return io_send_sw(error);
    }

    // Derive BabyJubjub public key
    error = derive_public_key(KEY_TYPE_SPENDING, PUBKEY_FORMAT_RAW, derived_priv, pubkey, &pubkey_len);

    // Clear private key immediately
    explicit_bzero(derived_priv, sizeof(derived_priv));
    explicit_bzero(chain_code, sizeof(chain_code));

    if (error != ZKN_OK)
    {
        return io_send_sw(error);
    }

    // Send response
    return io_send_response_pointer(pubkey, pubkey_len, SW_OK);
}

/**
 * APDU format:
 *   CLA INS P1 P2 Lc Data
 *   Data[0..3] = address index (4 bytes, big-endian)
 *
 * Response:
 *   Ethereum pubkey (65 bytes) from secp256k1 key at m/44'/60'/0'/0/address_index
 */
int handler_ethereum_pubkey(buffer_t *cdata)
{
    uint8_t derived_priv[64];
    uint8_t chain_code[32];
    uint8_t pubkey[PUBKEY_SECP256K1_UNCOMPRESSED_LEN];
    size_t pubkey_len = 0;
    zkn_error_t error;

    if (cdata->size < 4)
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    uint32_t address_index = read_u32_be(cdata->ptr);

    // Derive private key from BIP32 path: m/44'/60'/0'/0/address_index
    error = derive_private_key(KEY_TYPE_ETHEREUM, address_index, derived_priv, chain_code);
    if (error != ZKN_OK)
    {
        explicit_bzero(derived_priv, sizeof(derived_priv));
        return io_send_sw(error);
    }

    // Derive secp256k1 public key (uncompressed: 04||x||y, 65 bytes)
    error = derive_public_key(KEY_TYPE_ETHEREUM, PUBKEY_FORMAT_UNCOMPRESSED, derived_priv, pubkey, &pubkey_len);

    // Clear private key immediately
    explicit_bzero(derived_priv, sizeof(derived_priv));
    explicit_bzero(chain_code, sizeof(chain_code));

    if (error != ZKN_OK)
    {
        return io_send_sw(error);
    }

    // Send response
    return io_send_response_pointer(pubkey, pubkey_len, SW_OK);
}

// VIEWING_PRIVKEY (INS=0x11) — direct export of viewing private key (no UI).
// Data: account(4 BE)

int handler_viewing_privkey(buffer_t *cdata)
{
    uint8_t derived_key[64];
    uint8_t chain_code[32];
    zkn_error_t error;

    if (cdata->size < 4)
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    uint32_t account = read_u32_be(cdata->ptr);

    error = derive_private_key(KEY_TYPE_VIEWING, account, derived_key, chain_code);
    if (error != ZKN_OK)
    {
        explicit_bzero(derived_key, sizeof(derived_key));
        explicit_bzero(chain_code, sizeof(chain_code));
        return io_send_sw(SW_SIGNATURE_FAIL);
    }

    int ret = io_send_response_pointer(derived_key, 32, SW_OK);

    explicit_bzero(derived_key, sizeof(derived_key));
    explicit_bzero(chain_code, sizeof(chain_code));

    return ret;
}

// VIEW_PRIVKEY_DISPLAY (INS=0x13) — export viewing key with UI approval.
// Data: account(4 BE)

int handler_view_privkey_display(buffer_t *cdata)
{
    if (cdata->size < 4)
        return io_send_sw(SW_WRONG_DATA_LENGTH);

    explicit_bzero(&G_context, sizeof(G_context));
    G_context.state = STATE_NONE;

    G_context.bip32_path[0] = read_u32_be(cdata->ptr);
    G_context.state = STATE_PARSED;

    return ui_display_viewing_privkey();
}
