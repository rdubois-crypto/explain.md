// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX
//
// EdDSA-Poseidon sign APDU handlers.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../sw.h"
#include "os.h"
#include "cx.h"
#include "buffer.h"

#include "../globals.h"
#include "../ui/display.h"

#include "zkn_errors.h"
#include "zkn_tEdwards.h"
#include "zkn_eddsa.h"
#include "handler_sign.h"

#include "send_response.h"
#include "crypto_helpers.h"
#include "zkn_keyderivation.h"

// Read uint32 big-endian from buffer
static inline uint32_t read_u32_be(const uint8_t *buf)
{
  return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
         ((uint32_t)buf[2] << 8)  |  (uint32_t)buf[3];
}

// Helper called from validate_eddsa_poseidon_sign() after user approval.
// Derives privkey from account stored in raw_tx[0..3], signs msg at raw_tx+4,
// and stores the 96-byte result in G_context.tx_info.signature.
int handler_eddsa_poseidon_sign_stored(void)
{
  ZKN_ERROR_INIT();

  uint32_t account = read_u32_be(G_context.tx_info.raw_tx);
  uint8_t derived_priv[64];
  uint8_t chain_code[32];

  error = derive_private_key(KEY_TYPE_SPENDING, account, derived_priv, chain_code);
  if (error != ZKN_OK) {
    explicit_bzero(derived_priv, sizeof(derived_priv));
    return error;
  }

  ZKN_CHECK(cx_bn_lock(32, 0));

  zkn_edcurve_t curve;
  zkn_edpoint_t Kpub;
  uint32_t curveID = _BABYJUJUB_ID;

  ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, curveID));
  ZKN_CHECK(tEdwards_alloc(&curve, &Kpub));
  ZKN_CHECK(zkn_prv2pub(&curve, derived_priv, &Kpub));
  // msg lives at raw_tx+4; signature buffer is exactly 96 bytes (R8x|R8y|S)
  ZKN_CHECK(EddsaPoseidon_Sign_final(&curve, derived_priv, &Kpub,
                                     G_context.tx_info.raw_tx + 4, 32,
                                     G_context.tx_info.signature));
  G_context.tx_info.signature_len = 96;

  ZKN_CHECK(cx_bn_unlock());

end:
  explicit_bzero(derived_priv, sizeof(derived_priv));
  explicit_bzero(chain_code, sizeof(chain_code));
  return error;
}

// SIGN (INS=0x02) — sign from BIP32 path: derives privkey internally.
// Data: account(4 BE) || msg(32) = 36 bytes
// Returns R8x|R8y|S (96 bytes).
int handler_sign(buffer_t *cdata)
{
    ZKN_ERROR_INIT();

    uint8_t derived_priv[64];
    uint8_t chain_code[32];
    uint8_t out[96];
    uint8_t msg[32];

    if (cdata->size != 36)
        return io_send_sw(SW_WRONG_DATA_LENGTH);

    uint32_t account = read_u32_be(cdata->ptr);
    memcpy(msg, cdata->ptr + 4, 32);

    // Derive private key from BIP32 path: m/44'/1984'/account'/0'/0'
    error = derive_private_key(KEY_TYPE_SPENDING, account, derived_priv, chain_code);
    if (error != ZKN_OK) {
        explicit_bzero(derived_priv, sizeof(derived_priv));
        return io_send_sw(error);
    }

    ZKN_CHECK(cx_bn_lock(32, 0));

    zkn_edcurve_t curve;
    zkn_edpoint_t Kpub;
    uint32_t curveID = _BABYJUJUB_ID;

    ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, curveID));
    ZKN_CHECK(tEdwards_alloc(&curve, &Kpub));
    ZKN_CHECK(zkn_prv2pub(&curve, derived_priv, &Kpub));
    ZKN_CHECK(EddsaPoseidon_Sign_final(&curve, derived_priv, &Kpub, msg, 32, out));

    ZKN_CHECK(cx_bn_unlock());

    // Clear private key
    explicit_bzero(derived_priv, sizeof(derived_priv));
    explicit_bzero(chain_code, sizeof(chain_code));

    io_send_response_pointer(out, 96, SW_OK);

    ZKN_ERROR_CLOSE_SEND();
}

// SIGN_WITH_PRIVKEY (INS=0x50) — direct sign with raw privkey: no UI.
// Data: curveID(1) || prv(32) || msg(32) = 65 bytes
// Returns R8x|R8y|S (96 bytes).
int handler_sign_with_privkey(buffer_t *cdata)
{
  ZKN_ERROR_INIT();

  // size is curveID(1) || prv(32) || msg(32)
  if (cdata->size != 65)
    error = SW_WRONG_DATA_LENGTH;

  uint32_t curveID = cdata->ptr[0];

  uint8_t out[256];
  uint8_t in[256];

  for (size_t i = 0; i < 256; i++)
    out[i] = 0xff;

  for (size_t i = 0; i < cdata->size - 1; i++)
    in[i] = cdata->ptr[i + 1];

  ZKN_CHECK(cx_bn_lock(32, 0));

  zkn_edcurve_t curve;
  zkn_edpoint_t Kpub;
  uint8_t prv[32];
  uint8_t msg[32];

  for (size_t i = 0; i < 32; i++)
  {
    prv[i] = cdata->ptr[1 + i];  // offset curveID
    msg[i] = cdata->ptr[33 + i]; // offset curveID+prv
  }

  ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, curveID));
  ZKN_CHECK(tEdwards_alloc(&curve, &Kpub));
  ZKN_CHECK(zkn_prv2pub(&curve, in, &Kpub));
  ZKN_CHECK(EddsaPoseidon_Sign_final(&curve, prv, &Kpub, msg, 32, out));

  io_send_response_pointer(out, 96, SW_OK); // answer is R8x|R8y|S

  ZKN_CHECK(cx_bn_unlock());

  ZKN_ERROR_CLOSE_SEND();
}

// SIGN_DISPLAY (INS=0x12) — blind sign with BIP32 derivation: stores payload
// in G_context, shows approval UI, derives key and signs after user confirms.
// Data: account(4 BE) || msg(32) = 36 bytes
// Returns len(1)|sig(96)|msg_hash(32) after user confirms.
int handler_sign_display(buffer_t *cdata)
{
  // payload: account(4 BE) || msg(32) = 36 bytes
  if (cdata->size != 36)
    return io_send_sw(SW_WRONG_DATA_LENGTH);

  explicit_bzero(&G_context, sizeof(G_context));
  G_context.req_type = CONFIRM_TRANSACTION;
  G_context.state = STATE_NONE;

  // Store account + msg for deferred signing after user approval
  memmove(G_context.tx_info.raw_tx, cdata->ptr, 36);
  G_context.tx_info.raw_tx_len = 36;

  // Copy the message (bytes 4-35) into m_hash for display and response
  memmove(G_context.tx_info.m_hash, cdata->ptr + 4, 32);

  G_context.state = STATE_PARSED;

  return ui_display_blind_sign_eddsa_poseidon();
}
