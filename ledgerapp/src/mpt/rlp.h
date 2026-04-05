/**
 * rlp.h  —  Minimal RLP decoder (Ethereum Yellow Paper Appendix B)
 *
 * Supporte uniquement le décodage (pas l'encodage).
 * Limites volontaires pour le Nano : pas d'allocation dynamique.
 */
#pragma once
#include <stdint.h>
#include <string.h>

/* Type d'un item RLP */
typedef enum {
    RLP_STR  = 0,  /* byte string */
    RLP_LIST = 1,  /* liste d'items */
} RlpType;

/* Item RLP — pointe dans le buffer source (pas de copie) */
typedef struct {
    RlpType        type;
    const uint8_t *data;   /* contenu (string) ou début des items (list) */
    uint32_t       len;    /* longueur en bytes */
} RlpItem;

/* Résultat d'un décodage */
typedef enum {
    RLP_OK = 0,
    RLP_ERR_TRUNC,   /* buffer trop court */
    RLP_ERR_OVERFLOW,/* longueur encodée dépasse uint32 */
    RLP_ERR_TOOBIG,  /* item dépasse le buffer */
} RlpErr;

/**
 * rlp_decode — décode le premier item RLP dans buf[0..buf_len)
 *
 * @param buf     buffer source
 * @param buf_len longueur du buffer
 * @param out     item décodé (pointe dans buf)
 * @param consumed bytes consommés (header + data)
 */
static RlpErr rlp_decode(const uint8_t *buf, uint32_t buf_len,
                          RlpItem *out, uint32_t *consumed)
{
    if (buf_len == 0) return RLP_ERR_TRUNC;

    uint8_t prefix = buf[0];

    /* ── Single byte ── */
    if (prefix <= 0x7f) {
        out->type = RLP_STR;
        out->data = buf;
        out->len  = 1;
        *consumed = 1;
        return RLP_OK;
    }

    /* ── Short string (0-55 bytes) ── */
    if (prefix <= 0xb7) {
        uint32_t slen = prefix - 0x80;
        if (1 + slen > buf_len) return RLP_ERR_TRUNC;
        out->type = RLP_STR;
        out->data = buf + 1;
        out->len  = slen;
        *consumed = 1 + slen;
        return RLP_OK;
    }

    /* ── Long string ── */
    if (prefix <= 0xbf) {
        uint8_t llen = prefix - 0xb7;   /* bytes of length */
        if (1 + llen > buf_len) return RLP_ERR_TRUNC;
        uint32_t slen = 0;
        for (uint8_t i = 0; i < llen; i++) slen = (slen << 8) | buf[1 + i];
        if (1 + llen + slen > buf_len) return RLP_ERR_TRUNC;
        out->type = RLP_STR;
        out->data = buf + 1 + llen;
        out->len  = slen;
        *consumed = 1 + llen + slen;
        return RLP_OK;
    }

    /* ── Short list (0-55 bytes payload) ── */
    if (prefix <= 0xf7) {
        uint32_t plen = prefix - 0xc0;
        if (1 + plen > buf_len) return RLP_ERR_TRUNC;
        out->type = RLP_LIST;
        out->data = buf + 1;
        out->len  = plen;
        *consumed = 1 + plen;
        return RLP_OK;
    }

    /* ── Long list ── */
    {
        uint8_t llen = prefix - 0xf7;
        if (1 + llen > buf_len) return RLP_ERR_TRUNC;
        uint32_t plen = 0;
        for (uint8_t i = 0; i < llen; i++) plen = (plen << 8) | buf[1 + i];
        if (1 + llen + plen > buf_len) return RLP_ERR_TRUNC;
        out->type = RLP_LIST;
        out->data = buf + 1 + llen;
        out->len  = plen;
        *consumed = 1 + llen + plen;
        return RLP_OK;
    }
}

/**
 * rlp_list_item — itérateur : extrait le Nième item d'une liste RLP
 *
 * @param list  item de type RLP_LIST
 * @param idx   index 0-based
 * @param out   item résultat
 */
static RlpErr rlp_list_item(const RlpItem *list, uint32_t idx, RlpItem *out)
{
    if (list->type != RLP_LIST) return RLP_ERR_TRUNC;
    const uint8_t *p   = list->data;
    uint32_t       rem = list->len;
    uint32_t       i   = 0;

    while (rem > 0) {
        uint32_t consumed;
        RlpErr e = rlp_decode(p, rem, out, &consumed);
        if (e != RLP_OK) return e;
        if (i == idx) return RLP_OK;
        p   += consumed;
        rem -= consumed;
        i++;
    }
    return RLP_ERR_TRUNC;  /* idx hors limites */
}

/**
 * rlp_list_count — compte les items d'une liste RLP
 */
static uint32_t rlp_list_count(const RlpItem *list)
{
    if (list->type != RLP_LIST) return 0;
    const uint8_t *p   = list->data;
    uint32_t       rem = list->len;
    uint32_t       n   = 0;
    while (rem > 0) {
        RlpItem tmp; uint32_t c;
        if (rlp_decode(p, rem, &tmp, &c) != RLP_OK) break;
        p += c; rem -= c; n++;
    }
    return n;
}
