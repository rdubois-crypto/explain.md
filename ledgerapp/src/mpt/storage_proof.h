/**
 * storage_proof.h  —  Ethereum storage proof verifier
 *
 * Vérifie une storage proof EIP-1186 pour un slot bytes32 :
 *
 *   - Clé MPT   = keccak256(slot)  exprimée en 64 nibbles
 *   - Valeur    = RLP(bytes32)  — entier big-endian trimmé des zéros de tête
 *   - Chaque nœud doit vérifier : keccak256(node_i) == hash dans node_{i-1}
 *   - Le premier nœud doit vérifier : keccak256(node_0) == storageHash
 *
 * Différences vs account proof :
 *   - La clé est keccak256(slot) et non keccak256(address)
 *   - La valeur leaf est RLP d'un entier (pas un account RLP)
 *   - La valeur décodée est un bytes32 (re-padded à gauche)
 *
 * Réutilise rlp.h et keccak256.h.
 */
#pragma once
#include <stdint.h>
#include <string.h>
#include "keccak256.h"
#include "rlp.h"

#define SPF_HASH_LEN   32
#define SPF_KEY_NIBS   64
#define SPF_MAX_NODES  20
#define SPF_MAX_NODE   1024

typedef enum {
    SPF_OK = 0,
    SPF_ERR_HASH_MISMATCH,  /* keccak256(node) != expected */
    SPF_ERR_BAD_NODE,       /* RLP malformé ou type inattendu */
    SPF_ERR_PATH_MISMATCH,  /* nibble path diverge */
    SPF_ERR_NO_LEAF,        /* slot absent du trie */
    SPF_ERR_VALUE,          /* valeur leaf mal formée */
    SPF_ERR_PARAM,
} SpfErr;

static void spf_keccak256(const uint8_t *d, uint32_t n, uint8_t out[32])
{
    keccak256_ctx_t ctx;
    keccak256_init(&ctx);
    keccak256_update(&ctx, d, n);
    keccak256_final(&ctx, out);
}

/* slot (32 bytes) → key nibbles (64) = keccak256(slot) en nibbles */
static void slot_to_nibbles(const uint8_t slot[32], uint8_t nibs[64])
{
    uint8_t h[32];
    spf_keccak256(slot, 32, h);
    for (int i = 0; i < 32; i++) {
        nibs[2*i]   = (h[i] >> 4) & 0x0F;
        nibs[2*i+1] =  h[i]       & 0x0F;
    }
}

/* HP path decoder — réutilisation identique à mpt.h */
static void spf_decode_compact(const uint8_t *enc, uint32_t enc_len,
                                uint8_t *nibs, uint32_t *n_nibs, int *is_leaf)
{
    if (enc_len == 0) { *n_nibs = 0; *is_leaf = 0; return; }
    uint8_t hi = (enc[0] >> 4) & 0x0F;
    *is_leaf    = (hi >> 1) & 1;
    int odd     = hi & 1;
    *n_nibs     = 0;
    if (odd) nibs[(*n_nibs)++] = enc[0] & 0x0F;
    for (uint32_t i = 1; i < enc_len; i++) {
        nibs[(*n_nibs)++] = (enc[i] >> 4) & 0x0F;
        nibs[(*n_nibs)++] =  enc[i]       & 0x0F;
    }
}

/**
 * spf_verify — vérifie la storage proof et extrait la valeur bytes32
 *
 * @param storage_hash   32 bytes : storage root (storageHash du compte)
 * @param slot           32 bytes : slot Solidity (non hashé)
 * @param proof_nodes    tableau de nœuds RLP encodés
 * @param proof_lens     longueurs
 * @param n_nodes        nombre de nœuds
 * @param value_out      32 bytes output : valeur stockée (bytes32, zero-padded)
 */
SpfErr spf_verify(
    const uint8_t  storage_hash[32],
    const uint8_t  slot[32],
    const uint8_t *proof_nodes[],
    const uint32_t proof_lens[],
    uint32_t       n_nodes,
    uint8_t        value_out[32])
{
    if (n_nodes == 0 || n_nodes > SPF_MAX_NODES) return SPF_ERR_PARAM;

    /* Clé = nibbles de keccak256(slot) */
    uint8_t key[SPF_KEY_NIBS];
    slot_to_nibbles(slot, key);
    uint32_t key_pos = 0;

    uint8_t expected[32];
    memcpy(expected, storage_hash, 32);

    for (uint32_t ni = 0; ni < n_nodes; ni++) {
        const uint8_t *nb = proof_nodes[ni];
        uint32_t       nl = proof_lens[ni];

        /* Vérifie le hash du nœud */
        uint8_t h[32];
        spf_keccak256(nb, nl, h);
        if (memcmp(h, expected, 32) != 0) return SPF_ERR_HASH_MISMATCH;

        /* Décode le nœud RLP */
        RlpItem node; uint32_t consumed;
        if (rlp_decode(nb, nl, &node, &consumed) != RLP_OK) return SPF_ERR_BAD_NODE;
        if (node.type != RLP_LIST) return SPF_ERR_BAD_NODE;

        uint32_t cnt = rlp_list_count(&node);

        /* ── Branch (17 items) ── */
        if (cnt == 17) {
            if (key_pos >= SPF_KEY_NIBS) return SPF_ERR_BAD_NODE;
            uint8_t nib = key[key_pos++];
            RlpItem child;
            if (rlp_list_item(&node, nib, &child) != RLP_OK) return SPF_ERR_BAD_NODE;
            if (child.type == RLP_STR && child.len == 32) {
                memcpy(expected, child.data, 32);
            } else if (child.type == RLP_STR && child.len == 0) {
                return SPF_ERR_NO_LEAF;
            } else {
                return SPF_ERR_BAD_NODE;
            }
            continue;
        }

        /* ── Extension ou Leaf (2 items) ── */
        if (cnt == 2) {
            RlpItem path_item, val_item;
            if (rlp_list_item(&node, 0, &path_item) != RLP_OK) return SPF_ERR_BAD_NODE;
            if (rlp_list_item(&node, 1, &val_item)  != RLP_OK) return SPF_ERR_BAD_NODE;
            if (path_item.type != RLP_STR) return SPF_ERR_BAD_NODE;

            uint8_t path_nibs[128]; uint32_t path_n; int is_leaf;
            spf_decode_compact(path_item.data, path_item.len, path_nibs, &path_n, &is_leaf);

            if (key_pos + path_n > SPF_KEY_NIBS) return SPF_ERR_PATH_MISMATCH;
            if (memcmp(path_nibs, key + key_pos, path_n) != 0) return SPF_ERR_PATH_MISMATCH;
            key_pos += path_n;

            if (is_leaf) {
                /*
                 * Storage trie leaf value is RLP(trimmed_integer).
                 * val_item contains the raw RLP bytes — decode one more level.
                 */
                if (val_item.type != RLP_STR) return SPF_ERR_VALUE;

                /* Short value (single byte <= 0x7f): val_item IS the value */
                if (val_item.len <= 32 && (val_item.len == 0 || val_item.data[0] < 0x80)) {
                    memset(value_out, 0, 32);
                    memcpy(value_out + (32 - val_item.len), val_item.data, val_item.len);
                    return SPF_OK;
                }

                /* Longer value: val_item is RLP-encoded, decode inner */
                RlpItem inner; uint32_t ic;
                if (rlp_decode(val_item.data, val_item.len, &inner, &ic) != RLP_OK)
                    return SPF_ERR_VALUE;
                if (inner.type != RLP_STR || inner.len > 32)
                    return SPF_ERR_VALUE;

                memset(value_out, 0, 32);
                memcpy(value_out + (32 - inner.len), inner.data, inner.len);
                return SPF_OK;
            } else {
                /* Extension : val_item = hash du prochain nœud */
                if (val_item.type != RLP_STR || val_item.len != 32) return SPF_ERR_BAD_NODE;
                memcpy(expected, val_item.data, 32);
            }
            continue;
        }

        return SPF_ERR_BAD_NODE;
    }

    return SPF_ERR_NO_LEAF;
}
