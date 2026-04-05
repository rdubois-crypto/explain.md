// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX
//
// VSS Test Handler - Static test vectors from vss.test.ts
//
// Test vectors:
//   3 participants, threshold=2
//   Participant 1: id=1, seed=0x11*32, password=0xaa*32
//   Participant 2: id=2, seed=0x22*32, password=0xbb*32
//   Participant 3: id=3, seed=0x33*32, password=0xcc*32
//
// APDU format:
//   CLA=E0 INS=XX P1=test_id P2=sub_param Lc=00
//
// Test IDs (P1):
//   0x00-0x02: makeDealerCoeffsDeterministic for dealer 1,2,3
//   0x10-0x12: makeDealerCommitments for dealer 1,2,3 (TODO)
//   0x20-0x22: computeDealerSharesForIds for dealer 1,2,3 (TODO)
//   0x30:      combineGroupPubkeyFromCommitments (TODO)
//   0x40-0x42: verifyFeldmanShare for participant 1,2,3 (TODO)
//   0x50-0x52: finalizeVSSForParticipant for participant 1,2,3 (TODO)
//   0x60:      reconstructConstantFromShares (subset 1,2) (TODO)
//   0x61:      reconstructConstantFromShares (subset 2,3) (TODO)

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "io.h"
#include "buffer.h"

#include "get_vss.h"
#include "globals.h"
#include "sw.h"

#include "zkn_errors.h"
#include "zkn_vss.h"
#include "zkn_tEdwards.h"

// ============================================================================
// Static test vectors from vss.test.ts
// ============================================================================

#define VSS_TEST_NUM_PARTICIPANTS  3
#define VSS_TEST_THRESHOLD         2

// Participant seeds and passwords (filled with constant bytes)
static void init_test_participant(participant_t *p, size_t id) {
    p->id = id;
    
    switch (id) {
        case 1:
            memset(p->seed, 0x11, 32);
            memset(p->password, 0xaa, 32);
            break;
        case 2:
            memset(p->seed, 0x22, 32);
            memset(p->password, 0xbb, 32);
            break;
        case 3:
            memset(p->seed, 0x33, 32);
            memset(p->password, 0xcc, 32);
            break;
        default:
            // Invalid ID - zero everything
            memset(p->seed, 0, 32);
            memset(p->password, 0, 32);
            break;
    }
}

// ============================================================================
// Test: makeDealerCoeffsDeterministic
// Returns: threshold * 32 bytes (coefficients a0, a1, ..., a_{t-1})
// ============================================================================
static int test_makeDealerCoeffsDeterministic(uint8_t dealer_id, uint8_t *output, size_t *output_len) {
    ZKN_ERROR_INIT();
    
    if (dealer_id < 1 || dealer_id > VSS_TEST_NUM_PARTICIPANTS) {
        return ZKN_ERR_INVALID_PARAM;
    }
    
    // Initialize curve
    zkn_edcurve_t curve;
    ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID));
    
    // Initialize participant
    participant_t p;
    init_test_participant(&p, dealer_id);
    
    // Allocate output buffer for coefficients (threshold * 32 bytes)
    uint8_t coefflist[VSS_TEST_THRESHOLD * 32];
    
    // Generate coefficients
    ZKN_CHECK(makeDealerCoeffsDeterministic(&curve, &p, VSS_TEST_THRESHOLD, 0, coefflist));
    
    // Copy to output
    memcpy(output, coefflist, VSS_TEST_THRESHOLD * 32);
    *output_len = VSS_TEST_THRESHOLD * 32;
    
    // Cleanup
    explicit_bzero(coefflist, sizeof(coefflist));
    explicit_bzero(&p, sizeof(p));
    ZKN_CHECK(tEdwards_Curve_destroy(&curve));
    
    ZKN_ERROR_CLOSE();
}

// ============================================================================
// Stub tests for not-yet-implemented functions
// These will return SW_INS_NOT_SUPPORTED until implemented
// ============================================================================

#ifdef VSS_FULL_IMPLEMENTATION

// ============================================================================
// Test: makeDealerCommitments
// Returns: threshold * 64 bytes (commitments C0, C1, ..., each as x||y)
// ============================================================================
static int test_makeDealerCommitments(uint8_t dealer_id, uint8_t *output, size_t *output_len) {
    ZKN_ERROR_INIT();
    
    if (dealer_id < 1 || dealer_id > VSS_TEST_NUM_PARTICIPANTS) {
        return ZKN_ERR_INVALID_PARAM;
    }
    
    // Initialize curve
    zkn_edcurve_t curve;
    ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID));
    
    // Initialize participant
    participant_t p;
    init_test_participant(&p, dealer_id);
    
    // Generate coefficients first
    uint8_t coefflist[VSS_TEST_THRESHOLD * 32];
    ZKN_CHECK(makeDealerCoeffsDeterministic(&curve, &p, VSS_TEST_THRESHOLD, 0, coefflist));
    
    // Generate commitments (threshold * 64 bytes for uncompressed points)
    uint8_t commitments[VSS_TEST_THRESHOLD * 64];
    ZKN_CHECK(makeDealerCommitments(&curve, coefflist, VSS_TEST_THRESHOLD, commitments));
    
    // Copy to output
    memcpy(output, commitments, VSS_TEST_THRESHOLD * 64);
    *output_len = VSS_TEST_THRESHOLD * 64;
    
    // Cleanup
    explicit_bzero(coefflist, sizeof(coefflist));
    explicit_bzero(&p, sizeof(p));
    ZKN_CHECK(tEdwards_Curve_destroy(&curve));
    
    ZKN_ERROR_CLOSE();
}

// ============================================================================
// Test: computeDealerSharesForIds
// Returns: num_participants * 32 bytes (shares for ids 1, 2, 3)
// ============================================================================
static int test_computeDealerSharesForIds(uint8_t dealer_id, uint8_t *output, size_t *output_len) {
    ZKN_ERROR_INIT();
    
    if (dealer_id < 1 || dealer_id > VSS_TEST_NUM_PARTICIPANTS) {
        return ZKN_ERR_INVALID_PARAM;
    }
    
    // Initialize curve
    zkn_edcurve_t curve;
    ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID));
    
    // Initialize participant (dealer)
    participant_t p;
    init_test_participant(&p, dealer_id);
    
    // Generate coefficients
    uint8_t coefflist[VSS_TEST_THRESHOLD * 32];
    ZKN_CHECK(makeDealerCoeffsDeterministic(&curve, &p, VSS_TEST_THRESHOLD, 0, coefflist));
    
    // Compute shares for each recipient ID (1, 2, 3)
    uint8_t share[32];
    for (size_t recipient_id = 1; recipient_id <= VSS_TEST_NUM_PARTICIPANTS; recipient_id++) {
        ZKN_CHECK(computeDealerShareForId(&curve, coefflist, VSS_TEST_THRESHOLD, recipient_id, share));
        memcpy(output + (recipient_id - 1) * 32, share, 32);
    }
    
    *output_len = VSS_TEST_NUM_PARTICIPANTS * 32;
    
    // Cleanup
    explicit_bzero(coefflist, sizeof(coefflist));
    explicit_bzero(&p, sizeof(p));
    ZKN_CHECK(tEdwards_Curve_destroy(&curve));
    
    ZKN_ERROR_CLOSE();
}

// ============================================================================
// Test: verifyFeldmanShare
// For participant P, verify all shares from all dealers
// Returns: 1 byte per dealer (0x01 = valid, 0x00 = invalid)
// ============================================================================
static int test_verifyFeldmanShare(uint8_t participant_id, uint8_t *output, size_t *output_len) {
    ZKN_ERROR_INIT();
    
    if (participant_id < 1 || participant_id > VSS_TEST_NUM_PARTICIPANTS) {
        return ZKN_ERR_INVALID_PARAM;
    }
    
    // Initialize curve
    zkn_edcurve_t curve;
    ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID));
    
    // For each dealer, compute their coefficients, commitments, and share for this participant
    // Then verify the share
    for (size_t dealer_id = 1; dealer_id <= VSS_TEST_NUM_PARTICIPANTS; dealer_id++) {
        participant_t dealer;
        init_test_participant(&dealer, dealer_id);
        
        // Generate dealer's coefficients
        uint8_t coefflist[VSS_TEST_THRESHOLD * 32];
        ZKN_CHECK(makeDealerCoeffsDeterministic(&curve, &dealer, VSS_TEST_THRESHOLD, 0, coefflist));
        
        // Generate dealer's commitments
        uint8_t commitments[VSS_TEST_THRESHOLD * 64];
        ZKN_CHECK(makeDealerCommitments(&curve, coefflist, VSS_TEST_THRESHOLD, commitments));
        
        // Compute share for this participant
        uint8_t share[32];
        ZKN_CHECK(computeDealerShareForId(&curve, coefflist, VSS_TEST_THRESHOLD, participant_id, share));
        
        // Verify the share
        bool valid = false;
        ZKN_CHECK(verifyFeldmanShare(&curve, participant_id, share, commitments, VSS_TEST_THRESHOLD, &valid));
        
        output[dealer_id - 1] = valid ? 0x01 : 0x00;
        
        explicit_bzero(coefflist, sizeof(coefflist));
        explicit_bzero(&dealer, sizeof(dealer));
    }
    
    *output_len = VSS_TEST_NUM_PARTICIPANTS;
    
    ZKN_CHECK(tEdwards_Curve_destroy(&curve));
    
    ZKN_ERROR_CLOSE();
}

// ============================================================================
// Test: combineGroupPubkeyFromCommitments
// Combines C0 from all dealers to get group public key
// Returns: 64 bytes (x || y of group public key)
// ============================================================================
static int test_combineGroupPubkey(uint8_t *output, size_t *output_len) {
    ZKN_ERROR_INIT();
    
    // Initialize curve
    zkn_edcurve_t curve;
    ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID));
    
    // Collect all C0 commitments (first commitment from each dealer)
    uint8_t all_C0[VSS_TEST_NUM_PARTICIPANTS * 64];
    
    for (size_t dealer_id = 1; dealer_id <= VSS_TEST_NUM_PARTICIPANTS; dealer_id++) {
        participant_t dealer;
        init_test_participant(&dealer, dealer_id);
        
        uint8_t coefflist[VSS_TEST_THRESHOLD * 32];
        ZKN_CHECK(makeDealerCoeffsDeterministic(&curve, &dealer, VSS_TEST_THRESHOLD, 0, coefflist));
        
        uint8_t commitments[VSS_TEST_THRESHOLD * 64];
        ZKN_CHECK(makeDealerCommitments(&curve, coefflist, VSS_TEST_THRESHOLD, commitments));
        
        memcpy(all_C0 + (dealer_id - 1) * 64, commitments, 64);
        
        explicit_bzero(coefflist, sizeof(coefflist));
        explicit_bzero(&dealer, sizeof(dealer));
    }
    
    // Sum all C0 points
    zkn_edpoint_t acc;
    ZKN_CHECK(tEdwards_alloc(&curve, &acc));
    ZKN_CHECK(tEdwards_SetNeutral(&curve, &acc));
    
    zkn_edpoint_t C0_point;
    ZKN_CHECK(tEdwards_alloc(&curve, &C0_point));
    
    for (size_t i = 0; i < VSS_TEST_NUM_PARTICIPANTS; i++) {
        uint8_t *c0_bytes = all_C0 + i * 64;
        ZKN_CHECK(tEdwards_init(&curve, c0_bytes, c0_bytes + 32, &C0_point));
        
        zkn_edpoint_t tmp;
        ZKN_CHECK(tEdwards_alloc(&curve, &tmp));
        ZKN_CHECK(tEdwards_add(&curve, &acc, &C0_point, &tmp));
        ZKN_CHECK(tEdwards_copy(&tmp, &acc));
        ZKN_CHECK(tEdwards_destroy(&curve, &tmp));
    }
    
    ZKN_CHECK(tEdwards_normalize(&curve, &acc));
    ZKN_CHECK(tEdwards_export(&curve, &acc, output, output + 32));
    *output_len = 64;
    
    ZKN_CHECK(tEdwards_destroy(&curve, &acc));
    ZKN_CHECK(tEdwards_destroy(&curve, &C0_point));
    ZKN_CHECK(tEdwards_Curve_destroy(&curve));
    
    ZKN_ERROR_CLOSE();
}

// ============================================================================
// Test: finalizeVSSForParticipant
// Returns: 64 bytes (skShareDiv8 || skShare)
// ============================================================================
static int test_finalizeVSSForParticipant(uint8_t participant_id, uint8_t *output, size_t *output_len) {
    ZKN_ERROR_INIT();
    
    if (participant_id < 1 || participant_id > VSS_TEST_NUM_PARTICIPANTS) {
        return ZKN_ERR_INVALID_PARAM;
    }
    
    zkn_edcurve_t curve;
    ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID));
    
    cx_bn_t s_i_bn, share_bn, tmp;
    ZKN_CHECK(cx_bn_alloc(&s_i_bn, 32));
    ZKN_CHECK(cx_bn_set_u32(s_i_bn, 0));
    ZKN_CHECK(cx_bn_alloc(&share_bn, 32));
    ZKN_CHECK(cx_bn_alloc(&tmp, 32));
    
    for (size_t dealer_id = 1; dealer_id <= VSS_TEST_NUM_PARTICIPANTS; dealer_id++) {
        participant_t dealer;
        init_test_participant(&dealer, dealer_id);
        
        uint8_t coefflist[VSS_TEST_THRESHOLD * 32];
        ZKN_CHECK(makeDealerCoeffsDeterministic(&curve, &dealer, VSS_TEST_THRESHOLD, 0, coefflist));
        
        uint8_t share[32];
        ZKN_CHECK(computeDealerShareForId(&curve, coefflist, VSS_TEST_THRESHOLD, participant_id, share));
        
        ZKN_CHECK(cx_bn_init(share_bn, share, 32));
        ZKN_CHECK(cx_bn_mod_add(tmp, s_i_bn, share_bn, curve.order));
        ZKN_CHECK(cx_bn_copy(s_i_bn, tmp));
        
        explicit_bzero(coefflist, sizeof(coefflist));
    }
    
    uint8_t skShareDiv8[32];
    ZKN_CHECK(cx_bn_export(s_i_bn, skShareDiv8, 32));
    
    cx_bn_t eight, skShare_bn;
    ZKN_CHECK(cx_bn_alloc(&eight, 32));
    ZKN_CHECK(cx_bn_set_u32(eight, 8));
    ZKN_CHECK(cx_bn_alloc(&skShare_bn, 32));
    ZKN_CHECK(cx_bn_mod_mul(skShare_bn, s_i_bn, eight, curve.order));
    
    uint8_t skShare[32];
    ZKN_CHECK(cx_bn_export(skShare_bn, skShare, 32));
    
    memcpy(output, skShareDiv8, 32);
    memcpy(output + 32, skShare, 32);
    *output_len = 64;
    
    ZKN_CHECK(cx_bn_destroy(&s_i_bn));
    ZKN_CHECK(cx_bn_destroy(&share_bn));
    ZKN_CHECK(cx_bn_destroy(&tmp));
    ZKN_CHECK(cx_bn_destroy(&eight));
    ZKN_CHECK(cx_bn_destroy(&skShare_bn));
    ZKN_CHECK(tEdwards_Curve_destroy(&curve));
    
    ZKN_ERROR_CLOSE();
}

// ============================================================================
// Test: reconstructConstantFromShares
// Returns: 32 bytes (reconstructed a0)
// ============================================================================
static int test_reconstructConstantFromShares(uint8_t subset_id, uint8_t *output, size_t *output_len) {
    ZKN_ERROR_INIT();
    
    size_t ids[2];
    if (subset_id == 0) {
        ids[0] = 1; ids[1] = 2;
    } else if (subset_id == 1) {
        ids[0] = 2; ids[1] = 3;
    } else {
        return ZKN_ERR_INVALID_PARAM;
    }
    
    zkn_edcurve_t curve;
    ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID));
    
    vss_share_t shares[2];
    
    for (int i = 0; i < 2; i++) {
        size_t participant_id = ids[i];
        shares[i].id = participant_id;
        
        cx_bn_t s_i_bn, share_bn, tmp;
        ZKN_CHECK(cx_bn_alloc(&s_i_bn, 32));
        ZKN_CHECK(cx_bn_set_u32(s_i_bn, 0));
        ZKN_CHECK(cx_bn_alloc(&share_bn, 32));
        ZKN_CHECK(cx_bn_alloc(&tmp, 32));
        
        for (size_t dealer_id = 1; dealer_id <= VSS_TEST_NUM_PARTICIPANTS; dealer_id++) {
            participant_t dealer;
            init_test_participant(&dealer, dealer_id);
            
            uint8_t coefflist[VSS_TEST_THRESHOLD * 32];
            ZKN_CHECK(makeDealerCoeffsDeterministic(&curve, &dealer, VSS_TEST_THRESHOLD, 0, coefflist));
            
            uint8_t share[32];
            ZKN_CHECK(computeDealerShareForId(&curve, coefflist, VSS_TEST_THRESHOLD, participant_id, share));
            
            ZKN_CHECK(cx_bn_init(share_bn, share, 32));
            ZKN_CHECK(cx_bn_mod_add(tmp, s_i_bn, share_bn, curve.order));
            ZKN_CHECK(cx_bn_copy(s_i_bn, tmp));
            
            explicit_bzero(coefflist, sizeof(coefflist));
        }
        
        ZKN_CHECK(cx_bn_export(s_i_bn, shares[i].sk_share_div8, 32));
        
        cx_bn_t eight;
        ZKN_CHECK(cx_bn_alloc(&eight, 32));
        ZKN_CHECK(cx_bn_set_u32(eight, 8));
        ZKN_CHECK(cx_bn_mod_mul(tmp, s_i_bn, eight, curve.order));
        ZKN_CHECK(cx_bn_export(tmp, shares[i].sk_share, 32));
        
        ZKN_CHECK(cx_bn_destroy(&s_i_bn));
        ZKN_CHECK(cx_bn_destroy(&share_bn));
        ZKN_CHECK(cx_bn_destroy(&tmp));
        ZKN_CHECK(cx_bn_destroy(&eight));
    }
    
    ZKN_CHECK(reconstructConstantFromShares(&curve, shares, 2, output));
    *output_len = 32;
    
    ZKN_CHECK(tEdwards_Curve_destroy(&curve));
    
    ZKN_ERROR_CLOSE();
}

#endif // VSS_FULL_IMPLEMENTATION

// ============================================================================
// Main APDU Handler
// ============================================================================

int handler_get_vss(buffer_t *cdata, uint8_t p1, uint8_t p2) {
    (void)cdata;  // Unused - static test vectors
    (void)p2;     // Reserved for future use
    
    uint8_t output[256];  // Max output buffer
    size_t output_len = 0;
    zkn_error_t error = ZKN_OK;
    
    // Dispatch based on P1 (test ID)
    switch (p1) {
        // ----------------------------------------------------------------
        // makeDealerCoeffsDeterministic tests (P1 = 0x00-0x02)
        // IMPLEMENTED
        // ----------------------------------------------------------------
        case 0x00:
        case 0x01:
        case 0x02:
            error = test_makeDealerCoeffsDeterministic(p1 + 1, output, &output_len);
            break;
            
#ifdef VSS_FULL_IMPLEMENTATION
        // ----------------------------------------------------------------
        // makeDealerCommitments tests (P1 = 0x10-0x12)
        // Requires: makeDealerCommitments()
        // ----------------------------------------------------------------
        case 0x10:
        case 0x11:
        case 0x12:
            error = test_makeDealerCommitments(p1 - 0x10 + 1, output, &output_len);
            break;
            
        // ----------------------------------------------------------------
        // computeDealerSharesForIds tests (P1 = 0x20-0x22)
        // Requires: computeDealerShareForId()
        // ----------------------------------------------------------------
        case 0x20:
        case 0x21:
        case 0x22:
            error = test_computeDealerSharesForIds(p1 - 0x20 + 1, output, &output_len);
            break;
            
        // ----------------------------------------------------------------
        // combineGroupPubkeyFromCommitments (P1 = 0x30)
        // Requires: makeDealerCommitments()
        // ----------------------------------------------------------------
        case 0x30:
            error = test_combineGroupPubkey(output, &output_len);
            break;
            
        // ----------------------------------------------------------------
        // verifyFeldmanShare tests (P1 = 0x40-0x42)
        // Requires: makeDealerCommitments(), computeDealerShareForId(), verifyFeldmanShare()
        // ----------------------------------------------------------------
        case 0x40:
        case 0x41:
        case 0x42:
            error = test_verifyFeldmanShare(p1 - 0x40 + 1, output, &output_len);
            break;
            
        // ----------------------------------------------------------------
        // finalizeVSSForParticipant tests (P1 = 0x50-0x52)
        // Requires: computeDealerShareForId()
        // ----------------------------------------------------------------
        case 0x50:
        case 0x51:
        case 0x52:
            error = test_finalizeVSSForParticipant(p1 - 0x50 + 1, output, &output_len);
            break;
            
        // ----------------------------------------------------------------
        // reconstructConstantFromShares tests (P1 = 0x60-0x61)
        // Requires: computeDealerShareForId(), reconstructConstantFromShares()
        // ----------------------------------------------------------------
        case 0x60:
        case 0x61:
            error = test_reconstructConstantFromShares(p1 - 0x60, output, &output_len);
            break;
#endif // VSS_FULL_IMPLEMENTATION
            
        default:
            return io_send_sw(SW_INS_NOT_SUPPORTED);
    }
    
    if (error != ZKN_OK) {
        return io_send_sw(SW_BAD_STATE);
    }
    
    return io_send_response_pointer(output, output_len, SW_OK);
}
