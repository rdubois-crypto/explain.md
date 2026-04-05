// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX
//
// VSS Test Handler Header

#ifndef _GET_VSS_H
#define _GET_VSS_H

#include "buffer.h"

/**
 * Handler for VSS test APDU commands.
 *
 * APDU format:
 *   CLA=E0 INS=XX P1=test_id P2=sub_param Lc=00
 *
 * Test IDs (P1):
 *   0x00-0x02: makeDealerCoeffsDeterministic for dealer 1,2,3
 *              Returns: threshold * 32 bytes (coefficients)
 *
 *   0x10-0x12: makeDealerCommitments for dealer 1,2,3
 *              Returns: threshold * 64 bytes (points x||y)
 *
 *   0x20-0x22: computeDealerSharesForIds for dealer 1,2,3
 *              Returns: num_participants * 32 bytes (shares)
 *
 *   0x30:      combineGroupPubkeyFromCommitments
 *              Returns: 64 bytes (group public key x||y)
 *
 *   0x40-0x42: verifyFeldmanShare for participant 1,2,3
 *              Returns: num_dealers bytes (0x01=valid, 0x00=invalid)
 *
 *   0x50-0x52: finalizeVSSForParticipant for participant 1,2,3
 *              Returns: 64 bytes (skShareDiv8 || skShare)
 *
 *   0x60:      reconstructConstantFromShares (subset {1,2})
 *   0x61:      reconstructConstantFromShares (subset {2,3})
 *              Returns: 32 bytes (reconstructed a0)
 *
 * @param cdata Command data buffer (unused for static tests)
 * @param p1    Test ID
 * @param p2    Sub-parameter (test-specific)
 *
 * @return 0 on success, error code otherwise
 */
int handler_get_vss(buffer_t *cdata, uint8_t p1, uint8_t p2);

#endif // _GET_VSS_H
