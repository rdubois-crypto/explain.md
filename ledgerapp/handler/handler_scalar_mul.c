// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX
//
// Scalar multiplication APDU handlers.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../sw.h"
#include "os.h"
#include "cx.h"
#include "buffer.h"

#include "../globals.h"

#include "zkn_errors.h"
#include "zkn_tEdwards.h"
#include "handler_scalar_mul.h"

#include "send_response.h"

// example commands: e00e0000020101, multiply P by 1 on bandersnatch
// bandersnatch test: e00e000021011cfb69d4ca675f520cce760202687600ff8f87007419047174fd06b52876e7e2 is (order+1)P, shall return P
// babyjujub test:    e00e00002102060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f2 is (order+1)P, shall return P

int handler_scalar_mul_fixed_base(buffer_t *cdata)
{
  ZKN_ERROR_INIT();

  if (cdata->size > ECC_MAXSIZE8 + 1)
    return SW_WRONG_DATA_LENGTH;

  if (cdata->size < 2)
    return SW_WRONG_DATA_LENGTH;

  uint32_t curveID = cdata->ptr[0];

  uint8_t out[256];
  for (int i = 0; i < 256; i++)
  {
    out[i] = 0xff;
  }
  ZKN_CHECK(cx_bn_lock(32, 0));
  zkn_edcurve_t curve;
  // cx_trng_init();

  ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, curveID));

  zkn_edpoint_t edP;
  zkn_edpoint_t edQ;

  if (curveID == _BANDERSNATCH_ID)
  {
    // from ZKNOX PyBandersnatch
    // test_vectors['p'] = E(F(0x1cc6ee38139c1c110223537a8ce79d067e58cc1067c6fbb7d8b3a1b08dfc8f08), F(0x70a5894a64445438d015ac32ba360f092cde44bab11fc2b7d4b5c0d216228cce), F(1))
    uint8_t px[32] = {0x1c, 0xc6, 0xee, 0x38, 0x13, 0x9c, 0x1c, 0x11, 0x02, 0x23, 0x53, 0x7a, 0x8c, 0xe7, 0x9d, 0x06, 0x7e, 0x58, 0xcc, 0x10, 0x67, 0xc6, 0xfb, 0xb7, 0xd8, 0xb3, 0xa1, 0xb0, 0x8d, 0xfc, 0x8f, 0x08};
    uint8_t py[32] = {0x70, 0xa5, 0x89, 0x4a, 0x64, 0x44, 0x54, 0x38, 0xd0, 0x15, 0xac, 0x32, 0xba, 0x36, 0x0f, 0x09, 0x2c, 0xde, 0x44, 0xba, 0xb1, 0x1f, 0xc2, 0xb7, 0xd4, 0xb5, 0xc0, 0xd2, 0x16, 0x22, 0x8c, 0xce};

    // test_vectors['p_double'] = E(F(0x604a025084bdae7f6d83c3de82b41b840118cca2b4431bb1c9140190b705fea8), F(0x3e8ff40606be05404b97ccdefb19956b75ab0b532da07edf5d6b4f6a404b06cf), F(1))
    // test_vectors['p_plus_q'] = E(F(0x14d5319b5a0aee4d5ad410a5965e4f46c04b034f10252edc887567d206e762fb), F(0x2d04373af410d24b4bb950f8b3096928852705ab12c7e7b46611fac016328df9), F(1))
    // test_vectors['k'] = 0x1a862619b8224e61eb24bb583c84ce04913064d37308623924c7a64fcdc9f191
    // test_vectors['k_times_p'] = E(F(0x5e68a7f103de3be399640801563ddcaac8fc2fa31b413df3a8ae975ace0dc465), F(0xf2693e9239ee3709661fbf6c908de99ce7a41f149cefebe5ef6fc2c292bb4c6), F(1))s

    // test_vectors['q'] = E(F(0x2a2086fc8de76abcc75c48528de91cf68fb8ce4c04f80b94b071315dfff66db8), F(0x6765f125acbdd10815bedbffe1147d36cf5c501f7ad467f4cd12aeec62a7ef1f), F(1))
    // uint8_t qx[32]={0x2a, 0x20, 0x86, 0xfc, 0x8d, 0xe7, 0x6a, 0xbc, 0xc7, 0x5c, 0x48, 0x52, 0x8d, 0xe9, 0x1c, 0xf6, 0x8f, 0xb8, 0xce, 0x4c, 0x04, 0xf8, 0x0b, 0x94, 0xb0, 0x71, 0x31, 0x5d, 0xff, 0xf6, 0x6d, 0xb8};
    // uint8_t qy[32]={0x67, 0x65, 0xf1, 0x25, 0xac, 0xbd, 0xd1, 0x08, 0x15, 0xbe, 0xdb, 0xff, 0xe1, 0x14, 0x7d, 0x36, 0xcf, 0x5c, 0x50, 0x1f, 0x7a, 0xd4, 0x67, 0xf4, 0xcd, 0x12, 0xae, 0xec, 0x62, 0xa7, 0xef, 0x1f};

    ZKN_CHECK(tEdwards_alloc_init(&curve, px, py, &edP));
    ZKN_CHECK(tEdwards_alloc_init(&curve, px, py, &edQ));
  }

  // not tested
  if (curveID == _BABYJUJUB_ID)
  {

    // tbd:https://github.com/iden3/go-iden3-crypto/blob/master/babyjub/babyjub_test.go
    // aX=17777552123799933955779906779655732241715742912184938656739573121738514868268
    // 0x274dbce8d15179969bc0d49fa725bddf9de555e0ba6a693c6adb52fc9ee7a82c
    // aY=2626589144620713026669568689430873010625803728049924121243784502389097019475
    // 0x5ce98c61b05f47fe2eae9a542bd99f6b2e78246231640b54595febfd51eb853

    // test_vectors['p'] = E(F(0x1cc6ee38139c1c110223537a8ce79d067e58cc1067c6fbb7d8b3a1b08dfc8f08), F(0x70a5894a64445438d015ac32ba360f092cde44bab11fc2b7d4b5c0d216228cce), F(1))
    uint8_t px2[32] = {0x27, 0x4d, 0xbc, 0xe8, 0xd1, 0x51, 0x79, 0x96, 0x9b, 0xc0, 0xd4, 0x9f, 0xa7, 0x25, 0xbd, 0xdf, 0x9d, 0xe5, 0x55, 0xe0, 0xba, 0x6a, 0x69, 0x3c, 0x6a, 0xdb, 0x52, 0xfc, 0x9e, 0xe7, 0xa8, 0x2c};
    uint8_t py2[32] = {0x05, 0xce, 0x98, 0xc6, 0x1b, 0x05, 0xf4, 0x7f, 0xe2, 0xea, 0xe9, 0xa5, 0x42, 0xbd, 0x99, 0xf6, 0xb2, 0xe7, 0x82, 0x46, 0x23, 0x16, 0x40, 0xb5, 0x45, 0x95, 0xfe, 0xbf, 0xd5, 0x1e, 0xb8, 0x53};

    ZKN_CHECK(tEdwards_alloc_init(&curve, px2, py2, &edP));
    ZKN_CHECK(tEdwards_alloc_init(&curve, px2, py2, &edQ));
  }

  bool flag = false;

  ZKN_CHECK(tEdwards_IsOnCurve(&curve, &edP, &flag));
  if (flag != true)
    return io_send_sw(0xca01);

  ZKN_CHECK(tEdwards_IsOnCurve(&curve, &edQ, &flag));
  if (flag != true)
    return io_send_sw(0xca02);

  ZKN_CHECK(cx_bn_is_prime(curve.modulus, &flag));
  if (flag != true)
    return io_send_sw(0xca03);

  ZKN_CHECK(cx_bn_is_prime(curve.order, &flag));
  if (flag != true)
    return io_send_sw(0xca04);

  ZKN_CHECK(tEdwards_scalarMul(&curve, &edP, cdata->ptr + 1, cdata->size - 1, &edQ)); // compute the scalar multiplication of input data
  ZKN_CHECK(tEdwards_export(&curve, &edQ, out, out + 32));                            // shall be result

  ZKN_CHECK(cx_bn_unlock());

  io_send_response_pointer(out, curve.fieldsize8 * 2, SW_OK);

  ZKN_ERROR_CLOSE_SEND(); // return sw error if any, or 0 if execution OK
}

int handler_scalar_mul_variable_base(buffer_t *cdata)
{
  ZKN_ERROR_INIT();

  if (cdata->size != 97)
    return io_send_sw(SW_WRONG_DATA_LENGTH);

  const uint8_t *ptr = cdata->ptr;
  uint32_t curveID = ptr[0];
  ptr += 1;
  const uint8_t *px = ptr;
  ptr += 32;
  const uint8_t *py = ptr;
  ptr += 32;
  const uint8_t *k = ptr;

  uint8_t out[64];

  ZKN_CHECK(cx_bn_lock(32, 0));

  zkn_edcurve_t curve;
  ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, curveID));

  zkn_edpoint_t P, R;
  ZKN_CHECK(tEdwards_alloc_init(&curve, (uint8_t *)px, (uint8_t *)py, &P));
  ZKN_CHECK(tEdwards_alloc(&curve, &R));

  ZKN_CHECK(tEdwards_scalarMul(&curve, &P, k, 32, &R));
  ZKN_CHECK(tEdwards_destroy(&curve, &P));
  ZKN_CHECK(tEdwards_normalize(&curve, &R));

  uint8_t rx[32], ry[32];
  ZKN_CHECK(tEdwards_export(&curve, &R, rx, ry));

  for (size_t i = 0; i < 32; i++)
  {
    out[i] = rx[i];
    out[32 + i] = ry[i];
  }

  io_send_response_pointer(out, sizeof(out), SW_OK);
  ZKN_CHECK(cx_bn_unlock());
  ZKN_ERROR_CLOSE_SEND();
}

int handler_scalar_mul_fixed_base_msm2(buffer_t *cdata)
{
  ZKN_ERROR_INIT();

  if (cdata->size != 33)
    return io_send_sw(SW_WRONG_DATA_LENGTH);

  uint32_t curveID = cdata->ptr[0];
  uint8_t k[32];
  memcpy(k, cdata->ptr + 1, 32);

  uint8_t out[64];
  bool bn_locked = false;
  bool curve_alloced = false;
  bool point_alloced = false;

  zkn_edcurve_t curve;
  zkn_edpoint_t R;

  ZKN_CHECK(cx_bn_lock(32, 0));
  bn_locked = true;

  ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, curveID));
  curve_alloced = true;

  ZKN_CHECK(tEdwards_alloc(&curve, &R));
  point_alloced = true;

  ZKN_CHECK(tEdwards_fixedBase_2MSM(&curve, k, &R));

  uint8_t rx[32], ry[32];
  ZKN_CHECK(tEdwards_export(&curve, &R, rx, ry));

  for (size_t i = 0; i < 32; i++)
  {
    out[i] = rx[i];
    out[32 + i] = ry[i];
  }

  ZKN_CHECK(tEdwards_destroy(&curve, &R));
  point_alloced = false;

  ZKN_CHECK(tEdwards_Curve_partial_destroy(&curve));
  ZKN_CHECK(cx_bn_destroy(&curve.modulus));
  curve_alloced = false;

  ZKN_CHECK(cx_bn_unlock());
  bn_locked = false;

  return io_send_response_pointer(out, sizeof(out), SW_OK);

  ZKN_ERROR_CLOSE_SEND();

  if (point_alloced)
    tEdwards_destroy(&curve, &R);
  if (curve_alloced)
  {
    tEdwards_Curve_partial_destroy(&curve);
    (void)cx_bn_destroy(&curve.modulus);
  }
  if (bn_locked)
    cx_bn_unlock();

  return io_send_sw(error);
}

int handler_scalar_mul_fixed_base_msm4(buffer_t *cdata)
{
  ZKN_ERROR_INIT();

  if (cdata->size != 33)
    return io_send_sw(SW_WRONG_DATA_LENGTH);

  uint32_t curveID = cdata->ptr[0];
  uint8_t k[32];
  memcpy(k, cdata->ptr + 1, 32);

  uint8_t out[64];
  bool bn_locked = false;
  bool curve_alloced = false;
  bool point_alloced = false;

  zkn_edcurve_t curve;
  zkn_edpoint_t R;

  ZKN_CHECK(cx_bn_lock(32, 0));
  bn_locked = true;

  ZKN_CHECK(tEdwards_Curve_alloc_init(&curve, curveID));
  curve_alloced = true;

  ZKN_CHECK(tEdwards_alloc(&curve, &R));
  point_alloced = true;

  ZKN_CHECK(tEdwards_fixedBase_4MSM(&curve, k, &R));

  uint8_t rx[32], ry[32];
  ZKN_CHECK(tEdwards_export(&curve, &R, rx, ry));

  for (size_t i = 0; i < 32; i++)
  {
    out[i] = rx[i];
    out[32 + i] = ry[i];
  }

  ZKN_CHECK(tEdwards_destroy(&curve, &R));
  point_alloced = false;

  ZKN_CHECK(tEdwards_Curve_partial_destroy(&curve));
  ZKN_CHECK(cx_bn_destroy(&curve.modulus));
  curve_alloced = false;

  ZKN_CHECK(cx_bn_unlock());
  bn_locked = false;

  return io_send_response_pointer(out, sizeof(out), SW_OK);

  ZKN_ERROR_CLOSE_SEND();

  if (point_alloced)
    tEdwards_destroy(&curve, &R);
  if (curve_alloced)
  {
    tEdwards_Curve_partial_destroy(&curve);
    (void)cx_bn_destroy(&curve.modulus);
  }
  if (bn_locked)
    cx_bn_unlock();

  return io_send_sw(error);
}
