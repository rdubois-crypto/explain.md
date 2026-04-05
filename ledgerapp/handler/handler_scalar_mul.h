// handler_scalar_mul.h
// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX
//
// Scalar multiplication APDU handlers (variable base, fixed base, MSM).

#ifndef _HANDLER_SCALAR_MUL_H
#define _HANDLER_SCALAR_MUL_H

#include <stdint.h>
#include "buffer.h"

// SCALAR_MUL_VARIABLE_BASE (0x31) — variable base scalar multiplication
int handler_scalar_mul_variable_base(buffer_t *cdata);

// SCALAR_MUL_FIXED_BASE (0x32) — fixed base scalar multiplication
int handler_scalar_mul_fixed_base(buffer_t *cdata);

// SCALAR_MUL_FIXED_BASE_MSM2 (0x33) — fixed base 2-MSM scalar multiplication
int handler_scalar_mul_fixed_base_msm2(buffer_t *cdata);

#ifdef RAILGUN
// SCALAR_MUL_FIXED_BASE_MSM4 (0x34) — fixed base 4-MSM scalar multiplication
int handler_scalar_mul_fixed_base_msm4(buffer_t *cdata);
#endif

#endif
