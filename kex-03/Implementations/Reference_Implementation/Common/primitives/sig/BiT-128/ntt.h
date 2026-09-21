#ifndef BIT_NTT_H
#define BIT_NTT_H

#include <stdint.h>
#include "params.h"

void ntt_forward(int16_t a[BIT_N]);
void ntt_inverse(int16_t a[BIT_N]);
void ntt_pointwise_mul_raw(int16_t r[BIT_N], const int16_t a[BIT_N], const int16_t b[BIT_N]);
void ntt_pointwise_acc_raw(int16_t r[BIT_N], const int16_t a[BIT_N], const int16_t b[BIT_N]);
void ntt_montgomery_lift(int16_t r[BIT_N]);

#include "reduce.h"

#endif
