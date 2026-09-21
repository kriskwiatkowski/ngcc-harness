/*
 * test_reject_stats.c  —  rejection-sampling statistics harness (REFERENCE only).
 *
 * Stand-alone copy of the signing trajectory (bit_sig_sign) instrumented to
 * tally rejections.  It does NOT touch the core sources: it re-implements the
 * two static per-polynomial reject deciders (reject_sample_coeffs /
 * _sparse, copied verbatim from sample.c) and the sign loop, and calls the
 * public core functions for everything else.
 *
 * Why a copy: the production check_reject_sample_z0z1() lumps z0 and z1 together
 * and short-circuits on the first reject.  Here every stage (z0, z1, z2, and the
 * later highbits / norm / hint checks) is evaluated *independently* and counted
 * on its own, while the control flow (nonce advance, resample-on-reject, accept
 * condition) is kept byte-identical to the real signer so the measured rates are
 * representative.  KAT is identical between ref and AVX2, so ref suffices.
 *
 * Portable across BiT-128/256/512: the deciders take `const poly *` so the
 * int16 (128) vs int32 (256/512) coefficient type is handled transparently.
 *
 * Build:   make reject-stats         (or see Makefile target)
 * Run:     ./test_reject_stats [num_signatures]      (default 50000)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "sample.h"
#include "packing.h"
#include "sign.h"
#include "symmetric.h"
#include "endian.h"
#include "drng.h"

/* The signature scheme pulls randomness from this global (extern in sign.c). */
DRNG_ctx drng_algorithm;

/* ---- constants copied from sample.c (kept in lock-step with the core) ---- */
#if BIT_USE_SHAKE
#define RS_SQUEEZE_BYTES BIT_XOF256_RATE
#else
#define RS_SQUEEZE_BYTES 136
#endif
#define RS_TWO_POW_24 16777216ULL

/* ---- statistics ---------------------------------------------------------- */
typedef struct {
    uint64_t signs;          /* completed signatures                         */
    uint64_t fails;          /* signatures that hit BIT_SIGN_MAX_ITERS       */
    uint64_t iters;          /* total loop iterations (== z0z1 evaluations)  */
    uint64_t z0_rej, z1_rej; /* iterations in which z0 / z1 rejected         */
    uint64_t z2_reached, z2_rej;
    uint64_t hb_reached, hb_rej;     /* HighBits(w1) check                   */
    uint64_t norm_reached, norm_rej; /* ||z||_inf / hint norm check          */
    uint64_t hint_reached, hint_rej; /* hint range check                     */
} stat_t;

/* ===========================================================================
 *  Per-polynomial reject deciders — verbatim copies of the static functions in
 *  sample.c, except `v` is passed as a poly* so one body serves int16/int32.
 * ========================================================================= */
static int stat_rej_coeffs(const poly *z, const poly *vp,
                           int32_t gamma1, int32_t beta2, bit_xof256_state *st) {
    uint8_t r_buf[RS_SQUEEZE_BYTES];
    const int32_t fast_lo = beta2, fast_hi = gamma1 - beta2;
    const int32_t G_fast = 2 * (gamma1 - beta2);
    size_t buf_len = 0, pos = sizeof(r_buf);
    uint32_t reject = 0;

    for (int j = 0; j < BIT_N; j++) {
        int32_t val = ct_abs(z->coeffs[j]);
        int32_t beta1_i = ct_abs(vp->coeffs[j]);

        if (val >= fast_lo && val < fast_hi) continue;
        if ((uint32_t)(val >= gamma1)) { reject = 1; continue; }

        if (pos + 3 > buf_len) {
            bit_xof256_squeeze(st, r_buf, sizeof(r_buf));
            buf_len = sizeof(r_buf);
            pos = 0;
        }
        uint32_t R = load24_le(r_buf + pos);
        pos += 3;

        if (val < beta2) {
            int32_t F_int = 2 * gamma1 - 2 * ct_max(val, beta1_i);
            if ((uint64_t)R * F_int > (uint64_t)G_fast * RS_TWO_POW_24) reject = 1;
        } else {
            int32_t f_minus = ct_max(gamma1 - ct_abs(val - beta1_i), 0);
            int32_t f_plus  = ct_max(gamma1 - (val + beta1_i), 0);
            int32_t F_int = f_minus + f_plus;
            int32_t G_int = 2 * ct_max(gamma1 - ct_max(val, beta2), 0);
            if ((uint64_t)R * F_int > (uint64_t)G_int * RS_TWO_POW_24) reject = 1;
        }
    }
    return (int)reject;
}

static int stat_rej_coeffs_sparse(const poly *z, const sparse_challenge *support,
                                  const poly *vp, int32_t gamma1, int32_t beta2,
                                  bit_xof256_state *st) {
    uint8_t r_buf[RS_SQUEEZE_BYTES];
    const int32_t fast_lo = beta2, fast_hi = gamma1 - beta2;
    const int32_t G_fast = 2 * (gamma1 - beta2);
    size_t buf_len = 0, pos = sizeof(r_buf);
    uint32_t reject = 0;

    for (int t = 0; t < BIT_TAU; t++) {
        int j = support->pos[t];
        int32_t val = ct_abs(z->coeffs[j]);
        int32_t beta1_i = ct_abs(vp->coeffs[j]);

        if (val >= fast_lo && val < fast_hi) continue;
        if ((uint32_t)(val >= gamma1)) { reject = 1; continue; }

        if (pos + 3 > buf_len) {
            bit_xof256_squeeze(st, r_buf, sizeof(r_buf));
            buf_len = sizeof(r_buf);
            pos = 0;
        }
        uint32_t R = load24_le(r_buf + pos);
        pos += 3;

        if (val < beta2) {
            int32_t F_int = 2 * gamma1 - 2 * ct_max(val, beta1_i);
            if ((uint64_t)R * F_int > (uint64_t)G_fast * RS_TWO_POW_24) reject = 1;
        } else {
            int32_t f_minus = ct_max(gamma1 - ct_abs(val - beta1_i), 0);
            int32_t f_plus  = ct_max(gamma1 - (val + beta1_i), 0);
            int32_t F_int = f_minus + f_plus;
            int32_t G_int = 2 * ct_max(gamma1 - ct_max(val, beta2), 0);
            if ((uint64_t)R * F_int > (uint64_t)G_int * RS_TWO_POW_24) reject = 1;
        }
    }
    return (int)reject;
}

/* ===========================================================================
 *  Instrumented sign trajectory — a copy of bit_sig_sign with the z0/z1/z2
 *  reject checks split apart and counted independently (no short-circuit).
 *  Control flow / nonce management are identical to the production signer.
 * ========================================================================= */
static int stat_sign(const unsigned char *sk, const unsigned char *m,
                     size_t mlen, stat_t *S) {
    unsigned char seed_A[BIT_SEEDBYTES], secret_seed[BIT_SEEDBYTES];
    unsigned char tr[BIT_TRBYTES], message_hash[BIT_MESSAGEBYTES];
    unsigned char rnd[BIT_SEEDBYTES], temp_seed_y[BIT_SEEDBYTES];
    unsigned char b_batch[32];
    size_t b_bit_pos;

    poly_matrix_ntt A_0_ntt;
    polyvecl s_0, c_s;
    polyvecl_ntt y1_ntt;
    polyveck_ntt b1_ntt;
    poly_ntt y0_ntt;
    polyveck e, b1, b0, c_e, b0c;
    polyvecy y, z;
    polyveck w, w1, z2, h;
    polyvecm1 z1;
    poly c_poly;
    sparse_challenge c_sparse;

    unpack_sk(seed_A, &b1, secret_seed, tr, &s_0, &e, &b0, sk);
    poly_matrix_expand_ntt(&A_0_ntt, seed_A);
    polyveck_b1_scaled_to_ntt(&b1_ntt, &b1);

    bit_h256_2(message_hash, tr, BIT_TRBYTES, m, mlen);
    unsigned char hash_input[BIT_MESSAGEBYTES + BIT_POLYVECK_W1_BYTES];
    memcpy(hash_input, message_hash, BIT_MESSAGEBYTES);

    if (get_random_number(&drng_algorithm, rnd, BIT_SEEDBYTES * 8ULL) != 0) return -1;
    bit_xof256_3(temp_seed_y, BIT_SEEDBYTES, secret_seed, BIT_SEEDBYTES,
                 rnd, BIT_SEEDBYTES, message_hash, BIT_MESSAGEBYTES);

    uint16_t nonce_y = 0;
    polyvecy_sample_triangular(&y, temp_seed_y, &nonce_y);
    b_bit_pos = sizeof(b_batch) * 8;

    uint32_t sign_iter = 0;
    while (1) {
        if (++sign_iter > BIT_SIGN_MAX_ITERS) { S->fails++; return -1; }
        S->iters++;

        polyvecy_y1_to_ntt(&y1_ntt, &y);
        poly_to_ntt(&y0_ntt, &y.vec[0]);
        polyveck_compute_w_ntt(&w, &A_0_ntt, &b1_ntt, &y1_ntt, &y0_ntt, &y);

        polyveck_highbits(&w1, &w);
        polyveck_pack_w1(hash_input + BIT_MESSAGEBYTES, &w1);
        unsigned char challenge[BIT_CHALLENGEBYTES];
        bit_h256(challenge, hash_input, sizeof(hash_input));

        if (b_bit_pos >= sizeof(b_batch) * 8) {
            if (get_random_number(&drng_algorithm, b_batch,
                                  (unsigned long long)sizeof(b_batch) * 8ULL) != 0) return -1;
            b_bit_pos = 0;
        }
        uint8_t b_val = (uint8_t)((b_batch[b_bit_pos >> 3] >> (b_bit_pos & 7)) & 1U);
        b_bit_pos++;

        poly_challenge(&c_poly, challenge);
        poly_cneg(&c_poly, b_val);
        poly_challenge_to_sparse(&c_sparse, &c_poly);

        /* ---- z0 + z1 (split, no short-circuit) ----------------------- */
        polyvecl_mul_challenge_no_reduce(&c_s, &s_0, &c_sparse);
        poly_add(&z.vec[0], &y.vec[0], &c_poly);
        for (int i = 0; i < BIT_L; i++)
            poly_add(&z.vec[1 + i], &y.vec[1 + i], &c_s.vec[i]);

        int z1_rej = 0, z0_rej = 0;
        for (int i = 1; i <= BIT_L; i++) {          /* z1[0..L-1] = vec[1..L] */
            bit_xof256_state st;
            bit_xof256_init(&st, temp_seed_y, BIT_SEEDBYTES, (uint16_t)(nonce_y + i));
            if (stat_rej_coeffs(&z.vec[i], &c_s.vec[i - 1], BIT_GAMMA1, BIT_BETA, &st))
                z1_rej = 1;
            bit_xof256_zeroize(&st);
        }
        {                                            /* z0 = vec[0] (sparse)  */
            bit_xof256_state st0;
            bit_xof256_init(&st0, temp_seed_y, BIT_SEEDBYTES, (uint16_t)(nonce_y + 0));
            if (stat_rej_coeffs_sparse(&z.vec[0], &c_sparse, &c_poly,
                                       BIT_GAMMA1_0, 1, &st0))
                z0_rej = 1;
            bit_xof256_zeroize(&st0);
        }
        nonce_y = (uint16_t)(nonce_y + 4U);
        if (z0_rej) S->z0_rej++;
        if (z1_rej) S->z1_rej++;
        if (z0_rej || z1_rej) {
            polyvecy_sample_y0(&y, temp_seed_y, &nonce_y);
            polyvecy_sample_y1(&y, temp_seed_y, &nonce_y);
            continue;
        }

        /* ---- z2 (split, no short-circuit) --------------------------- */
        polyveck_mul_challenge_no_reduce(&c_e, &e, &c_sparse);
        for (int i = 0; i < BIT_K; i++)
            poly_add(&z.vec[1 + BIT_L + i], &y.vec[1 + BIT_L + i], &c_e.vec[i]);

        int z2_rej = 0;
        for (int i = BIT_L + 1; i < BIT_Y; i++) {    /* z2[0..K-1] = vec[L+1..] */
            bit_xof256_state st;
            bit_xof256_init(&st, temp_seed_y, BIT_SEEDBYTES,
                            (uint16_t)(nonce_y + (i - BIT_L - 1)));
            if (stat_rej_coeffs(&z.vec[i], &c_e.vec[i - BIT_L - 1],
                                BIT_GAMMA1_2, BIT_BETA, &st))
                z2_rej = 1;
            bit_xof256_zeroize(&st);
        }
        nonce_y = (uint16_t)(nonce_y + (uint16_t)BIT_K);
        S->z2_reached++;
        if (z2_rej) S->z2_rej++;
        if (z2_rej) { polyvecy_sample_triangular(&y, temp_seed_y, &nonce_y); continue; }

        /* ---- later deterministic checks ----------------------------- */
        S->hb_reached++;
        if (check_reject_highbits_w1_sparse(&w1.vec[0], &w.vec[0], &c_sparse)) {
            S->hb_rej++;
            polyvecy_sample_triangular(&y, temp_seed_y, &nonce_y);
            continue;
        }

        for (int i = 0; i < BIT_L + 1; i++) z1.vec[i] = z.vec[i];
        for (int i = 0; i < BIT_K; i++)     z2.vec[i] = z.vec[1 + BIT_L + i];

        polyveck_mul_challenge_no_reduce(&b0c, &b0, &c_sparse);
        polyveck_make_hint_compressed(&h, &w1, &w, &z2, &b0c, &c_poly, b_val);

        S->norm_reached++;
        if (check_reject_norm(&z1, &h)) {
            S->norm_rej++;
            polyvecy_sample_triangular(&y, temp_seed_y, &nonce_y);
            continue;
        }

        S->hint_reached++;
        if (check_reject_hint_range(&h)) {
            S->hint_rej++;
            polyvecy_sample_triangular(&y, temp_seed_y, &nonce_y);
            continue;
        }

        break;   /* accepted */
    }
    S->signs++;
    return 0;
}

/* ===========================================================================
 *  Driver
 * ========================================================================= */
static void pct(const char *name, uint64_t rej, uint64_t reached) {
    double r = reached ? 100.0 * (double)rej / (double)reached : 0.0;
    printf("  %-9s: %10llu / %-10llu = %7.4f %%\n",
           name, (unsigned long long)rej, (unsigned long long)reached, r);
}

int main(int argc, char **argv) {
    long N = (argc > 1) ? atol(argv[1]) : 50000;
    if (N < 1) N = 1;

    /* Deterministic DRNG seed for reproducibility. */
    unsigned char seed[64];
    for (size_t i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)(0x5A ^ i);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "DRNG init failed\n");
        return 2;
    }

    unsigned long long pk_len = BIT_PUBLICKEYBYTES, sk_len = BIT_SECRETKEYBYTES;
    unsigned char *pk = malloc(BIT_PUBLICKEYBYTES);
    unsigned char *sk = malloc(BIT_SECRETKEYBYTES);
    unsigned char m[BIT_MESSAGEBYTES];
    if (!pk || !sk) { fprintf(stderr, "alloc failed\n"); return 2; }

    stat_t S; memset(&S, 0, sizeof(S));

    for (long it = 0; it < N; it++) {
        /* fresh key + distinct message each round → representative average */
        pk_len = BIT_PUBLICKEYBYTES; sk_len = BIT_SECRETKEYBYTES;
        if (bit_sig_keygen(pk, &pk_len, sk, &sk_len) != 0) {
            fprintf(stderr, "keygen failed at %ld\n", it);
            return 2;
        }
        memset(m, 0, sizeof(m));
        memcpy(m, &it, sizeof(it) < sizeof(m) ? sizeof(it) : sizeof(m));
        stat_sign(sk, m, sizeof(m), &S);
    }

    uint64_t rej_iters = (S.iters >= S.signs) ? (S.iters - S.signs) : 0;
    double avg_iter = S.signs ? (double)S.iters / (double)S.signs : 0.0;

    printf("================================================================\n");
#ifdef BIT_LEVEL_NAME
    printf("BiT reject statistics  [%s]  (ref, %s route)\n", BIT_LEVEL_NAME,
           BIT_USE_SHAKE ? "SHAKE" : "SM3");
#else
    printf("BiT reject statistics  (ref, %s route)  N=%ld\n",
           BIT_USE_SHAKE ? "SHAKE" : "SM3", N);
#endif
    printf("----------------------------------------------------------------\n");
    printf("  signatures      : %llu  (failed: %llu)\n",
           (unsigned long long)S.signs, (unsigned long long)S.fails);
    printf("  total iterations: %llu\n", (unsigned long long)S.iters);
    printf("  rejected iters  : %llu   (overall %.4f %% per iteration)\n",
           (unsigned long long)rej_iters,
           S.iters ? 100.0 * (double)rej_iters / (double)S.iters : 0.0);
    printf("  avg iters / sign: %.4f\n", avg_iter);
    printf("----------------------------------------------------------------\n");
    printf("  per-stage reject rate (rejections / times stage reached):\n");
    pct("z0", S.z0_rej, S.iters);          /* z0 evaluated every iteration   */
    pct("z1", S.z1_rej, S.iters);          /* z1 evaluated every iteration   */
    pct("z2", S.z2_rej, S.z2_reached);     /* z2 only if z0z1 passed         */
    pct("highbits", S.hb_rej, S.hb_reached);
    pct("norm", S.norm_rej, S.norm_reached);
    pct("hint", S.hint_rej, S.hint_reached);
    printf("================================================================\n");
    free(pk); free(sk);
    return 0;
}
