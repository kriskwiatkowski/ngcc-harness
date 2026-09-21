/*
 * Hint statistics for BiT-128 (q=26881, N=256, K=2, L=3, GAMMA2=1024)
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../params.h"
#include "../polyvec.h"
#include "../poly.h"
#include "../packing.h"
#include "../sample.h"
#include "../symmetric.h"
#include "../drng.h"

#define MAX_ITER  100000
#define HMAX      40

static long cnt_total, cnt_z01, cnt_z2, cnt_hb, cnt_norm, cnt_hint_range, cnt_ok;
static long reached_hint;
static long h_abs_hist[HMAX+2];
static long h_max_hist[HMAX+2];
static long esc_hist[500];  /* escape count (|h|>=2) distribution */
static long esc_max;
static long z1_hist[50]; /* bucket=128 */

/* signed hint histogram: index = value+6, covers -6..+6 */
#define SHIFT 6
static long h_signed_hist[2*SHIFT+1];

#define MAX_CROSS 64
static long maxh_cross_dist[HMAX+2][MAX_CROSS+2];

static void collect(const polyveck *h, const polyvecm1 *z1) {
    int maxh = 0;
    for (int i = 0; i < BIT_K; i++)
        for (int j = 0; j < BIT_N; j++) {
            int v = h->vec[i].coeffs[j];
            /* signed histogram -6..+6 */
            if (v >= -SHIFT && v <= SHIFT) h_signed_hist[v + SHIFT]++;
            int av = v;
            if (av < 0) av = -av;
            if (av <= HMAX) h_abs_hist[av]++;
            else            h_abs_hist[HMAX+1]++;
            if (av > maxh) maxh = av;
        }
    if (maxh <= HMAX) h_max_hist[maxh]++;
    else              h_max_hist[HMAX+1]++;

    /* count escapes: |h| >= 2 */
    int esc_cnt = 0;
    for (int i = 0; i < BIT_K; i++)
        for (int j = 0; j < BIT_N; j++) {
            int av = h->vec[i].coeffs[j];
            if (av < 0) av = -av;
            if (av >= 2) esc_cnt++;
        }
    if (esc_cnt < 500) esc_hist[esc_cnt]++;
    if (esc_cnt > esc_max) esc_max = esc_cnt;

    int cnt_at_max = 0;
    for (int i = 0; i < BIT_K; i++)
        for (int j = 0; j < BIT_N; j++) {
            int av = h->vec[i].coeffs[j];
            if (av < 0) av = -av;
            if (av == maxh) cnt_at_max++;
        }
    {
        int cidx = maxh <= HMAX ? maxh : HMAX+1;
        int bidx = cnt_at_max <= MAX_CROSS ? cnt_at_max : MAX_CROSS+1;
        maxh_cross_dist[cidx][bidx]++;
    }

    int32_t mx = 0;
    for (int i = 0; i < BIT_L+1; i++)
        for (int j = 0; j < BIT_N; j++) {
            int32_t v = z1->vec[i].coeffs[j];
            if (v < 0) v = -v;
            if (v > mx) mx = v;
        }
    int b = mx / 128;
    if (b >= 50) b = 49;
    z1_hist[b]++;
}

static void report(void) {
    if (!cnt_total) return;
    printf("\n========== Hint Statistics (%ld iterations) ==========\n", cnt_total);
    printf("Parameters: q=%d N=%d K=%d L=%d TAU=%d BETA=%d\n",
           BIT_Q, BIT_N, BIT_K, BIT_L, BIT_TAU, BIT_BETA);
    printf("            GAMMA1=%d GAMMA2=%d B_INF=%d\n",
           BIT_GAMMA1, BIT_GAMMA2, BIT_B_INF);

    printf("\n-- Rejection breakdown --\n");
    printf("  z0z1          : %6ld  (%5.1f%%)\n", cnt_z01,      100.*cnt_z01/cnt_total);
    printf("  z2            : %6ld  (%5.1f%%)\n", cnt_z2,       100.*cnt_z2/cnt_total);
    printf("  highbits      : %6ld  (%5.1f%%)\n", cnt_hb,       100.*cnt_hb/cnt_total);
    printf("  norm          : %6ld  (%5.1f%%)\n", cnt_norm,     100.*cnt_norm/cnt_total);
    printf("  hint_range    : %6ld  (%5.1f%%)\n", cnt_hint_range,100.*cnt_hint_range/cnt_total);
    printf("  SUCCESS       : %6ld  (%5.1f%%)",  cnt_ok,       100.*cnt_ok/cnt_total);
    if (cnt_ok > 0) printf("  avg %5.1f iters/sig", (double)cnt_total/cnt_ok);
    printf("\n");

    long h_total = 0;
    for (int v = 0; v <= HMAX+1; v++) h_total += h_abs_hist[v];
    if (h_total) {
        printf("\n-- Hint |h| distribution --\n");
        printf("  |h|    count   pct       cum\n");
        long cum = 0;
        for (int v = 0; v <= HMAX+1; v++) {
            if (!h_abs_hist[v]) continue;
            cum += h_abs_hist[v];
            printf("  %2d   %8ld  %5.2f%%  %5.1f%%\n",
                   v, h_abs_hist[v], 100.*h_abs_hist[v]/h_total, 100.*cum/h_total);
        }

        printf("\n-- Hint signed distribution (-6..+6) --\n");
        printf("  val   count   pct       cum\n");
        cum = 0;
        for (int v = -SHIFT; v <= SHIFT; v++) {
            long n = h_signed_hist[v + SHIFT];
            if (!n) continue;
            cum += n;
            printf("  %3d  %8ld  %5.2f%%  %5.1f%%\n",
                   v, n, 100.*n/h_total, 100.*cum/h_total);
        }
    }

    printf("\n-- Max |h| per attempt --\n");
    for (int v = 0; v <= HMAX+1; v++)
        if (h_max_hist[v])
            printf("  max|h|=%d: %6ld  (%5.1f%%)\n",
                   v, h_max_hist[v], 100.*h_max_hist[v]/reached_hint);

    printf("\n-- Escape count (|h|>=2) distribution (OV_MAX=%d) --\n", BIT_H_OVERFLOW_MAX);
    printf("  max observed = %ld\n", esc_max);
    for (int e = 0; e < 500; e++) {
        if (!esc_hist[e]) continue;
        printf("  %3d escapes: %6ld\n", e, esc_hist[e]);
    }

    printf("\n-- Coeffs-at-max-|h| per attempt --\n");
    for (int mh = 0; mh <= HMAX+1; mh++) {
        int any = 0;
        for (int c = 0; c <= MAX_CROSS+1; c++)
            if (maxh_cross_dist[mh][c]) { any = 1; break; }
        if (!any) continue;
        printf("  max|h|=%d:\n", mh);
        for (int c = 0; c <= MAX_CROSS+1; c++) {
            long n = maxh_cross_dist[mh][c];
            if (!n) continue;
            if (c == 0) printf("    none at max  : %6ld\n", n);
            else if (c <= MAX_CROSS) printf("    %2d at max     : %6ld\n", c, n);
            else printf("    >%d at max    : %6ld\n", MAX_CROSS, n);
        }
    }

    printf("\n-- z1 max-norm distribution (bucket=128, B_INF=%d) --\n", BIT_B_INF);
    for (int b = 0; b < 50; b++)
        if (z1_hist[b])
            printf("  [%4d,%4d): %6ld\n", b*128, (b+1)*128, z1_hist[b]);
    printf("\n");
}

int main(void) {
    printf("BiT-128 Hint Statistics Collector\n");
    printf("========================================\n");

    for (int kp = 0; kp < 1; kp++) {
        unsigned char seed_A[BIT_SEEDBYTES], sec[BIT_SEEDBYTES], tr[BIT_TRBYTES];
        poly_matrix_ntt A; polyvecl_ntt s0ntt; polyvecl s0;
        polyveck e, b, b1, b0;
        uint16_t n = 0;
        get_random_number(&test_rng, seed_A, BIT_SEEDBYTES*8ULL); get_random_number(&test_rng, sec, BIT_SEEDBYTES*8ULL);
        polyvecl_sample_S1(&s0, sec, &n); polyveck_sample_S1(&e, sec, &n);
        poly_matrix_expand_ntt(&A, seed_A); polyvecl_to_ntt(&s0ntt, &s0);
        poly_matrix_mul_vector_ntt(&b, &A, &s0ntt); polyveck_add_eta1(&b, &b, &e);
        polyveck_decompose_b(&b1, &b0, &b);
        unsigned char pk[BIT_PUBLICKEYBYTES], sk[BIT_SECRETKEYBYTES];
        pack_pk(pk, seed_A, &b1); bit_h256(tr, pk, BIT_PUBLICKEYBYTES);
        pack_sk(sk, seed_A, &b1, sec, tr, &s0, &e, &b0);

        unsigned char m[64] = {0x42};
        unsigned char msg_hash[BIT_MESSAGEBYTES];
        bit_h256_2(msg_hash, tr, BIT_TRBYTES, m, 64);
        unsigned char hi[BIT_MESSAGEBYTES + BIT_POLYVECK_W1_BYTES];
        memcpy(hi, msg_hash, BIT_MESSAGEBYTES);
        unsigned char rnd[BIT_SEEDBYTES], tsy[BIT_SEEDBYTES];
        get_random_number(&test_rng, rnd, BIT_SEEDBYTES*8ULL);
        bit_xof256_3(tsy, BIT_SEEDBYTES, sec, BIT_SEEDBYTES,
                     rnd, BIT_SEEDBYTES, msg_hash, BIT_MESSAGEBYTES);

        unsigned char sa2[BIT_SEEDBYTES], sc2[BIT_SEEDBYTES], tr2[BIT_TRBYTES];
        polyveck b1s, es, b0s; polyvecl s0s;
        unpack_sk(sa2, &b1s, sc2, tr2, &s0s, &es, &b0s, sk);
        poly_matrix_expand_ntt(&A, sa2);
        polyveck_ntt b1ntt; polyveck_b1_scaled_to_ntt(&b1ntt, &b1s);

        polyvecy y; uint16_t ny = 0;
        polyvecy_sample_triangular(&y, tsy, &ny);
        polyvecl_ntt y1ntt; poly_ntt y0ntt;
        polyveck w, w1, ce, z2, h, b0c; polyvecl cs;
        poly cp; sparse_challenge cs2; polyvecm1 z1; polyvecy z;

        for (int iter = 0; iter < MAX_ITER; iter++) {
            cnt_total++;
            polyvecy_y1_to_ntt(&y1ntt, &y); poly_to_ntt(&y0ntt, &y.vec[0]);
            polyveck_compute_w_ntt(&w, &A, &b1ntt, &y1ntt, &y0ntt, &y);
            polyveck_highbits(&w1, &w);
            polyveck_pack_w1(hi + BIT_MESSAGEBYTES, &w1);
            unsigned char ch[BIT_CHALLENGEBYTES];
            bit_h256(ch, hi, sizeof(hi));
            unsigned char bc; get_random_number(&test_rng, &bc, 1*8ULL); uint8_t bv = bc & 1;
            poly_challenge(&cp, ch); poly_cneg(&cp, bv);
            poly_challenge_to_sparse(&cs2, &cp);
            polyvecl_mul_challenge_no_reduce(&cs, &s0s, &cs2);
            poly_add(&z.vec[0], &y.vec[0], &cp);
            for (int i = 0; i < BIT_L; i++)
                poly_add(&z.vec[1+i], &y.vec[1+i], &cs.vec[i]);
            if (check_reject_sample_z0z1(&z, &cs, &cp, &cs2, tsy, &ny)) {
                cnt_z01++; polyvecy_sample_y0(&y, tsy, &ny);
                polyvecy_sample_y1(&y, tsy, &ny); continue;
            }
            polyveck_mul_challenge_no_reduce(&ce, &es, &cs2);
            for (int i = 0; i < BIT_K; i++)
                poly_add(&z.vec[1+BIT_L+i], &y.vec[1+BIT_L+i], &ce.vec[i]);
            if (check_reject_sample_z2(&z, &ce, tsy, &ny)) {
                cnt_z2++; polyvecy_sample_triangular(&y, tsy, &ny); continue;
            }
            if (check_reject_highbits_w1_sparse(&w1.vec[0], &w.vec[0], &cs2)) {
                cnt_hb++; polyvecy_sample_triangular(&y, tsy, &ny); continue;
            }
            for (int i = 0; i < BIT_L+1; i++) z1.vec[i] = z.vec[i];
            for (int i = 0; i < BIT_K; i++) z2.vec[i] = z.vec[1+BIT_L+i];
            polyveck_mul_challenge_no_reduce(&b0c, &b0s, &cs2);
            polyveck_make_hint_compressed(&h, &w1, &w, &z2, &b0c, &cp, bv);
            reached_hint++;
            collect(&h, &z1);
            if (check_reject_norm(&z1, &h)) {
                cnt_norm++; polyvecy_sample_triangular(&y, tsy, &ny); continue;
            }
            if (check_reject_hint_range(&h)) {
                cnt_hint_range++; polyvecy_sample_triangular(&y, tsy, &ny); continue;
            }
            cnt_ok++;
            polyvecy_sample_triangular(&y, tsy, &ny);
        }
    }
    report();
    return 0;
}
