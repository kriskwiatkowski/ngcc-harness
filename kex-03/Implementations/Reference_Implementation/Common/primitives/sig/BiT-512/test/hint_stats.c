#include "../drng.h"
static DRNG_ctx test_rng;
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../params.h"
#include "../polyvec.h"
#include "../poly.h"
#include "../sample.h"
#include "../symmetric.h"
#include "../drng.h"

#define MAX_ITER 30000
#define HMAX 40
#define SHIFT 6

static long cnt_total,cnt_z01,cnt_z2,cnt_hb,cnt_norm,cnt_hint_range,cnt_ok,reached_hint;
static long h_abs_hist[HMAX+2],h_max_hist[HMAX+2],esc_hist[2000],esc_max;
static long h_signed_hist[2*SHIFT+1];

static void collect(const polyveck *h){
    int maxh=0;
    for(int i=0;i<BIT_K;i++) for(int j=0;j<BIT_N;j++){
        int v=h->vec[i].coeffs[j];
        if(v>=-SHIFT&&v<=SHIFT)h_signed_hist[v+SHIFT]++;
        int av=v<0?-v:v;
        if(av<=HMAX)h_abs_hist[av]++;else h_abs_hist[HMAX+1]++;
        if(av>maxh)maxh=av;
    }
    if(maxh<=HMAX)h_max_hist[maxh]++;else h_max_hist[HMAX+1]++;
    int ec=0;
    for(int i=0;i<BIT_K;i++) for(int j=0;j<BIT_N;j++){int av=h->vec[i].coeffs[j];if(av<0)av=-av;if(av>=2)ec++;}
    if(ec<2000)esc_hist[ec]++; if(ec>esc_max)esc_max=ec;
}
static void report(void){
    if(!cnt_total)return;
    printf("\n===== BiT-512 Hint Stats (%ld iter) =====\n",cnt_total);
    printf("q=%d N=%d K=%d L=%d TAU=%d BETA=%d G1=%d G12=%d G2=%d BINF=%d AH=%d\n",
        BIT_Q,BIT_N,BIT_K,BIT_L,BIT_TAU,BIT_BETA,BIT_GAMMA1,BIT_GAMMA1_2,BIT_GAMMA2,BIT_B_INF,ALPHA_HINT);
    printf("z0z1:%ld(%.1f%%) z2:%ld(%.1f%%) hb:%ld(%.1f%%) norm:%ld(%.1f%%) hr:%ld SUCC:%ld(%.1f%%)\n",
        cnt_z01,100.*cnt_z01/cnt_total,cnt_z2,100.*cnt_z2/cnt_total,cnt_hb,100.*cnt_hb/cnt_total,
        cnt_norm,100.*cnt_norm/cnt_total,cnt_hint_range,cnt_ok,100.*cnt_ok/cnt_total);
    long ht=0;for(int v=0;v<=HMAX+1;v++)ht+=h_abs_hist[v];
    if(ht){printf("\n-- |h| distribution --\n");
        long cum=0;for(int v=0;v<=HMAX+1;v++){if(!h_abs_hist[v])continue;cum+=h_abs_hist[v];
        printf(" %2d %8ld %5.2f%% %5.1f%%\n",v,h_abs_hist[v],100.*h_abs_hist[v]/ht,100.*cum/ht);}
        printf("\n-- Signed --\n");cum=0;
        for(int v=-SHIFT;v<=SHIFT;v++){long n=h_signed_hist[v+SHIFT];if(!n)continue;cum+=n;
        printf(" %3d %8ld %5.2f%% %5.1f%%\n",v,n,100.*n/ht,100.*cum/ht);}}
    printf("\n-- Max|h| per attempt --\n");
    for(int v=0;v<=HMAX+1;v++)if(h_max_hist[v])printf(" max|h|=%d: %ld (%.1f%%)\n",v,h_max_hist[v],100.*h_max_hist[v]/reached_hint);
    printf("\n-- Escape count max=%ld --\n",esc_max);
    for(int e=0;e<2000;e++)if(esc_hist[e])printf(" %d:%ld\n",e,esc_hist[e]);
}
int main(void){
    printf("BiT-512 Hint Stats\n");
    unsigned char sd[16]={0x42}; init_random_number(&test_rng, sd,16);
    unsigned char sA[BIT_SEEDBYTES],sc[BIT_SEEDBYTES],tr[BIT_TRBYTES];
    poly_matrix_ntt A;polyvecl_ntt s0ntt;polyvecl s0;polyveck e,b,b1,b0;uint16_t n=0;
    get_random_number(&test_rng, sA,BIT_SEEDBYTES);get_random_number(&test_rng, sc,BIT_SEEDBYTES);
    polyvecl_sample_S1(&s0,sc,&n);polyveck_sample_S1(&e,sc,&n);
    poly_matrix_expand_ntt(&A,sA);polyvecl_to_ntt(&s0ntt,&s0);
    poly_matrix_mul_vector_ntt(&b,&A,&s0ntt);polyveck_add_eta1(&b,&b,&e);
    polyveck_decompose_b(&b1,&b0,&b);
    unsigned char pk[BIT_PUBLICKEYBYTES],sk[BIT_SECRETKEYBYTES];
    pack_pk(pk,sA,&b1);bit_h256(tr,pk,BIT_PUBLICKEYBYTES);
    pack_sk(sk,sA,&b1,sc,tr,&s0,&e,&b0);
    unsigned char m[64]={0x42},mh[BIT_MESSAGEBYTES];
    bit_h256_2(mh,tr,BIT_TRBYTES,m,64);
    unsigned char rnd[BIT_SEEDBYTES],tsy[BIT_SEEDBYTES];
    get_random_number(&test_rng, rnd,BIT_SEEDBYTES);
    bit_xof256_3(tsy,BIT_SEEDBYTES,sc,BIT_SEEDBYTES,rnd,BIT_SEEDBYTES,mh,BIT_MESSAGEBYTES);
    unsigned char sa2[BIT_SEEDBYTES],sc2[BIT_SEEDBYTES],tr2[BIT_TRBYTES];
    polyveck b1s,es,b0s;polyvecl s0s;
    unpack_sk(sa2,&b1s,sc2,tr2,&s0s,&es,&b0s,sk);
    poly_matrix_expand_ntt(&A,sa2);polyveck_ntt b1ntt;polyveck_b1_scaled_to_ntt(&b1ntt,&b1s);
    polyvecy y,z;uint16_t ny=0;polyvecy_sample_triangular(&y,tsy,&ny);
    unsigned char hi[BIT_POLYVECK_W1_BYTES+BIT_MESSAGEBYTES];
    memset(hi,0,sizeof(hi));memcpy(hi+BIT_POLYVECK_W1_BYTES,mh,BIT_MESSAGEBYTES);
    polyvecl_ntt y1ntt;poly_ntt y0ntt;polyveck w,w1,ce,z2,h,b0c;polyvecl cs;
    poly cp;sparse_challenge cs2;polyvecm1 z1;
    for(int iter=0;iter<MAX_ITER;iter++){
        cnt_total++;
        polyvecy_y1_to_ntt(&y1ntt,&y);poly_to_ntt(&y0ntt,&y.vec[0]);
        polyveck_compute_w_ntt(&w,&A,&b1ntt,&y1ntt,&y0ntt,&y);
        polyveck_highbits(&w1,&w);polyveck_pack_w1(hi,&w1);
        unsigned char ch[BIT_CHALLENGEBYTES];bit_h256(ch,hi,sizeof(hi));
        unsigned char bc;get_random_number(&test_rng, &bc,1);uint8_t bv=bc&1;
        poly_challenge(&cp,ch);poly_cneg(&cp,bv);poly_challenge_to_sparse(&cs2,&cp);
        polyvecl_mul_challenge_no_reduce(&cs,&s0s,&cs2);
        polyveck_mul_challenge_no_reduce(&ce,&es,&cs2);
        poly_add(&z.vec[0],&y.vec[0],&cp);
        for(int i=0;i<BIT_L;i++)poly_add(&z.vec[1+i],&y.vec[1+i],&cs.vec[i]);
        for(int i=0;i<BIT_K;i++)poly_add(&z.vec[1+BIT_L+i],&y.vec[1+BIT_L+i],&ce.vec[i]);
        if(check_reject_sample_z0z1(&z,&cs,&cp,&cs2,tsy,&ny)){cnt_z01++;polyvecy_sample_y0(&y,tsy,&ny);polyvecy_sample_y1(&y,tsy,&ny);continue;}
        if(check_reject_sample_z2(&z,&ce,tsy,&ny)){cnt_z2++;polyvecy_sample_triangular(&y,tsy,&ny);continue;}
        if(check_reject_highbits_w1_sparse(&w1.vec[0],&w.vec[0],&cs2)){cnt_hb++;polyvecy_sample_triangular(&y,tsy,&ny);continue;}
        for(int i=0;i<BIT_L+1;i++)z1.vec[i]=z.vec[i];
        for(int i=0;i<BIT_K;i++)z2.vec[i]=z.vec[1+BIT_L+i];
        polyveck_mul_challenge_no_reduce(&b0c,&b0s,&cs2);
        polyveck_make_hint_compressed(&h,&w1,&w,&z2,&b0c,&cp,bv);
        reached_hint++;collect(&h);
        if(check_reject_norm(&z1,&h)){cnt_norm++;polyvecy_sample_triangular(&y,tsy,&ny);continue;}
        cnt_ok++;polyvecy_sample_triangular(&y,tsy,&ny);
    }
    report();return 0;
}
