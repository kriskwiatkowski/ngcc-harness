# kex-02 AFS-KEX — algorithm summary

Four-pass **mutually authenticated** key exchange (the submitted variant is **pMAKE-BW**)
built entirely from KEMs — no signatures. Each party's session public key is a
*composite* key `cpk_U = pk_U + pk_U^e`: the sum of its certified long-term MLWE public
key and a freshly generated ephemeral one derived from a seed. Each side encapsulates to
the peer's composite key; the two KEM secrets are run through a PRF to give the session
key plus two *seed-protection* keys, which XOR-mask each party's ephemeral seed. The peer
then regenerates pk^e from the recovered seed, subtracts it from cpk to recover the
long-term key, and checks the identity binding — so authentication is achieved without
ever transmitting a signature, and (in the full protocol) without transmitting the
long-term key in the clear. The KEM is **BW-KEM**: an MLWE PKE whose message is carried
by a nested **Barnes–Wall lattice code** (E8/BW8 at level 1, BW32 above), FO-transformed
in the style of [DHK+21] with implicit rejection.

Specification: `kex-02-spec.pdf` (104 pages). §2.1 BW-PKE/BW-KEM (Figs. 1–2), §2.2
pMAKE-BW (Fig. 3), §2.3 pUAKE-BW (Fig. 4, not implemented), Remark 2.1 (public-key
identifiers), §2.6 Tables 1–2 (parameters), §4 Table 6 (implementation sizes). English.

## Parameters

| parameter | AFS_KEX_C128 | AFS_KEX_C256 | AFS_KEX_C512 | meaning |
|---|---|---|---|---|
| coding lattice | BW8 (E8) | BW32 | BW32 | Table 2 |
| (n, τ, µ0) | (8, 2, 4) | (32, 2, 32) | (32, 2, 32) | codec block, scaling, bits/block |
| N | 256 | 256 | 512 | ring degree, R_q = Z_q[x]/(x^N+1) |
| q | 3329 | 3329 | 3329 | modulus (q̂ = 4096 decoding modulus) |
| k | 2 | 4 | 4 | module rank |
| λ | 128 | 256 | 512 | seed / KEM-key bits |
| (η_s, η_e, η_ct) | (6, 6, 5) | (3, 3, 3) | (2, 2, 2) | CBD widths |
| d_u | 10 | 10 | 10 | u compression bits |
| d_v | 4 | 5 | 6 | v compression bits |
| (sec.c, sec.q) | (131, 119) | (267, 242) | (556, 504) | Table 1 |
| δ / δ_AFS | 2^-138.14 / 2^-67.98 | 2^-209.94 / 2^-122.24 | 2^-232.71 / 2^-124.13 | Table 1 |
| \|M\| = (N/n)·µ0 | 128 bits | 256 bits | 512 bits | message space |

Only the three **base** BW-KEM parameter sets are shipped. Table 1 also lists
AFS-KEM-BW-C384 and four "strengthened" rows (larger d_u, d_v), and Table 3 lists a whole
alternative AFS-KEM-ML family — none of these are implemented.

Sizes (bytes), specification vs the built reference library. The relevant spec table is
**Table 6** (§4), which reports the sizes *of this NGCC-interface implementation*;
Table 1 reports the underlying BW-KEM |pk| and |ct|, and Table 4 Panel A reports the
*protocol* communication cost of pMAKE-BW as drawn in Fig. 3.

| instance | pk T6 | pk impl | sk T6 | sk impl | st_A | st_B | total msg T6 | total msg impl | ss | passes |
|---|---|---|---|---|---|---|---|---|---|---|
| AFS_KEX_C128 | 1568 | 1568 | 3170 | 3170 | 64 | 64 | 1568 | 1568 | 16 / 16 | 4 / 4 |
| AFS_KEX_C256 | 3136 | 3136 | 6338 | 6338 | 128 | 128 | 2944 | 2944 | 32 / 32 | 4 / 4 |
| AFS_KEX_C512 | 6272 | 6272 | 12674 | 12674 | 256 | 256 | 6016 | 6016 | 64 / 64 | 4 / 4 |

Every value matches Table 6, and the per-pass split matches too (C128: pass-1 768,
pass-2 784, pass-3 16, pass-4 **0**). Note the structure: the ICCS "long-term public key"
is **2 × |pk_BW-KEM|** because it carries `cpk_U ‖ pk_U` and the ICCS "long-term secret
key" is **2 × |sk_BW-KEM|** carrying `csk_U ‖ sk_U`; st = 4·λ/8 holds
`seed_U ‖ K_SESSION ‖ K_ENC^B ‖ K_ENC^A`. Underlying BW-KEM sizes (Table 1) are
784/768, 1568/1440, 3136/2944 for |pk|/|ct| ✓, and BW-KEM |sk| = |sk_cpa| + |pk| +
|ID(pk)| + λ/8 = 1585 / 3169 / 6337.

**Table 4 Panel A gives pMAKE-BW's communication as 3136 / 6080 / 12288 bytes**, i.e.
2·|pk| + 2·|ct| + 2·λ/8 — twice what the library transmits, because in Fig. 3 cpk_A and
cpk_B are *messages* (rounds 1 and 2) whereas the NGCC mapping makes them part of the
long-term public key. §4 states this explicitly. See discrepancy 1.

## Pseudocode

### BW-PKE (Fig. 1)
```
KeyGen():  ρ, σ ←$ {0,1}^λ;  A := SampleA(ρ);  (s,e) := SampleSE_{η1}(σ)
           t := As + e;      pk := (t, ρ);  sk := s

Enc(pk = (t,ρ), m; r):
    A := SampleA(ρ);  r := SampleR_{η1}(r);  (e1,e2) := SampleE_{η2}(r)
    u0 := A^T r + e1;        v0 := t^T r + e2
    u  := Compress_{q,2^du}(u0)
    v  := Compress_{q,2^dv}(v0 + ⌊PolyEncode(m)⌉)        # Barnes-Wall lattice code
    return c := (u, v)

Dec(sk = s, c = (u,v)):
    u' := Decompress(u, du);  v' := Decompress(v, dv)
    w  := ⌈(q̂/q)(v' − s^T u')⌋                            # lift to the decoding modulus q̂
    return PolyDecode(w mod± q̂)
```
`PolyEncode` splits m into N/n blocks of µ0 bits, maps each through `Encode_{C_{n,τ}(q/2^τ)}`
into the complex Barnes–Wall lattice C^{n/2}, and interleaves the real/imaginary parts
back into the polynomial with stride d. `PolyDecode` de-interleaves and runs the
bounded-distance decoder `Decode_{C_{n,τ}(q̂/2^τ)}`.

### BW-KEM (Fig. 2)
```
KeyGen():   (pk,sk) ← BW-PKE.KeyGen();  z ←$ {0,1}^λ;  return (pk, (sk,z))
EKeyGen(pk = (t,ρ), seed):                                # deterministic, AFS-specific
    A := SampleA(ρ)                                       # reuse the PEER'S matrix seed
    (s_e, e_e) := SampleSE_{η1}(seed);   t_e := A s_e + e_e
    return (pk_e := (t_e, ρ), sk_e := s_e)
Encaps(pk):  m ←$ M;  (K, r) := H(ID(pk), m);  c ← BW-PKE.Enc(pk, m; r);  return (c, K)
Decaps((sk,z), c):
    m' := BW-PKE.Dec(sk, c);  (K', r') := H(ID(pk), m');  K̃ := H1(ID(pk), z, c)
    return  (m' = ⊥ or BW-PKE.Enc(pk, m'; r') ≠ c) ? K̃ : K'
```
`ID(pk)` is "a deterministic public-key identifier" (Remark 2.1) used only for
random-oracle domain separation; the spec leaves its definition open and only requires a
min-entropy assumption on ID(cpk) (Theorem 6.9).

### pMAKE-BW — pass structure (Fig. 3)

The specification defines **4 passes**; OBSERVED reports `passes=4`. Agreement on the
count. The message *contents* differ — see discrepancy 1.

Spec (Fig. 3):
```
Init_A / Init_B:  (pk_U, sk_U) ← BW-KEM.KeyGen(); CA binds id_U to pk_U;  st_U = ε

pass 1  A → B:  seed_A ←$ {0,1}^λ
                (pk_e^A, sk_e^A) ← EKeyGen(pk_A, seed_A)
                t_c^A := t_A + t_e^A;  cpk_A := (t_c^A, ρ_A);  csk_A := (s_A + s_e^A, z_A)
                m1 = cpk_A ;   st_A = (seed_A, csk_A)
pass 2  B → A:  same composite construction for B, then
                (ct_A, K_A) ←$ Encaps(cpk_A)
                m2 = (cpk_B, ct_A) ;  st_B = (seed_B, csk_B, K_A)
pass 3  A → B:  K'_A ← Decaps(csk_A, ct_A)         (abort on ⊥)
                (ct_B, K_B) ←$ Encaps(cpk_B)
                (K_SESSION, K_ENC^A, K_ENC^B) ← PRF(K'_A, K_B)
                c_seed^A := K_ENC^A ⊕ seed_A
                m3 = (id_A, ct_B, c_seed^A)
pass 4  B → A:  K'_B ← Decaps(csk_B, ct_B)         (abort on ⊥)
                (K_SESSION, K_ENC^A, K_ENC^B) ← PRF(K_A, K'_B)
                seed'_A := c_seed^A ⊕ K_ENC^A
                (pk_e^{A'}, ·) ← EKeyGen(cpk_A, seed'_A);  pk'_A := (t_c^A − t_e^{A'}, ρ_A)
                if CAVerf(id_A, pk'_A) ≠ 1: abort            # B authenticates A
                c_seed^B := K_ENC^B ⊕ seed_B;   accept K_SESSION
                m4 = (id_B, c_seed^B)
DeriveSS_A:     seed'_B := c_seed^B ⊕ K_ENC^B
                (pk_e^{B'}, ·) ← EKeyGen(cpk_B, seed'_B);  pk'_B := (t_c^B − t_e^{B'}, ρ_B)
                if CAVerf(id_B, pk'_B) ≠ 1: abort            # A authenticates B
                accept K_SESSION
DeriveSS_B:     K_SESSION (already accepted in pass 4)
```

As implemented (`KEX_AlgorithmInstance.c`), with cpk pre-distributed per §4:
```
Init_A / Init_B (kex_init_self):
    coins ←DRNG 2λ/8 ;  (pk_U, sk_U) ← BW-KEM.KeyGen(coins)
    seed_U ←DRNG λ/8 ;  (pk_e, sk_e) ← EKeyGen(pk_U, seed_U)
    cpk_U := pk_U + pk_e (polyvec add, ρ_U kept);  csk_U := sk_U + sk_e
    pk := cpk_U ‖ pk_U        sk := csk_U ‖ sk_U        st := seed_U

pass 1  A → B:  (ct_B, K_B) ← Encaps(cpk_B)                     m1 = ct_B
                st_A = (seed_A, K_B)
pass 2  B → A:  K_B ← Decaps(csk_B, ct_B)
                (ct_A, K_A) ← Encaps(cpk_A)
                K_SESSION ‖ K_ENC^B ‖ K_ENC^A := XOF(K_B ‖ K_A, 3λ/8)
                c_seed^B := K_ENC^B ⊕ seed_B                    m2 = (ct_A, c_seed^B)
                st_B = (seed_B, K_SESSION, K_ENC^B, K_ENC^A)
pass 3  A → B:  K_A ← Decaps(csk_A, ct_A)
                K_SESSION ‖ K_ENC^B ‖ K_ENC^A := XOF(K_B ‖ K_A, 3λ/8)
                c_seed^A := K_ENC^A ⊕ seed_A                    m3 = c_seed^A
                st_A = (seed_A, K_SESSION, K_ENC^B, K_ENC^A)
                seed_B := K_ENC^B ⊕ c_seed^B                    # from m2
                (pk_e, ·) ← EKeyGen(cpk_B, seed_B);  pk'_B := cpk_B − pk_e
                if pk'_B ≠ pk_B (the second half of pkb): return −1
pass 4  B → A:  seed_A := K_ENC^A ⊕ c_seed^A
                (pk_e, ·) ← EKeyGen(cpk_A, seed_A);  pk'_A := cpk_A − pk_e
                if pk'_A ≠ pk_A (the second half of pka): return −1
                m4 = ε                                          # nothing is sent
DeriveSS_A / DeriveSS_B:  ss := st[λ/8 : 2λ/8]                  # K_SESSION
```

## Implementation vs specification

Checked: `params.h` (all three), `kem.c` (FO), `indcpa.c` (BW-PKE + `indcpa_keypair_ekeygen`),
`BWcoding.c` (PolyEncode/PolyDecode), `symmetric-iccs.c` + `symmetric.h` (H/H1/XOF/PRF),
`KEX_AlgorithmInstance.c` (the whole protocol layer), `randombytes_api.c`, and the shipped
`KAT_KEX.c` driver.

Agreements:
- Every Table-1 constant for the three base rows is in `params.h`: k = 2/4/4,
  N = 256/256/512, q = 3329, λ/8 = `SYMBYTES` = 16/32/64, η = (6,6,5)/(3,3,3)/(2,2,2)
  (`ETA_S/ETA_E/ETA_CT` at C128, `ETA1/ETA2` above), d_u = 10 throughout
  (`POLYVECCOMPRESSEDBYTES` = k·N·10/8), d_v = 4/5/6 (`POLYCOMPRESSEDBYTES` =
  128/160/384). Derived |pk| = 784/1568/3136 and |ct| = 768/1440/2944 reproduce Table 1.
- Table 2's codec choice is honoured: C128's `BWcoding.c` uses
  `CODEC_BLOCK_COEFFS 8` / `CODEC_MESSAGE_BITS_PER_BLOCK 4` (BW8, µ0 = 4) with the
  RM(1,3) generator masks {0x55, 0x0f, 0x3c, 0xf0}; C256/C512 ship `encode_bw32` /
  `decode_bw32` with the recursive `BDD_8`/`BDD_16`/`BDD` decoder (BW32, µ0 = 32). The
  message sizes (N/n)·µ0 = 128/256/512 bits equal `INDCPA_MSGBYTES`·8 ✓.
- The FO transform of Fig. 2 is present and complete in `kem.c`: derandomised encaps,
  re-encryption comparison over the full ciphertext (`verify`), constant-time `cmov`
  between K' and the rejection key `rkprf(z, c)` — implicit rejection, no early return.
- `indcpa_keypair_ekeygen` is exactly `EKeyGen`: it reads ρ out of the *peer's* packed
  public key (`memcpy(publicseed, pkprime+POLYVECBYTES, SYMBYTES)`), regenerates A from
  it, and samples (s_e, e_e) from the explicit seed — so the composite key stays in the
  same MLWE instance, as Fig. 2 requires.
- The composite construction is the plain polynomial-vector sum on both the public and
  the secret side (`polyvec_add` of `pk_s`+`pk_e` and of `sk_s`+`sk_e`), and
  `extract_pk` is the matching subtraction, with ρ copied across unchanged ✓.
- **Both identity checks are present and not inverted**: pass 3 (A verifies B) and pass 4
  (B verifies A) each recompute pk' from the recovered seed and return
  `KEX_VERIFY_FAILURE` (−1) when `memcmp` against the peer's static key differs.
- All protocol randomness comes from the seeded DRNG through `get_drng_bytes` →
  `get_random_number(&drng_algorithm, …)`. `randombytes_api.c` (getrandom(2) /
  CryptGenRandom) is linked only because the unused non-derandomised
  `crypto_kem_keypair`/`crypto_kem_enc` reference it; no reachable path uses OS entropy.
- H, H1 and the PRF/XOF are the NGCC SM3 auxiliary functions as §4 states
  (`sm3hash(256)` at C128, `pseudohash(512)`/`pseudohash(1024)` for the 2λ-byte G output
  at C256/C512, `pseudoXOF` for the matrix/noise XOF and for the 3λ/8-byte PRF output).

Discrepancies:
1. **(a)/(c) documented restructuring of the message schedule — but only partly
   documented.** §4 does say that under the NGCC interface "each party is assumed to have
   obtained both the peer's static public key and the peer's combined public key cpk
   before the handshake", which accounts for cpk_A and cpk_B disappearing from passes 1
   and 2 (and for Table 6's total of 1568 vs Table 4's 3136). What §4 does **not** say is
   that the remaining messages are also re-ordered:
   * Fig. 3 has **B** encapsulate first (to cpk_A, round 2) and **A** second (to cpk_B,
     round 3). The implementation has **A** encapsulate first (pass 1, `m1 = ct_B`) and
     B second (pass 2, `m2 = ct_A ‖ c_seed^B`).
   * Fig. 3 sends `c_seed^B` in round **4**, *after* B has run `CAVerf(id_A, pk'_A)`.
     The implementation sends it in pass **2**, before B has any evidence about A at all.
     Confidentiality of seed_B survives (the mask K_ENC^B is derived from K_A, which
     needs csk_A), but the "reveal only after authenticating" ordering of Fig. 3 is gone.
   * Fig. 3's round-4 message is `(id_B, c_seed^B)`; the implementation's pass 4 sends
     **nothing** — identities are never transmitted at all, they are implicit in the
     ICCS pk arguments.
2. **(a) real deviation — `kex_generate_pass4_msg_b` never writes its output lengths.**
   `KEX_AlgorithmInstance.c:248-251` casts `stb_len_bytes`, `m4` and `m4_len_bytes` to
   `(void)` and returns 1 without assigning `*m4_len_bytes` or `*stb_len_bytes`. The
   shipped `KAT_KEX.c` happens to initialise `m4_len_bytes = 0` once before the record
   loop (line 100), so the KATs record `M4_Len = 0`; any other caller that passes an
   uninitialised length variable reads garbage and then hex-dumps that many bytes out of
   the `m4` buffer. This is an outright ICCS-API contract violation, not a style issue.
3. **(a) weak instantiation of `ID(pk)` — a raw public-key prefix, not a hash.**
   `kem.c:31` and `kem.c:88` both carry a commented-out `hash_h(…)` immediately above a
   `memcpy(…, pk, PREFIXHASHBYTES)`, so the "public-key identifier" fed to the random
   oracles is literally the **first λ/8 + 1 bytes of the packed public key** (17 / 33 / 65
   bytes). Remark 2.1 permits a deterministic identifier and only assumes min-entropy of
   ID(cpk) — which a 136/264/520-bit prefix of an honest t satisfies — so this is
   defensible *within* the stated proof. But three things follow that the spec does not
   discuss: (i) ID is trivially non-injective and non-collision-resistant for
   adversarially chosen keys, so the FO's multi-target countermeasure and any key-binding
   (MAL-BIND / LEAK-BIND-K-PK) property are lost; (ii) the prefix lies entirely inside the
   packed t vector, so **ρ — the matrix seed, i.e. the whole MLWE instance — is not
   covered by ID at all**; (iii) `PREFIXHASHBYTES` is stored verbatim in the secret key
   where an FO implementation normally stores H(pk), so the secret key leaks a 17/33/65-
   byte plaintext prefix of the public key. A one-line change to the shipped, already
   present `hash_h` would remove all three.
4. **(a) conceptual deviation with a security consequence — the "ephemeral" key is
   generated at init, not per session.** Fig. 3 round 1 reads "the initiator A **samples
   seedA**" inside the pass, making (seed_A, sk_e^A) per-session ephemeral; that is what
   gives the protocol its forward secrecy (§3, "against a passive adversary with secret-
   state exposure"). In the implementation `seed_U`, `pk_e`, `sk_e` and hence `cpk_U`,
   `csk_U` are all produced inside `kex_init_a`/`kex_init_b` (`kex_init_self`) and stored
   in the ICCS **long-term** pk/sk. Under the ICCS API, `kex_init_*` is the long-term
   key-generation call and the passes are run many times against it, so a deployment that
   follows the API semantics reuses one seed_U — and one sk_e^U — for every session, and
   forward secrecy is gone. More directly, the first half of each returned long-term
   `sk` is `csk_U`: after recording `ct_B = m1` and `ct_A = m2[0..|ct|-1]`, later
   compromise of both API long-term keys lets an attacker compute
   `K_B = Decaps(csk_B, ct_B)`, `K_A = Decaps(csk_A, ct_A)`, and the exact old
   `K_SESSION = XOF(K_B || K_A)[0..lambda/8-1]`. `reproduce_pfs_break.c` demonstrates
   this after zeroing both session states; using only the true static-key halves is a
   negative control. The KAT driver re-runs `kex_init_*` per record, so the KATs pass
   and the defect is invisible to testing. §4's "cpk obtained before the handshake"
   sentence arguably endorses the static cpk, but it does not address the loss of
   per-session ephemerality, and it is irreconcilable with Fig. 3 as drawn.
5. **(a) deviation — B can output a session key without pass 4 having succeeded.**
   Fig. 3 has B accept K_SESSION only after `CAVerf(id_A, pk'_A)` passes. In the
   implementation K_SESSION is already written into `st_B` by pass 2, and
   `kex_derive_ss_b` (`:296-313`) copies it out unconditionally — it ignores `ma`,
   `pka` and `skb` entirely and performs no check. The authentication of A lives solely
   in `kex_generate_pass4_msg_b`'s return value. A caller that ignores that return value,
   or that calls `kex_derive_ss_b` without pass 4, accepts an unauthenticated session.
   (Symmetrically `kex_derive_ss_a` ignores everything, but A's check at least happens in
   pass 3, whose failure the ICCS driver does abort on.)
6. **(b)/(c) "abort on decapsulation failure" is silently replaced by implicit
   rejection.** Fig. 3 rounds 3 and 4 say "if decapsulation fails, it aborts".
   `crypto_kem_dec` always returns 0 (implicit rejection), so the
   `if (crypto_kem_dec(...) != 0) return KEX_API_CORE_FAILURE` guards in passes 2 and 3
   are dead code; a tampered ciphertext yields a pseudorandom K and the run fails later
   at the pk-binding `memcmp` (or, for a tampered ct_B, silently produces mismatched
   session keys). Defensible as implicit rejection, but it is not what Fig. 3 says.
7. **(informational) unbounded VLA in the XOF wrapper.**
   `symmetric-iccs.c` `kyber_iccs_xof_squeezeblocks` allocates
   `uint8_t stream[state->squeezed_bytes + outblocks*XOF_BLOCKBYTES]` on the stack and
   re-derives the whole prefix on every squeeze, so matrix generation is O(len²) and the
   stack usage grows with the number of rejection-sampling retries. Correct (pseudoXOF is
   SM3 in counter mode and therefore prefix-stable) but unbounded.
8. **(informational)** Of the eight parameter rows in Table 1 and the eight in Table 3,
   only the three base BW rows are implemented; pUAKE-BW (Fig. 4), the strengthened rows,
   C384, and the whole AFS-KEM-ML family are absent.

Not verified: the Barnes–Wall encoder/decoder (`BWcoding.c`, 676 lines of recursive BDD
for BW32) was read only for its block/µ0 constants and entry points, not validated as a
correct BW lattice decoder; the NTT/`basemul` layer and the compression constants were
not checked coefficient-by-coefficient; the δ/δ_AFS figures of Table 1 were not
recomputed; the security proofs of §§5–6 were not reviewed. The line-level reading is of
the AFS_KEX_C128 tree, with `params.h`, `symmetric-iccs.c` and `BWcoding.c` spot-checked
in the C256 and C512 trees (these three differ between instances; the protocol layer
`KEX_AlgorithmInstance.c` is structurally identical).
