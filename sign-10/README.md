# sign-10 — Facto-DSA: cryptanalysis

Facto-DSA's structural security claim is wrong. The specification prices the
recovery of the hidden subspace `K2 = ker L2` as an exhaustive search of cost
`q^n` (§3.2.5, giving 2^160 / 2^272 / 2^512 for the three instances). That price
is wrong because `K2` is not an unstructured set of `q^n` points: it is an
**n-dimensional linear subspace lying inside the zero locus of the public map**,
with `n = r/2`. A linear subspace inside a variety is found by solving a small
algebraic system, not by guessing.

Once one vector of `K2` is known the specification itself concedes the rest:
§3.2.5 says "one vector in `K2` can reveal the whole zero subspace by public
linear algebra", and §3.2.2 (Attack D) spells out the chain from there to a
forgery. We implemented Facto-DSA from the specification and ran that chain; it
proceeds as the author describes, up to and including the recovery of an
**equivalent triangular central map**.

| instance | claimed | spec's cheapest listed attack | spec's "one vector" (§3.2.5) | this work |
|---|---|---|---|---|
| Facto-DSA-128 | 128 | 129 | 160 | ≈ 55 † |
| Facto-DSA-256 | 256 | 265 | 272 | ≈ 96 |
| Facto-DSA-512 | 512 | 512 | 512 | ≈ 185 |

Bits, in the specification's own cost model (§3.2.1, `C(vars+d, d)^w`, `w = 3`),
using the solving degree `d = n+1` measured experimentally. † see "What is
measured and what is not" — the Facto-DSA-128 figure is the least supported of
the three.

## Why `q^n` is the wrong price

Write `P(z) = T · M_n((Q(L1 z) + R(L2 z)) ⊗ L2 z)` and put `A(z) = Q(X) + R(Y)`
with `X = L1 z`, `Y = L2 z`. Then:

* `K2 = ker L2` has dimension `n` and lies in `Z = {P = 0}`, because `Y = 0`
  kills the product polynomial. (The specification states this much.)
* Apart from `K2`, `Z` contains only `W = {A(z) = 0}` — `n` quadrics in `2n`
  variables, so dimension `n` but degree `2^n` and **not linear** — and a
  residual piece of dimension `s+1`.

Since `dim K2 = n` and `n + (n+1) > 2n`, a random subspace `L` of dimension
`n+1` **always** meets `K2` in a line, while `W ∩ L` contains no line and the
residual piece misses `L` entirely. Restricting the public system to `L` gives

> `m` homogeneous cubic equations in `n+1` variables, with a guaranteed
> `F_q`-rational solution: the point of `K2 ∩ L`.

No guessing. The `q^n` search collapses to one Macaulay/XL solve in `n`
variables.

The second component `W` is not mentioned anywhere in the specification. It does
not help an attacker directly (it is not linear), but it is why the restricted
system has `2^n + 1` roots, and any repair aimed only at `K2` would leave it in
place.

## Attack chain

Public key only; every stage is cross-checked against the secret key that the
same run generated.

1. **One vector of `K2`** — restrict to random `L` of dimension `n+1`, solve by
   Macaulay/XL, extract `F_q`-rational roots via eigenvalues of a multiplication
   matrix in the quotient.
2. **Separate `K2` from `W`** — for a root `v`, `ker J(v)` equals `K2` when
   `v ∈ K2` (and then `P` vanishes *identically* on it), whereas for `v ∈ W` it
   is the tangent space of `W`, on which `P` does not vanish. Separates the two
   perfectly in every run.
3. **Coordinate separation** — rewrite `P` in `(x,y)`; the `x³` block is
   identically zero.
4. **Shear** — `x → x + Γy` changes the `x·y²` block linearly in `Γ`; one linear
   solve makes the hidden input map split as `X = Mx`, `Y = Ny`.
5. **Isolate `Q`** — the `y_k`-coefficients of the `x²y` block span the hidden
   `n`-dimensional quadratic space.
6. **Symmetriser** — "`G⁽ʲ⁾ C_s` symmetric for all `j`" has a one-dimensional
   solution space; the resulting `E_j` are symmetric.
7. **Triangular flag** — the top coordinate direction is the solution of
   `rank[A₀u | … | A_{k-1}u] = 1`, a rank-1 MinRank with linear entries.
   Iterating yields an equivalent extended-triangular map that inverts under the
   submission's own Algorithm 7.

## What is measured and what is not

**Measured.** The reimplementation is validated at all three submitted parameter
sets: public-key sizes reproduce §2.2 Table 2 exactly (40,040 / 456,960 /
5,674,240 bytes), 20/20 signatures verify, trial counts match §2.3, tampered
signatures are rejected, and `dim ker L2 = n` with `P` vanishing identically on
it. So the structural fact the attack exploits is confirmed **directly on the
real instances**.

The algebraic solve is demonstrated at reduced size, 3 seeds each:

| n | m | s | quotient dim | solving degree | step-1 time | full chain |
|---|---|---|---|---|---|---|
| 5 | 8 | 1 | 33 = 2⁵+1 | 6 | 0.0 s | all stages pass ×3 |
| 6 | 10 | 1 | 65 = 2⁶+1 | 7 | 2.6 s | all stages pass ×3 |
| 7 | 12 | 1 | 129 = 2⁷+1 | 8 | ~170 s | all stages pass ×3 |

`K2` matches the secret `ker L2` exactly in all nine runs, and the recovered `Q`
is triangular in the recovered coordinates (`dim Q_i = i+1` for all `i`).

**Not measured, and the caveats that follow.**

1. **`d = n+1` is an extrapolation** from n = 5, 6, 7, not a proof.
2. **Only the `s = 1` shape was reached.** Those instances have `m ≈ 2n`, the
   shape of Facto-DSA-256 and -512. Facto-DSA-128 has `m/n = 1.3`, a *less*
   overdetermined system, where the solving degree plausibly exceeds `n+1`. The
   ≈55-bit figure for Facto-DSA-128 is therefore the weakest of the three and
   should be read as "far below 128", not as a precise cost.
3. **No forged signature is emitted.** The last step — identifying the Hankel
   container with the polynomial ring (rational-normal-curve / GRS recovery) —
   is not re-implemented here. It is not novel and not in dispute: it is the
   submitter's own tool (§3.2.2 Attack A step 3, "recovered by the standard GRS
   key recovery method"; Attack D step 7), used there to break the earlier
   variants. This is the one gap between what is shown here and a working
   universal forger.
4. **This is not run against the submitter's code.** No sign-10 reference
   implementation is included in this repository, so `cryptanalysis/` builds a
   reimplementation written from the specification. Unlike every other candidate
   folder here, it does not drive the submitter's own sources.

## Reproducing

```sh
make -C sign-10/cryptanalysis
make -C sign-10/cryptanalysis test
```

Or individually — arguments are `n m seed max_degree`:

```sh
sign-10/cryptanalysis/build/selftest 10 13 1     # Facto-DSA-128 keygen/sign/verify
sign-10/cryptanalysis/build/attack1  6 10 1 12   # K2 recovery
sign-10/cryptanalysis/build/attack3  6 10 1 12   # full chain
```

`attack1` and `attack3` print a cross-check of every recovered object against
the secret key generated in the same run; the attack itself consumes only the
public key.

See `COMMENT.md` for the write-up intended for the submitter, and
`pseudocode.md` for the extracted algorithm description.
