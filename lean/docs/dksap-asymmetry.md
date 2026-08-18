# DKSAP: sound classically, totally broken given a discrete-log oracle

Background for `PqStealth/DKSAP.lean`, `PqStealth/Controls.lean` (the broken
variant) and `PqStealth/Demo.lean`.

DKSAP is scheme 1 of ERC-5564: the SECP256K1 dual-key stealth address protocol,
the only stealth scheme actually deployed today and the baseline this project
measures against. It is modelled as an instance of the same `StealthScheme`
abstraction used for the ML-KEM construction, so the two live in one framework
and the comparison is structural rather than rhetorical.

Put the two halves together and the same scheme, in one framework, is sound
under a classical assumption and totally broken given a discrete-log oracle.
That is a statement about the quantum transition rather than about DKSAP being
weak.

## The group model

Matching VCVio's `DiffieHellman` file: `F` is the scalar field (exponents), `G`
the group (elliptic curve points), and `a • g` is the additive rendering of
`gᵃ`. Keeping the group abstract is deliberate — the attack uses only the group
law, so nothing depends on the curve.

A recipient holds `(m, v)` and publishes `(M, V) = (m • g, v • g)`: `m` is the
spending key, `v` the viewing key. The sender draws an ephemeral `r`, publishes
`R = r • g`, and derives the stealth key `P = M + h(r • V) • g`; the recipient
recomputes the same scalar as `h(v • R)` and checks the resulting key against
`P`. `h : G → F` abstracts the hash that turns the shared secret point into a
scalar. The announcement is the pair `(R, P)`; `P` stands in for the on-chain
address, whose hashing is irrelevant to everything proved.

`dksap_derivation_agrees` is the identity the whole scheme rests on —
`r • (v • g) = v • (r • g)` — and also the reason the attack works once `v` is
known.

## The break: key recovery, not forgery

What is proved, in `DKSAP.lean`:

1. `dksap_perfectlyComplete` — the instance really is DKSAP: a recipient always
   detects a payment addressed to them. This is what rules out a vacuous model.
2. `dksap_recover_eq_honest` — an adversary holding the discrete logs of the
   PUBLISHED meta-address recomputes the recipient's honest stealth spending
   key exactly.
3. `dksap_key_recovery` — that recovered scalar is a valid secret key for the
   announced stealth public key.

### Why key recovery rather than a distinguishing game

The question this answers is "is DKSAP forgeable by a quantum adversary". The
answer is stronger than forgeability: the adversary recovers the actual signing
key, and key recovery implies UNIVERSAL forgery — sign anything, spend
anything. Stating it that way also keeps the result equational; there is no
probability slack anywhere. Phrasing it instead as a distinguishing game
("advantage = 1") would be strictly weaker AND harder, since it would inherit
an address-collision term.

### The injectivity hypothesis

`dksap_recover_eq_honest` assumes `Function.Injective (· • g)`. Injectivity
says the generator's orbit hits each point once, so a discrete log pins down
the exact scalar rather than merely some scalar with the same image. It holds
in the prime-order group DKSAP is instantiated over (`F = ZMod p`). It is
genuinely needed: the recovered viewing scalar is fed to `h`, so an answer that
is only correct up to the group law would derive a different shared secret.
VCVio assumes the sibling condition `Function.Bijective (· • g)` in the same
situation, and the classical half of `DKSAP.lean` uses that bijectivity form.

### What the discrete-log oracle abstracts, and what it does not

Shor's algorithm is not formalized, and cannot be: the verification framework
this project builds on models classical probabilistic computation only (no
quantum computation, no QROM), and carries no elliptic curves at all. What Shor
CONTRIBUTES to this attack is exactly one thing — discrete logarithms become
computable — and that is what is assumed, in the standard way, by taking the
oracle's answers as hypotheses (`xM • g = M`). Every step after that is
ordinary algebra. So this is a proof about a scheme relative to an assumption
about the adversary, NOT a proof about a quantum algorithm.

The load-bearing premise is that the meta-address is **published** (ERC-6538
registers `(M, V)` on-chain). An unpublished meta-address leaves an unspent
stealth address protected by hash preimage resistance — though any output that
has been spent exposes its public key and falls anyway.

### Honest scope of the contrast with the ML-KEM scheme

The ML-KEM construction in this development contains no group element, so this
adversary gains nothing against it. That is an asymmetry, and it is NOT proved
to be a separation: relative to a discrete-log oracle, the hardness of the
lattice assumptions is an ASSUMPTION, not a theorem. The honest statement is
that the DKSAP break is unconditional given the oracle, while the ML-KEM bounds
hold under assumptions that the oracle is not known to affect.

Two further scope notes. The break concerns the key exchange and the spending
key derived from it; it says nothing about how value is spent in practice
today, where the accompanying design still relies on a classical
account-abstraction route. And the two consequences differ in urgency:
deanonymization is retroactive (announcements recorded now can be opened
later), whereas theft requires the funds to still be there when the capability
exists.

## The other half: why it is a sound design classically

On its own the break is a weak claim — in a world where every discrete log is
available, every discrete-log-based scheme dies, and showing one of them die
proves little about the design. The classical half of `DKSAP.lean` supplies the
contrast:
DKSAP is unlinkable, and all of that unlinkability rests on a single assumption
about the hashed Diffie–Hellman value.

### The shape of the argument

The sender derives the stealth key as `M + h(r • V) • g`. Replace the scalar
`h(r • V)` by a uniformly random one and the announcement becomes independent
of the recipient outright — proved, not assumed. So the entire question is
whether the real scalar is distinguishable from uniform, which is the hashed
Diffie–Hellman assumption (implied by DDH with `h` modelled as a random
oracle).

This mirrors how the ML-KEM side is organized: the structural hops are proved,
and one named hardness assumption carries the weight. The classical assumption
is stated, not proved, exactly as MLWE is on the other side.

### The idealized scheme

`dksapIdeal F g` draws the shared scalar uniformly at random instead of
deriving it as `h(r • V)`; everything else is unchanged. It is a proof device,
not a scheme anyone could run — a recipient cannot recompute a random scalar,
so detection does not work — and it is only ever used as the middle game of a
hop.

`dksapIdeal_unlinkAdvantage_eq_zero`: the idealized scheme is perfectly
unlinkable. Not "negligibly" — exactly zero. With a uniform scalar the
announced stealth key is a uniformly distributed group element whatever the
recipient's key was, so the two branches are the same distribution and no
adversary, however powerful, does better than guessing.

The substitution behind it (`dksapIdeal_announce_indep`) is `s ↦ d + s`, where
`d` is the discrete log of `M1 − M0`; it is a bijection of the scalar field, so
it carries the uniform distribution to itself. `dksapIdeal_branch_indep` lifts
that to a whole announcement, ephemeral key included.

### The classical security statement

`hashedDH g h adv b` is the hashed-DH advantage on branch `b`: distinguishing
an announcement whose scalar is the real `h(r • V)` from one whose scalar is
uniform. Under DDH with `h` a random oracle this is negligible; it is the
classical assumption the scheme rests on, and it is exactly what a discrete-log
oracle destroys.

`dksap_unlinkAdvantage_le_hashedDH`: DKSAP's unlinkability advantage is bounded
by the two per-branch hashed-DH advantages and nothing else — the idealized
middle game contributes exactly zero, so there is no residual slack in the
reduction.

Read alongside `dksap_key_recovery`, this is the point of the whole exercise.

## Negative control

A proof closed by `simp` can be correct about something other than what was
intended, and a completeness theorem is especially exposed to this — if the
model were vacuous, or the detection test trivially true, the proof would still
go through and nothing would look amiss.

The usual defence is to break the scheme on purpose and check that the same
proof script stops working. That is worth doing interactively, but it is a poor
regression test: a failing tactic script is not checked by the build, and it
silently stops being evidence the moment a tactic gets stronger. The durable
version is to state the negation as an ordinary theorem and prove it. Then the
build itself guarantees that the broken variant really is broken, and hence
that the completeness theorem next door has content.

`dksapBroken` drops the recipient's spending key from the detection test —
the single most plausible way to get this scheme wrong — and
`dksapBroken_not_perfectlyComplete` proves it fails.

## The runnable demo

Everything else in the development is abstract: the group `G`, the scalar field
`F` and the hash `h` are type variables, which is what makes the theorems apply
to any curve. The cost is that nothing can be executed and inspected.

`Demo.lean` fixes a tiny concrete instance so the scheme — and the key-recovery
attack against it — can actually be RUN with `#eval`. It is a sanity check on
the model and an entry point for reading the development, not a cryptographic
instantiation: the group is the additive group of `ZMod 23`, in which discrete
logarithms are just division. That is precisely why the attack is executable
there, and it is also why the instance offers no security whatsoever.

The point being demonstrated: the abstract theorem `dksap_key_recovery`,
applied to these concrete numbers, says the recovered scalar is the recipient's
actual spending key — and you can watch that happen.
