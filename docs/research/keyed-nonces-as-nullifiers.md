# Keyed and expiring nonces (EIP-8250 / EIP-8266): the protocol grew a nullifier, so we should stop designing one

*2026-09-03. Extends D-020 (spend targets EIP-8141 frame transactions) and revisits the
parked D-012 / D-008 ZK-spend variant. No code or vectors change; this is a design memo
against two Draft EIPs that were not on the table when D-020 was written.*

## 1. Question

D-020 locked the spend path onto EIP-8141 frame transactions and inherited that EIP's
replay model: **one linear account nonce per sender**. Two follow-on Draft EIPs change
that model:

- **[EIP-8250](https://eips.ethereum.org/EIPS/eip-8250) — Keyed Nonces for Frame
  Transactions** (Thiery, Wahrstätter, lightclient, Buterin; Draft, created 2026-04-16;
  requires 7623, 8037, 8141). Replaces the single `nonce` with `(nonce_keys, nonce_seq)`.
- **[EIP-8266](https://eips.ethereum.org/EIPS/eip-8266) — Expiring Nonces for Frame
  Transactions** (Wahrstätter, lightclient; Draft, created 2026-05-15; requires 8141).
  Replay protection bounded by a 60-second deadline instead of a nonce.

The question: **if a keyed nonce is already a protocol-enforced single-use token — a
nullifier — what does that let this scheme stop building, and does it improve stealth
address *generation*?**

Short answer: it removes one of the two obligations that keep the compact,
commitment-based derivation of D-012 parked, and it dissolves the sponsor bottleneck in
the shipped frames spend route. But the two EIPs are not interchangeable for us, the
recommendation is mostly **8266, not 8250**, and there is a derivation trap that would
hand every payer a permanent spend-detection oracle if we get it wrong.

---

## 2. What the two EIPs actually give

### 2.1 EIP-8250: keyed nonces

`nonce` becomes two payload fields: `nonce_keys` (1–16 `uint256`, strictly increasing,
`MAX_NONCE_KEYS = 16`) and `nonce_seq` (`uint64`). `nonce_keys == [0]` means the legacy
account nonce. Any non-zero key gets its own slot in the `NONCE_MANAGER` predeploy at
`0x…8250`:

```
slot(sender, nonce_key) = keccak256( left_pad_32(sender) ‖ uint256_to_bytes32(nonce_key) )
```

A transaction is stateful-valid only if `nonce_seq == current_nonce_seq(sender, k)` for
**every** `k` it names, and consumption — writing `nonce_seq + 1` to each named slot —
happens exactly once, during EIP-8141's payment-approval transition. Transactions whose
non-zero key sets are disjoint are therefore replay-independent: same sender, no
serialization between them.

The EIP says the nullifier part in its own words:

> Tying nonce consumption to EIP-8141's payment-approval step also gives single-use-key
> applications, such as nullifiers, an atomic spent-once guarantee: if validation requires
> every selected key to be unused, successful inclusion makes all selected keys used.

Costs and exposure that matter to us:

| Fact | Value |
| --- | --- |
| First use of a non-zero key | `KEYED_NONCE_FIRST_USE_STATE_GAS = 97,920` state gas, per fresh key |
| Slot lifetime | **permanent** — slots are never deleted |
| Key exhaustion | at `nonce_seq == 2^64 − 1` the key cannot advance |
| Introspection | `TXPARAM 0x01` `nonce_seq`, `0x0E` `len(nonce_keys)`, `0x0F` hash of the key array, `0x10` first key |
| App guidance | authenticate at least `(sender, nonce_keys_hash, nonce_seq == 0)` in `VERIFY`; domain-separate derived keys; reject `k == 0` |

### 2.2 EIP-8266: expiring nonces

`tx.nonce == 2^64 − 1` selects the mode. The transaction carries exactly one `VERIFY`
frame targeting `EXPIRY_VERIFIER` with an 8-byte deadline `d`, and the protocol enforces
`now <= d <= now + MAX_EXPIRY_SECS` with `MAX_EXPIRY_SECS = 60`. Seen sig-hashes go into a
fixed ring buffer at `NONCE_RING` (`RING_CAPACITY = 2^18`), each fresh write paired with a
clear as the pointer wraps, so state growth is bounded at `2 × RING_CAPACITY` slots and is
**zero in steady state**. Flat `EXPIRING_NONCE_GAS = 13,000`, deliberately excluding the
`SSTORE_SET` premium. And the line that matters most here: nodes **MAY admit multiple
pending expiring-nonce transactions per sender**, unlike EIP-8141.

### 2.3 The distinction we have to keep straight

These solve two different problems that look alike:

- **8266 gives freshness.** "This exact transaction has not been included in the last 60
  seconds." Cheap, no permanent state, no derived secret.
- **8250 gives a nullifier.** "This *token*, chosen by the application, is now spent,
  forever, and the fact is public state." Expensive, permanent, and the token is a payload
  field anyone can read.

Our scheme needs freshness on every spend and a nullifier only in one hypothetical
variant. Reaching for 8250 by default would be paying 97,920 state gas and a permanent
slot per payment for a property we already get from the account balance.

---

## 3. The user's premise, restated precisely

> A keyed nonce for the transaction *is* its nullifier, and the process of nullifying a
> transaction is not needed any more because double-spending is solved at the protocol
> level.

Both halves are right, and they cut in opposite directions, which is the useful part.

**A nullifier exists because a note is a commitment.** In a UTXO/note system nothing
on-chain stops you presenting the same note twice, so the application publishes a
single-use tag and maintains a spent set. That machinery is: state for the set, a
membership check at spend, and a ZK statement binding the tag to the note secret.

**pq-sap does not have notes.** Value at a stealth address is native ETH at an account.
Spending it debits a balance; the balance is the double-spend defence. So for the
mainline construction A spend path there is nothing to nullify — the user's second half
is exactly right, and the correct conclusion is *don't buy a nullifier*, i.e. **8266, not
8250**.

**Except in the variants where the authorization is detachable from the balance.** That is
D-008/D-012 territory: a ZK ownership proof, or D-018's commit-signer opening, is a piece
of evidence that could in principle be replayed independently of the account it authorizes.
There the first half of the premise pays: the nullifier we would have had to design is now
a choice of `nonce_key`. We don't build it, store it, or prove it — we pick it.

---

## 4. The immediate win: the sponsor stops being a bottleneck and a link

This is the concrete, non-speculative one, and it touches shipped code.

`js-client/contracts/src/frames/Stealth8141Account.sol` documents the shape a public
frames network admits today: **the stealth account is not the transaction's `sender`.** A
sponsor EOA is sender and payer, the stealth account is called as a `DEFAULT` frame, and
the ML-DSA signature authorizes the whole `(sponsor, nonce, frames)` tuple via
`TXPARAM 0x08` (`sig_hash`). In the demo that sponsor is the in-page throwaway key
(`ui/src/lib/throwaway.ts`). Two costs follow, both structural:

1. **Linkability.** The sponsor is a unique public sender bound to a recipient's spends,
   and it must be funded from somewhere. This is precisely the leak D-020 expected native
   paymaster frames to close — but paymaster frames fix *who pays*, not *whose nonce
   orders the transaction*. The sender field stays.
2. **Serialization.** One legacy nonce per sender. `ui/src/lib/frames.ts` already carries
   the scar: `pendingNonce()` exists because "rapid back-to-back frame txs collide on
   `latest`." A sponsor shared by many recipients would be a global lock.

EIP-8250's Rationale names this situation directly — privacy applications hit a throughput
bottleneck when "a shared sender becomes necessary to avoid binding onchain activity to a
unique public sender."

Worth naming what actually happened here: **ERC-4337 had this for free and frame
transactions gave it up.** A bundler packs many UserOps from many accounts into one
transaction, so the on-chain sender is the bundler and mixing is a side effect of the
architecture. EIP-8141 removes the bundler and makes the account originate its own
transaction — which is the point — but the mixing goes with it. Keyed and expiring nonces
are what give it back.

**What we should do with that.** Both EIPs unblock a *shared, public sponsor*: one
well-funded account carrying every stealth spend on the network, each spend in its own
replay domain, no coordination, nothing for the recipient to fund. The anonymity set of
the spend's `sender` field becomes every user of that sponsor instead of one throwaway EOA.
8266 is the better fit — 13,000 gas, no permanent slot, multiple pending transactions per
sender explicitly allowed — with 8250 as the fallback if the 60-second deadline is too
tight for a pre-signed or hardware-signed PQ spend (ML-DSA blinded signing averages ~30
rejection rounds, D-011, so signing latency is not negligible).

**No contract change is needed for the binding.** EIP-8141's `sig_hash` is keccak over the
RLP body, and EIP-8250 replaces the `nonce` field *inside that body*. So
`Stealth8141Account.executeFrame`, which already validates the ARBITRARY signature over
`FRAME_CTX.sigHash()`, binds `nonce_keys` and `nonce_seq` for free; the NatSpec claim
"authorizes exactly one `(sponsor, nonce, frames)` tuple" simply becomes
`(sponsor, nonce_keys, nonce_seq, frames)`. That already satisfies EIP-8250's guidance to
authenticate `(sender, nonce_keys_hash, nonce_seq == 0)` in `VERIFY`. What *would* change
is `js-client/src/frame-tx/serialize.ts`, whose body layout is transcribed from deployed
ethrex, not from the spec draft — so that is a when-the-chain-ships-it change, not now.

**Sponsor incentive.** A public sponsor needs paying. EIP-8141's `[deploy, only_verify,
pay]` prefix already allows reimbursement from the stealth account inside the same
transaction. That re-creates a value edge from the stealth address to the sponsor, but the
sponsor is shared, so it carries no identity — unlike today's per-recipient throwaway.

---

## 5. The generation win: one of the two obstacles in front of the compact meta-address

This is the answer to "does it improve stealth address *generation*", and it is indirect
but real.

Today's derivation is pinned by construction A (D-003): the sender must be able to compute
the recipient's one-time **public key**, because the account verifies a signature under a
key bound to its address. That single requirement is why the meta-address must carry the
full-precision `t` — `version(1) ‖ rho(32) ‖ pack23(t)(4,416) ‖ ek(1,184) ≈ 5,633 B` — and
why D-011 measures meta-address registration at ≈3.79M gas naive (~61× the EC baseline).
plan.md states the same constraint from the other side: the sender-names-the-address model
"constrains the derivation constructions this project evaluates."

D-012 measured the prize for escaping it: with a ZK ownership proof instead of a blinded
signature, the meta-address sheds `t` and becomes `version ‖ 32-B commitment ‖ ek` —
**5,633 B → 1,217 B, 4.6×** — and the KEM decouples from spend entirely, so discovery can
be chosen on scan speed alone. D-012 is parked, with the stated reason being that the
ZK-spend **address-binding** is unproven.

A ZK spend owes two things, not one:

- **(a) Binding** — the proof must be tied to *this* address/announcement, so you can only
  spend what you own. Still open. EIP-8250 does not help.
- **(b) Non-replay** — the proof must not be presentable twice. Under construction A this
  was free and invisible, because the one-time account's own legacy nonce serialized it;
  in any design where the authorization is detachable it becomes a nullifier obligation.

**EIP-8250 discharges (b) at the protocol layer, for the price of picking a key.** That
does not unpark D-012 — (a) is the harder half and is untouched — but it removes the
obligation that would otherwise have had to be designed, specified, proved, and paid for
alongside it. Anyone costing the ZK-spend variant after Hegotá should cost it as
"binding, plus a `nonce_key`", not "binding, plus a nullifier subsystem".

Scope honesty: the fully note-shaped variant, where value lands in a shared pool and the
nullifier does all the work, is **not** an ERC-5564 scheme — value there does not land at
an address the sender named. That is the Native-UTXO direction plan.md already points at,
and keyed nonces make it substantially cheaper to specify. It is adjacent work, not a
change to this ERC.

---

## 6. The derivation trap: never derive the nonce key from the shared secret

The obvious derivation is `k = H(ss)`. **It is wrong, and wrong in a way specific to this
scheme.**

`ss` is the ML-KEM shared secret, and in a stealth scheme the *sender* computes it — they
encapsulated it. Meanwhile `nonce_keys` are public payload fields, exposed in-protocol via
`TXPARAM 0x0F` / `0x10`, and the consumed slot at `keccak(pad32(sender) ‖ bytes32(k))` in
`NONCE_MANAGER` is permanent, publicly readable state. So `k = H(ss)` would hand every
payer a permanent, publicly checkable oracle: *has my payment been spent yet, and in which
transaction*.

**How much this costs depends on the variant, and it is worth being exact.** In today's
construction-A shape the payer already has a spend oracle: they know the stealth address,
value visibly leaves it, and that stays true under the §4 shared sponsor — mixing the
`sender` field does not hide the value edge. So an `ss`-derived key gives the payer no
*information* they could not already get; it only makes the lookup cheaper (a storage read
keyed to the sponsor, rather than watching an address) and permanent.

It becomes decisive the moment the nonce key is the **only** public per-payment tag —
which is exactly the direction §5 points at, and exactly what a gas-bank-style draw would
be. In a pooled or ZK-spend variant the value edge is gone by construction, and an
`ss`-derived key would put the payer's link straight back, keyed to the one party we most
want excluded. The rule below costs nothing to follow, so it should be adopted
unconditionally rather than when the variant that needs it arrives.

**Rule.** The nonce key MUST be derived from a value the sender cannot compute, bound to
public per-payment data so keys never collide across payments:

```
k = SHAKE256( "PQSAP-nonce-key-v1" ‖ K_null ‖ ct )   truncated to 256 bits,  k != 0
```

- `K_null` — a **nullifying key** derived from the recipient's master seed under its own
  domain separator. The sender cannot compute it; the recipient regenerates it
  deterministically. It may be derived from the ML-DSA spend secret instead, since whoever
  spends holds it — but keeping it separate lets a watch-only scanner hold the detection
  key `dk` without gaining the ability to compute spend tags.
- `ct` — the announcement's ML-KEM ciphertext. Public, distinct per payment, already in
  the announcement, so no extra bytes anywhere.
- `k != 0` and the domain separator are EIP-8250's own MUSTs. The **sender-uncomputable**
  requirement is ours: the EIP does not state it, because it does not have a party that
  knows the payment secret and is not the spender. This is worth carrying upstream as
  feedback on 8250's Security Considerations.

**Key-hierarchy consequence.** This makes a third key alongside detection (`dk`) and spend
— small, but a real spec change: the recipient's seed must derive `(dk, spend, K_null)`
under distinct domain separators, and a watch-only export must be able to omit `K_null`.

**Free side effect, both ways.** Because the key is used exactly once, `nonce_seq` is 0
before the spend and 1 forever after, so `slot(sender, k)` is a public "already spent"
flag. A recipient's own wallet can answer "which of my payments are still unspent" with a
storage read per payment instead of a transfer scan — genuinely useful. Anyone who learns
`K_null` gets the same view over every payment the recipient ever received, retroactively
and permanently. `K_null` is therefore a *linking* key with the same disclosure profile as
a viewing key, and the spec must say so.

---

## 7. Costs, against D-020's hard constraint

D-020's binding constraint is the mempool validation prefix: `MAX_VERIFY_GAS = 100,000`
**execution** gas, 500,000 **state** gas, and no measured PQ verifier fits the execution
half (C13 at 188,092 gas tx-level; ML-DSA at ~15M — out by two orders of magnitude).

Neither EIP moves that number; both add a state-gas line item:

| Mechanism | Per-spend cost | Permanent state | Fits the 500k state budget |
| --- | --- | --- | --- |
| Legacy nonce (`[0]`) | `STATE_BYTES_PER_NEW_ACCOUNT × CPSB` if the sender is fresh | account | yes |
| Keyed nonce, first use | 97,920 state gas per fresh key | one slot, forever | yes — but ≤5 fresh keys |
| Expiring nonce | 13,000 flat | none (ring, net zero) | yes, comfortably |

Two readings:

- A stealth scheme generates one payment per announcement, so an 8250-per-payment design
  buys **one permanent state slot per payment, network-wide, forever.** For a project whose
  headline cost finding is "on-chain cost is data, not compute" (D-011: the announcement is
  already pinned to the EIP-7623 calldata floor at 67,580 gas), quietly adding permanent
  state per payment is the wrong direction and we should say so out loud rather than
  discover it in review.
- It strengthens, rather than weakens, D-020's working-group ask. The ask was a
  protocol-validated PQ signature identifier or a raised verify budget. Add: **if 8250
  lands, the state-gas budget also has to accommodate at least one first-use keyed nonce
  alongside a PQ verification** — 97,920 of 500,000 is a fifth of the state budget spent
  before validation begins.

---

## 8. What this does not fix

Stated plainly, because the temptation to oversell a protocol-level gift is real:

- **Not verification cost.** PQ verification stays in the millions of gas (D-007, D-020).
  Nothing here helps the public-mempool admission problem.
- **Not the announcement.** 1,088-B ciphertext, 67,580-gas calldata floor, unchanged (D-011).
- **Not the value graph.** A shared sponsor mixes the *sender* and *gas-funding* edges. The
  value still leaves a unique stealth address the payer named. The gain is bounded to the
  sponsor side, and the ERC text must not imply otherwise.
- **Not deployment cost.** Each stealth address still deploys its own account and key blob
  (D-014/D-020: keys never in initcode). Keyed nonces are about replay domains, not code.
- **Not available.** Both EIPs are **Draft**, neither is scheduled, and EIP-8141 itself is
  only SFI for Hegotá. `serialize.ts` tracks *deployed* ethrex on chain 81410 for exactly
  this reason.

---

## 9. Recommendation

1. **Default to EIP-8266, not EIP-8250, for the mainline spend.** We need freshness, not a
   nullifier; the balance is our double-spend defence. 13,000 gas and no permanent state
   beats 97,920 gas and a slot per payment. Accept the 60-second deadline; note it as a
   constraint for pre-signed spends.
2. **Adopt the shared-sponsor pattern as the target frames spend shape** once either EIP
   ships, and retire the per-recipient throwaway sponsor. Record it as the completion of
   D-020's gas-funding-privacy item — paymaster frames fix the payer, nonce independence
   fixes the sender.
3. **Fix the derivation rule now, in the spec, before anyone implements it.** Nonce keys
   MUST be derived from a recipient-only `K_null`, domain-separated, bound to `ct`, never
   from `ss`. Add `K_null` to the key hierarchy with viewing-key disclosure semantics.
4. **Re-cost the D-012 ZK-spend variant** with the non-replay obligation removed. It stays
   parked on address-binding, but the cost line is now "binding + one `nonce_key`", and the
   prize is unchanged: 5,633 B → 1,217 B meta-address, KEM decoupled from spend.
5. **Carry two items to the EIP authors.** (a) The sender-uncomputable requirement belongs
   in 8250's Security Considerations — schemes where a third party knows the payment secret
   need it, and 8250's own privacy framing invites exactly those schemes. (b) The D-020 ask
   should now cover state gas as well as execution gas in the validation prefix.

Nothing here changes vectors, the Python reference, or any locked decision. Items 1–3 are
spec-text changes to make before the ERC freeze; items 4–5 are follow-ups.

## Sources

- [EIP-8250: Keyed Nonces for Frame Transactions](https://eips.ethereum.org/EIPS/eip-8250)
  ([discussion](https://ethereum-magicians.org/t/eip-8250-keyed-nonces-for-frame-transactions/28437))
- [EIP-8266: Expiring Nonces for Frame Transactions](https://eips.ethereum.org/EIPS/eip-8266)
  ([discussion](https://ethereum-magicians.org/t/eip-8266-expiring-nonces-for-frame-transactions/28575))
- [EIP-8141: Frame Transaction](https://eips.ethereum.org/EIPS/eip-8141)
- In-repo: `docs/DECISIONS.md` D-003, D-007, D-008, D-011, D-012, D-014, D-018, D-020;
  `js-client/contracts/src/frames/Stealth8141Account.sol`;
  `js-client/src/frame-tx/serialize.ts`; `ui/src/lib/frames.ts`; `ui/src/lib/throwaway.ts`.
