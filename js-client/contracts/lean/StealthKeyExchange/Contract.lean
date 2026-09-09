import StealthKeyExchange.Params

/-!
# A functional model of `StealthKeyExchange.sol`

The contract's state is its registry array plus what it can append to the
ERC-5564 announcer's log; its three state-changing entry points are total
functions from `(state, calldata)` to `Except Error (result × state)`, one
`Except.error` per custom error. Every `if`/`revert` in the Solidity has one
line here in the same order, so the correspondence is by inspection (the
Foundry tests replay the same conformance vectors against the real bytecode,
and `scripts/check_constants.py` pins the shared numbers). What this module
then proves, once and for all inputs:

* `announce_toBool` — `announce` succeeds exactly when `isValidAnnouncement`
  holds (a ciphertext of a supported length, a view tag present);
* `announce_ok` — on success the log gains exactly one entry, at the end,
  carrying scheme ID `2` and the caller's `stealthAddress`, ciphertext and
  metadata unchanged, and the registry is untouched;
* `announce_no_registry_read` — the announcement path does not read the
  registry: its outcome and the appended entry are the same for every registry
  content. There is no input through which an announcement could reference a
  recipient's registered key;
* `registerViewingKey_*` — the registry is append-only: registration succeeds
  exactly on the supported key lengths, assigns the next index, stores the
  bytes and their set, and leaves every earlier index resolving to what it did;
* `kemOfMetaAddress_*` — a meta-address is typed by its version byte and length.
-/

namespace StealthKeyExchange

/-- Byte strings (`bytes calldata`). -/
abbrev Bytes := List UInt8

/-- EVM addresses, kept abstract: the model never inspects one. -/
abbrev Address := Nat

/-- One `Announcement` event of the ERC-5564 announcer. -/
structure Announcement where
  /-- ERC-5564 scheme ID. -/
  schemeId : Nat
  /-- The announced stealth address. -/
  stealthAddress : Address
  /-- `msg.sender` as the announcer sees it — this contract, for forwarded announcements. -/
  caller : Address
  /-- The KEM ciphertext, in the `ephemeralPubKey` slot. -/
  ephemeralPubKey : Bytes
  /-- `metadata[0]` is the view tag. -/
  metadata : Bytes
  deriving DecidableEq, Repr

/-- A registry entry (`struct ViewingKey`, with the SSTORE2 pointer dereferenced). -/
structure ViewingKey where
  /-- The set the key's length identified at registration. -/
  kem : Kem
  /-- The encapsulation key bytes. -/
  ek : Bytes
  deriving DecidableEq, Repr

/-- Everything the contract can read or write. -/
structure State where
  /-- The contract's own address (`address(this)`). -/
  self : Address
  /-- `_keys`. -/
  keys : Array ViewingKey
  /-- The ERC-5564 announcer's event log, oldest first. -/
  log : List Announcement
  deriving DecidableEq, Repr

/-- The contract's custom errors. -/
inductive Error where
  /-- `UnsupportedCiphertextLength(length)`. -/
  | unsupportedCiphertextLength (length : Nat)
  /-- `UnsupportedEncapsulationKeyLength(length)`. -/
  | unsupportedEncapsulationKeyLength (length : Nat)
  /-- `UnsupportedMetaAddress(length, version)`. -/
  | unsupportedMetaAddress (length : Nat) (version : UInt8)
  /-- `MissingViewTag()`. -/
  | missingViewTag
  /-- `NoSuchViewingKey(index)`. -/
  | noSuchViewingKey (index : Nat)
  deriving DecidableEq, Repr

/-! ## Pure functions -/

/-- `isValidAnnouncement`: the shape predicate wallets can pre-check. -/
def isValidAnnouncement (ct md : Bytes) : Bool :=
  (kemOfCiphertextLength ct.length).isSome && decide (viewTagBytes ≤ md.length)

/-- `viewTagOf`. -/
def viewTagOf (md : Bytes) : Except Error UInt8 :=
  match md with
  | [] => .error .missingViewTag
  | b :: _ => .ok b

/-- `kemOfMetaAddress`: version byte and total length determine the set. -/
def kemOfMetaAddress (ma : Bytes) : Except Error Kem :=
  match ma with
  | [] => .error (.unsupportedMetaAddress 0 0)
  | v :: _ =>
    if v = metaVersionMlkem then
      if ma.length = Kem.mlkem768.metaAddressBytes then .ok .mlkem768
      else if ma.length = Kem.mlkem512.metaAddressBytes then .ok .mlkem512
      else if ma.length = Kem.mlkem1024.metaAddressBytes then .ok .mlkem1024
      else .error (.unsupportedMetaAddress ma.length v)
    else if v = metaVersionXwing then
      if ma.length = Kem.xwing.metaAddressBytes then .ok .xwing
      else .error (.unsupportedMetaAddress ma.length v)
    else .error (.unsupportedMetaAddress ma.length v)

/-! ## Entry points -/

/-- The event `announce` forwards to the ERC-5564 announcer. -/
def forwarded (s : State) (stealthAddress : Address) (ct md : Bytes) : Announcement :=
  { schemeId := schemeId, stealthAddress := stealthAddress, caller := s.self,
    ephemeralPubKey := ct, metadata := md }

/-- `announce(stealthAddress, ciphertext, metadata)`: type the ciphertext by its
length, require the view tag, forward. Note the signature: no registry index,
no recipient key — nothing recipient-identifying can enter an announcement. -/
def announce (s : State) (stealthAddress : Address) (ct md : Bytes) :
    Except Error (Kem × State) :=
  match kemOfCiphertextLength ct.length with
  | none => .error (.unsupportedCiphertextLength ct.length)
  | some kem =>
    if md.length < viewTagBytes then .error .missingViewTag
    else .ok (kem, { s with log := s.log ++ [forwarded s stealthAddress ct md] })

/-- `registerViewingKey(encapsulationKey)`: type the key by its length, append. -/
def registerViewingKey (s : State) (ek : Bytes) : Except Error (Nat × State) :=
  match kemOfEncapsulationKeyLength ek.length with
  | none => .error (.unsupportedEncapsulationKeyLength ek.length)
  | some kem => .ok (s.keys.size, { s with keys := s.keys.push { kem := kem, ek := ek } })

/-- `viewingKeyOf(index)`. -/
def viewingKeyOf (s : State) (i : Nat) : Except Error ViewingKey :=
  match s.keys[i]? with
  | some k => .ok k
  | none => .error (.noSuchViewingKey i)

/-- `viewingKeyCount()`. -/
def viewingKeyCount (s : State) : Nat := s.keys.size

/-! ## `announce` -/

/-- `announce` succeeds exactly when `isValidAnnouncement` holds. -/
theorem announce_toBool (s : State) (a : Address) (ct md : Bytes) :
    (announce s a ct md).toBool = isValidAnnouncement ct md := by
  unfold announce isValidAnnouncement
  cases kemOfCiphertextLength ct.length with
  | none => rfl
  | some kem =>
    simp only [Option.isSome_some, Bool.true_and]
    by_cases h : md.length < viewTagBytes
    · simp only [h, ↓reduceIte, Except.toBool, decide_eq_false (Nat.not_le.mpr h)]
    · simp only [h, ↓reduceIte, Except.toBool, decide_eq_true (Nat.not_lt.mp h)]

/-- The success case: exactly one entry appended to the log, the scheme ID, the
address, the ciphertext and the metadata forwarded unchanged, the registry and
the contract's identity untouched, and the returned set is the ciphertext's. -/
theorem announce_ok {s s' : State} {a : Address} {ct md : Bytes} {kem : Kem}
    (h : announce s a ct md = .ok (kem, s')) :
    s'.log = s.log ++ [forwarded s a ct md] ∧ s'.keys = s.keys ∧ s'.self = s.self ∧
      ct.length = kem.ciphertextBytes ∧ viewTagBytes ≤ md.length := by
  unfold announce at h
  split at h
  · exact nomatch h
  · rename_i kem' hk
    split at h
    · exact nomatch h
    · rename_i hmd
      cases Except.ok.inj h
      exact ⟨rfl, rfl, rfl, kemOfCiphertextLength_eq_some_iff.mp hk, Nat.not_lt.mp hmd⟩

/-- The forwarded entry is the input, byte for byte, under scheme ID `2`. -/
theorem forwarded_fields (s : State) (a : Address) (ct md : Bytes) :
    (forwarded s a ct md).schemeId = 2 ∧ (forwarded s a ct md).stealthAddress = a ∧
      (forwarded s a ct md).caller = s.self ∧ (forwarded s a ct md).ephemeralPubKey = ct ∧
      (forwarded s a ct md).metadata = md :=
  ⟨rfl, rfl, rfl, rfl, rfl⟩

/-- The failure case names the input that failed. -/
theorem announce_error {s : State} {a : Address} {ct md : Bytes} {e : Error}
    (h : announce s a ct md = .error e) :
    (e = .unsupportedCiphertextLength ct.length ∧ kemOfCiphertextLength ct.length = none) ∨
      (e = .missingViewTag ∧ md.length < viewTagBytes) := by
  unfold announce at h
  split at h
  · rename_i hk
    exact Or.inl ⟨(Except.error.inj h).symm, hk⟩
  · split at h
    · rename_i hmd
      exact Or.inr ⟨(Except.error.inj h).symm, hmd⟩
    · exact nomatch h

/-- The announcement path does not read the registry: replacing the registry
with anything gives the same outcome, the same appended entry, and the
replaced registry. Hence no announcement can depend on — or reveal — which
keys are registered. -/
theorem announce_no_registry_read (s : State) (keys : Array ViewingKey) (a : Address)
    (ct md : Bytes) :
    announce { s with keys := keys } a ct md =
      (announce s a ct md).map (fun r => (r.1, { r.2 with keys := keys })) := by
  unfold announce
  cases kemOfCiphertextLength ct.length with
  | none => rfl
  | some kem =>
    by_cases h : md.length < viewTagBytes
    · simp only [h, ↓reduceIte, Except.map]
    · simp only [h, ↓reduceIte, Except.map]
      rfl

/-- The log is append-only under `announce`: the old log is a prefix of the new one. -/
theorem announce_log_prefix {s s' : State} {a : Address} {ct md : Bytes} {kem : Kem}
    (h : announce s a ct md = .ok (kem, s')) : s.log.isPrefixOf s'.log = true := by
  rw [(announce_ok h).1]
  exact List.isPrefixOf_iff_prefix.mpr (List.prefix_append _ _)

/-! ## The registry -/

/-- Registration succeeds exactly on the supported encapsulation-key lengths. -/
theorem registerViewingKey_toBool (s : State) (ek : Bytes) :
    (registerViewingKey s ek).toBool = (kemOfEncapsulationKeyLength ek.length).isSome := by
  unfold registerViewingKey
  cases kemOfEncapsulationKeyLength ek.length <;> rfl

/-- The success case: the assigned index is the old count, the count grows by
one, the new slot holds the key and its set, every older index still resolves
to what it did, and nothing else moves. -/
theorem registerViewingKey_ok {s s' : State} {ek : Bytes} {i : Nat}
    (h : registerViewingKey s ek = .ok (i, s')) :
    i = s.keys.size ∧ s'.keys.size = s.keys.size + 1 ∧
      (∃ kem, kemOfEncapsulationKeyLength ek.length = some kem ∧
        s'.keys[i]? = some { kem := kem, ek := ek }) ∧
      (∀ j, j < s.keys.size → s'.keys[j]? = s.keys[j]?) ∧
      s'.log = s.log ∧ s'.self = s.self := by
  unfold registerViewingKey at h
  split at h
  · exact nomatch h
  · rename_i kem hk
    cases Except.ok.inj h
    refine ⟨rfl, Array.size_push .., ⟨kem, hk, Array.getElem?_push_size⟩, ?_, rfl, rfl⟩
    intro j hj
    show (s.keys.push _)[j]? = s.keys[j]?
    rw [Array.getElem?_push_lt hj, Array.getElem?_eq_getElem hj]

/-- `viewingKeyOf` succeeds exactly below the count. -/
theorem viewingKeyOf_toBool (s : State) (i : Nat) :
    (viewingKeyOf s i).toBool = decide (i < viewingKeyCount s) := by
  unfold viewingKeyOf viewingKeyCount
  by_cases h : i < s.keys.size
  · rw [Array.getElem?_eq_getElem h]
    simp only [Except.toBool, decide_eq_true h]
  · rw [Array.getElem?_eq_none (Nat.not_lt.mp h)]
    simp only [Except.toBool, decide_eq_false h]

/-- After a registration, the new index reads back the registered key with its
set, and every earlier index reads back exactly what it did before. -/
theorem viewingKeyOf_after_register {s s' : State} {ek : Bytes} {i : Nat}
    (h : registerViewingKey s ek = .ok (i, s')) :
    (∃ kem, kemOfEncapsulationKeyLength ek.length = some kem ∧
        viewingKeyOf s' i = .ok { kem := kem, ek := ek }) ∧
      ∀ j, j < s.keys.size → viewingKeyOf s' j = viewingKeyOf s j := by
  obtain ⟨-, -, ⟨kem, hk, hnew⟩, hold, -, -⟩ := registerViewingKey_ok h
  refine ⟨⟨kem, hk, ?_⟩, ?_⟩
  · unfold viewingKeyOf
    rw [hnew]
  · intro j hj
    unfold viewingKeyOf
    rw [hold j hj]

/-! ## Meta-addresses -/

/-- Soundness: a typed meta-address has the set's version byte and length. -/
theorem kemOfMetaAddress_ok {ma : Bytes} {k : Kem} (h : kemOfMetaAddress ma = .ok k) :
    ma.head? = some k.metaAddressVersion ∧ ma.length = k.metaAddressBytes := by
  unfold kemOfMetaAddress at h
  split at h
  · exact nomatch h
  · rename_i v rest
    split at h
    · rename_i hv
      split at h
      · rename_i hl
        cases Except.ok.inj h
        exact ⟨by rw [hv]; rfl, hl⟩
      · split at h
        · rename_i hl
          cases Except.ok.inj h
          exact ⟨by rw [hv]; rfl, hl⟩
        · split at h
          · rename_i hl
            cases Except.ok.inj h
            exact ⟨by rw [hv]; rfl, hl⟩
          · exact nomatch h
    · split at h
      · rename_i hv
        split at h
        · rename_i hl
          cases Except.ok.inj h
          exact ⟨by rw [hv]; rfl, hl⟩
        · exact nomatch h
      · exact nomatch h

deriving instance DecidableEq for Except

/-- Completeness: a byte string with a set's version byte and length is typed as
that set. -/
theorem kemOfMetaAddress_encode (k : Kem) (rest : Bytes)
    (h : rest.length + 1 = k.metaAddressBytes) :
    kemOfMetaAddress (k.metaAddressVersion :: rest) = .ok k := by
  have hl : (k.metaAddressVersion :: rest).length = k.metaAddressBytes := by
    rw [List.length_cons, h]
  simp only [kemOfMetaAddress, hl]
  cases k <;> decide

/-- Hence `kemOfMetaAddress` is exactly "version byte and length match". -/
theorem kemOfMetaAddress_ok_iff {ma : Bytes} {k : Kem} :
    kemOfMetaAddress ma = .ok k ↔
      ma.head? = some k.metaAddressVersion ∧ ma.length = k.metaAddressBytes := by
  constructor
  · exact kemOfMetaAddress_ok
  · rintro ⟨hv, hl⟩
    cases ma with
    | nil => exact nomatch hv
    | cons v rest =>
      cases Option.some.inj hv
      exact kemOfMetaAddress_encode k rest hl

end StealthKeyExchange
