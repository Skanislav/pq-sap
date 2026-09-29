import StealthKeyExchange.Contract
import StealthKeyExchange.Vectors

/-!
# Axiom audit

Same device as `lean/PqStealth/Axioms.lean`: each headline theorem's axiom
list is frozen by a `#guard_msgs`, so a `sorry` anywhere in its dependency
cone (which would add `sorryAx`) is a build error. The model is constructive
bookkeeping, so most theorems need no axioms at all; the ones that go through
`by_cases` or `simp` pick up `propext`, and `Classical.choice` where
`by_cases` decides a proposition classically.
-/

namespace StealthKeyExchange

/-- info: 'StealthKeyExchange.announce_toBool' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in
#print axioms announce_toBool

/-- info: 'StealthKeyExchange.announce_ok' does not depend on any axioms -/
#guard_msgs (whitespace := lax) in
#print axioms announce_ok

/-- info: 'StealthKeyExchange.announce_error' does not depend on any axioms -/
#guard_msgs (whitespace := lax) in
#print axioms announce_error

/-- info: 'StealthKeyExchange.announce_no_registry_read' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in
#print axioms announce_no_registry_read

/-- info: 'StealthKeyExchange.announce_log_prefix' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms announce_log_prefix

/-- info: 'StealthKeyExchange.registerViewingKey_toBool' does not depend on any axioms -/
#guard_msgs (whitespace := lax) in
#print axioms registerViewingKey_toBool

/-- info: 'StealthKeyExchange.registerViewingKey_ok' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in
#print axioms registerViewingKey_ok

/-- info: 'StealthKeyExchange.viewingKeyOf_toBool' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in
#print axioms viewingKeyOf_toBool

/-- info: 'StealthKeyExchange.viewingKeyOf_after_register' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in
#print axioms viewingKeyOf_after_register

/-- info: 'StealthKeyExchange.kemOfMetaAddress_ok_iff' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in
#print axioms kemOfMetaAddress_ok_iff

/-- info: 'StealthKeyExchange.kemOfCiphertextLength_eq_some_iff' does not depend on any axioms -/
#guard_msgs (whitespace := lax) in
#print axioms kemOfCiphertextLength_eq_some_iff

/-- info: 'StealthKeyExchange.kemOfEncapsulationKeyLength_eq_some_iff' does not depend on any axioms -/
#guard_msgs (whitespace := lax) in
#print axioms kemOfEncapsulationKeyLength_eq_some_iff

/-- info: 'StealthKeyExchange.Kem.metaAddressBytes_injective' does not depend on any axioms -/
#guard_msgs (whitespace := lax) in
#print axioms Kem.metaAddressBytes_injective

end StealthKeyExchange
