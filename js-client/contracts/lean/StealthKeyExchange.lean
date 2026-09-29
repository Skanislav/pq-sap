import StealthKeyExchange.Params
import StealthKeyExchange.Contract
import StealthKeyExchange.Vectors
import StealthKeyExchange.Axioms

/-!
# StealthKeyExchange — a machine-checked model of the on-chain key-exchange layer

The Lean side of `js-client/contracts/src/StealthKeyExchange.sol`. Four modules:
`Params` (the parameter table and its consistency), `Contract` (the state
machine and its theorems), `Vectors` (the conformance vectors replayed through
the model, generated), `Axioms` (the audit). Map and reading order: `README.md`.
-/
