import PqStealth.Blinding
import PqStealth.Invariants
import PqStealth.Games
import PqStealth.KEMAnonymity
import PqStealth.MultiUnlink
import PqStealth.MultiRecipient
import PqStealth.ConstructionA
import PqStealth.BlindingROM
import PqStealth.SharedSecretHiding
import PqStealth.AnonymityFromSPR
import PqStealth.MLKEM
import PqStealth.SPRTwoHop
import PqStealth.Ownership
import PqStealth.DKSAP
import PqStealth.DKSAPOracle
import PqStealth.ROMUpToBad
import PqStealth.Reorder
import PqStealth.Soundness
import PqStealth.Demo
import PqStealth.Controls
import PqStealth.Axioms

/-!
# PqStealth — machine-checked core for post-quantum stealth addresses

Importing this module brings in the whole development and, via
`PqStealth.Axioms`, runs the axiom audit as part of the build. Twenty content
modules in three layers: the algebraic core (`Blinding`, `Invariants`); the
game layer (`Games`, `Reorder`, `MultiUnlink`, `MultiRecipient`, `KEMAnonymity`,
`ConstructionA`, `ROMUpToBad`, `BlindingROM`, `SharedSecretHiding`,
`AnonymityFromSPR`, `MLKEM`, `SPRTwoHop`, `Ownership`, `Soundness`); the
classical comparison and controls (`DKSAP`, `DKSAPOracle`, `Controls`, `Demo`).

Reading order: `Demo` → `DKSAP` → `ROMUpToBad` → `DKSAPOracle` → `Blinding` →
`Games` → `MultiUnlink` → `MultiRecipient` → `KEMAnonymity` → `ConstructionA` →
`BlindingROM` → `SharedSecretHiding` → `AnonymityFromSPR` → `MLKEM` →
`SPRTwoHop` → `Ownership` → `Soundness` → `Controls`. Map: `README.md`; design
essays: `docs/`.
-/
