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
import PqStealth.Ownership
import PqStealth.DKSAP
import PqStealth.Soundness
import PqStealth.Demo
import PqStealth.Controls
import PqStealth.Axioms

/-!
# PqStealth — machine-checked core for post-quantum stealth addresses

Importing this module brings in the whole development and, via
`PqStealth.Axioms`, runs the axiom audit as part of the build. Sixteen content
modules in three layers: the algebraic core (`Blinding`, `Invariants`); the
game layer (`Games`, `MultiUnlink`, `MultiRecipient`, `KEMAnonymity`,
`ConstructionA`, `BlindingROM`, `SharedSecretHiding`, `AnonymityFromSPR`,
`MLKEM`, `Ownership`, `Soundness`); the classical comparison and controls
(`DKSAP`, `Controls`, `Demo`).

Reading order: `Demo` → `DKSAP` → `Blinding` → `Games` → `MultiUnlink` →
`MultiRecipient` → `KEMAnonymity` → `ConstructionA` → `BlindingROM` →
`SharedSecretHiding` → `AnonymityFromSPR` → `MLKEM` → `Ownership` →
`Soundness` → `Controls`. Map: `README.md`; design essays: `docs/`.
-/
