import PqStealth.Blinding
import PqStealth.Invariants
import PqStealth.Games
import PqStealth.KEMAnonymity
import PqStealth.MultiUnlink
import PqStealth.ConstructionA
import PqStealth.SharedSecretHiding
import PqStealth.AnonymityFromSPR
import PqStealth.MLKEM
import PqStealth.Ownership
import PqStealth.DKSAP
import PqStealth.Demo
import PqStealth.Controls
import PqStealth.Axioms

/-!
# PqStealth — machine-checked core for post-quantum stealth addresses

Importing this module brings in the whole development and, via
`PqStealth.Axioms`, runs the axiom audit as part of the build. Twelve content
modules in three layers: the algebraic core (`Blinding`, `Invariants`); the
game layer (`Games`, `KEMAnonymity`, `ConstructionA`, `SharedSecretHiding`,
`AnonymityFromSPR`, `MLKEM`, `Ownership`); the classical comparison and
controls (`DKSAP`, `Controls`, `Demo`).

Reading order: `Demo` → `DKSAP` → `Blinding` → `Games` → `KEMAnonymity` →
`ConstructionA` → `SharedSecretHiding` → `AnonymityFromSPR` → `MLKEM` →
`Ownership` → `Controls`. Map: `README.md`; design essays: `docs/`.
-/
