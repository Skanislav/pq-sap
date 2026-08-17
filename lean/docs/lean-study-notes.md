# Lean 4 study notes for the PqStealth development

Condensed from the two official books, read 2026-08-17 as preparation for
the improvement pass on `lean/PqStealth/` (see `improvements.md`):

- *Functional Programming in Lean* — https://lean-lang.org/functional_programming_in_lean/
- *Theorem Proving in Lean 4* — https://lean-lang.org/theorem_proving_in_lean4/

The two digests below are meant to be read next to the code. The items that
map directly onto this repo are: `abbrev` vs `def` for transparency to
instance search and `simp`; `#guard_msgs` + `#print axioms` for build-checked
axiom audits; `simp only` over bare `simp` for proofs that must survive
dependency bumps; `set_option autoImplicit false` (or the lakefile
equivalent) so a typo in a binder is an error rather than a fresh implicit;
`section`/`variable` scoping rules (only variables mentioned in a theorem's
*statement* are included, instance binders follow their dependencies — hence
the `omit ... in` dance in `DKSAPClassical.lean`); module docstrings `/-! -/`
for `doc-gen4`; and `termination_by`/`decreasing_by` when recursion is not
structural.

---

# Functional Programming in Lean — study digest

Source: https://lean-lang.org/functional_programming_in_lean/ (current Verso edition; chapters below follow its TOC). Assumes Haskell/OCaml/Rust background; focus is on what is *Lean-specific*.

## 1. Getting to Know Lean

**Commands.** `#eval e` evaluates (needs `Repr`/`ToString`/`ToExpr` for the result — a partial application errors with "Could not synthesize a `ToExpr`, `Repr`, or `ToString` instance for type String → String"). `#check e` shows a type without evaluating; `#check f` shows the signature with binder names, `#check (f)` shows the plain arrow type; `#check @f` shows *all* implicit/instance args. `example : T := e` type-checks without naming (good for functions/`do` blocks that `#eval` can't print).

**Definitions.** `def x : T := e`; functions `def add1 (n : Nat) : Nat := n + 1`. `:=` defines, `=` is propositional equality. Names are usable only after their definition (no forward refs). Curried: `Nat → Nat → Nat` = `Nat → (Nat → Nat)`; ASCII `->` works. Type ascription is `(e : T)`.

**`def` vs `abbrev` (gotcha).** `def NaturalNumber : Type := Nat` then `def n : NaturalNumber := 38` fails: `failed to synthesize OfNat NaturalNumber 38` — `def`s are *not* unfolded during instance search. Use `abbrev N : Type := Nat` (reducible) or `(38 : Nat)`. Same for bounds predicates and `Prop`-valued definitions used with `simp`/`decide`.

**Literals.** Untyped numerals default to `Nat`; `Nat` subtraction truncates: `(1 - 2 : Nat) = 0`; use `Int`. `0.0` is `Float`, `0` isn't. Numeric literals go through the `OfNat α n` class (see ch. 3).

**Structures.**
```lean
structure Point where
  x : Float
  y : Float
deriving Repr
def origin : Point := { x := 0.0, y := 0.0 }   -- or ⟨0.0, 0.0⟩ (needs known type)
def p2 : Point where x := 1; y := 2           -- `where` form
#eval { origin with x := 3 }                   -- functional update, original unchanged
```
Generates `Point.mk` (rename with `structure Point where point :: x : Float ...`) and accessors `Point.x`. Brace/anonymous-constructor syntax needs the expected type known: `{ x := 0.0, y := 0.0 : Point }` or `(⟨1, 2⟩ : Point)`; otherwise "invalid {...} notation, expected type is not known".

**Generalized dot notation (very Lean).** `e.f a b` calls `T.f` where `T` is the *head type of `e`*, inserting `e` as the *first explicit argument of type `T`* (not necessarily the first parameter): `def Point.modifyBoth (f : Float → Float) (p : Point)`, then `p.modifyBoth Float.floor`. Works for any namespace: `"a".append "b"`, `(4 : Nat).double` after `def Nat.double`.

**Inductive types & matching.**
```lean
inductive Nat where
  | zero : Nat
  | succ (n : Nat) : Nat
def isZero (n : Nat) : Bool := match n with
  | Nat.zero => true
  | Nat.succ k => false
```
Constructors live in the type's namespace (`Nat.succ`); use leading-dot `.succ k` when the expected type is known. Nat literal patterns: `| 0 => .. | n + 1 => ..` (right of `+` must be a literal; `2 + n` fails). Structural recursion is checked; termination is *required*: `evenLoops n` with unchanged arg fails "failed to infer structural recursion". Non-structural (e.g. `div (n - k) k`) needs `termination_by`/`decreasing_by`/`partial`.

**Polymorphism.** Type args are ordinary (explicit) params: `def replaceX (α : Type) (p : PPoint α) ...`; make them implicit with `{α : Type}`; or omit entirely — *auto-bound implicits*: any unbound lowercase/Greek identifier in a signature becomes an implicit param. Supply explicitly by name: `List.length (α := Int)`. Built-ins: `Option` (`none`/`some`; `Option (Option Int)` is fine, unlike nullables), `Prod` (`α × β`, `(a, b)`, right-assoc), `Sum` (`α ⊕ β`, `.inl`/`.inr`), `Unit` (`()`), `Empty`. Naming: `f?` returns `Option`, `f!` panics, `fD` takes a default. Gotchas: constructors can't take `Type` args unless the type is universe-bumped ("Invalid universe level"), no negative occurrences (`(MyType → Int) → MyType` rejected), and `#eval []` can't infer `α`.

**Conveniences.** Pattern-matching definitions (`def length : List α → Nat | [] => 0 | _ :: ys => ...`), simultaneous match `match n, xs with | 0, ys => ..` (matching a *tuple* `(n, xs)` breaks termination checking!), `let x := e` / `let (a, b) := e` / `let rec`, `fun x => ..`, `fun | 0 => .. | n+1 => ..`, `(· + 1)` section syntax (each `·` a param, left to right), `if let some x := e then .. else ..`, `s!"x = {x}"` (needs `ToString`), namespaces (`namespace N ... end N`, `open N`, `open N in cmd`, `open N (f g)`, `def N.f` defines into `N`). Strings: `String` is UTF-8 bytes + cached length; `.drop`/`.trimAscii`/`.dropWhile` return `String.Slice` (zero-copy) — call `.copy` to get a `String`; pattern arg can be a `Char`, `String`, or `Char → Bool`.

*Not covered by the book but standard:* `section ... end` scopes `open`/`variable`; `variable (α : Type) [Monad m]` declares params auto-added to following defs that mention them; `universe u`.

## 2. Hello, World!

`def main : IO Unit := IO.println "hi"`; run with `lean --run File.lean`. `main` may also be `IO UInt32` or `List String → IO UInt32`. `IO α` = "a description of effects that, when executed, throws or returns α"; evaluation ≠ execution. `do` blocks: `let x ← act` runs an action, `let x := e` binds a pure value, bare `act` sequences. Nested actions `(← act)` are hoisted to the enclosing `do` — but *not* out of `if` branches ("Nested action must be nested inside a `do` expression"), so both branches' effects run unconditionally if you hoist manually. IO actions are values: `def twice (a : IO Unit) : IO Unit := do a; a`, lists of actions, `pure ()`. `#eval` *executes* IO actions (stdin is empty; may re-run on edits). Layout is whitespace-sensitive; braces/semicolons possible but unidiomatic.

**Projects.** `lake new foo` → `Main.lean`, `Foo.lean`, `Foo/Basic.lean`, `lakefile.toml`, `lean-toolchain`; `lake build`, `lake exe foo`. Modules (`Foo/Basic.lean` = `import Foo.Basic`) are separate from namespaces. `partial def` for possibly-non-terminating functions (e.g. reading a stream) — excluded from proofs but doesn't infect callers; still needs an inhabited return type. `IO.FS.Stream`, `IO.getStdin/Stdout/Stderr`, `IO.FS.Handle.mk`, `System.FilePath` (single-field structure: `⟨"path"⟩`, `String` coerces to it), `ByteArray`, `USize`. `if`/`match` as *statements* in `do` get implicit `do` per branch.

## 3. Interlude: Propositions, Proofs, and Indexing

`Prop` is a universe of propositions; a proposition is a type, a proof a term of it. `theorem name : 1 + 1 = 2 := rfl` (definitional equality); tactics: `by decide` (decision procedure on closed terms), `by simp`, `by grind`. Connectives: `True.intro`, `And.intro`/`∧`, `Or.inl/inr`, `A → B`, `¬A = A → False`. Evidence as arguments: `def third (xs : List α) (ok : xs.length > 2) : α := xs[2]` and call `third xs (by decide)`. Indexing forms: `xs[i]` (needs a proof in scope, else "failed to prove index is valid"), `xs[i]?` (`Option`), `xs[i]!` (panic; needs `Inhabited α`), `xs[i]'h`. Gotcha: `xs [1]` with a space is function application. `simp` won't unfold a `def`-defined `Prop`; use `abbrev`.

## 4. Overloading and Type Classes

```lean
class Plus (α : Type) where
  plus : α → α → α
instance : Plus Nat where plus := Nat.add
def sum [Add α] [Zero α] : List α → α | [] => 0 | x :: xs => x + sum xs
```
Classes are structures; methods live in namespace `Plus`; `[C α]` is an *instance-implicit* found by search (not unification like `{}`); instances are anonymous by default and the most recent wins; instances may take `[Add α]` premises → recursive search. Operators desugar to *heterogeneous* classes: `+`→`HAdd.hAdd`, `*`→`HMul`, `++`→`HAppend`, `==`→`BEq.beq`, `<`→`LT.lt`, `&&&`/`|||`/`^^^`/`<<<`; homogeneous `Add`, `Mul`, `Append`, `Neg`, `AndOp`/`OrOp` (since `And`/`Or` are logic). Literals: `OfNat α n` (parameter is a *value*, e.g. `instance : OfNat Pos (n + 1)`), `Zero`, `One`. `outParam` marks class params determined by search (`class HPlus (α β : Type) (γ : outParam Type)`); without it, an unknown `γ` metavariable blocks search. `@[default_instance]` lets `HPlus.hPlus (5 : Nat)` default to `Nat → Nat`. Debug with `set_option trace.Meta.synthInstance true`.

Standard classes: `BEq` (Bool `==`) vs `=` (Prop; needs `Decidable` to use in `if`) — `instance : Decidable (x < y) := inferInstance ...`; `Ord`/`compare : α → α → Ordering` (`.lt/.eq/.gt`); `Hashable`/`mixHash`; `ToString`, `Repr`; `Functor` (`<$>`, laws: identity/composition); `deriving BEq, Hashable, Repr, Inhabited, Ord` (inline or `deriving instance BEq for T`; no handler for `ToString`). Arrays: `#[1,2]`, `xs.size`, `GetElem coll idx (elem : outParam) (inBounds : outParam)`; you can index by custom types (`GetElem (List α) Pos α (fun l n => l.length > n.toNat)`). Coercions: `Coe α β` (`Coe Pos Nat`, `Nat`→`Int`, `α`→`Option α`, chained), `CoeDep α x β` (per-value), `CoeSort` (structure-as-type), `CoeFun` (structure-as-function; `instance : CoeFun Adder (fun _ => Nat → Nat)`); force with `↑e`. Coercions fire only on a *type mismatch* with enough type info — `def x : Option Nat := 392` fails (`OfNat` error, not a mismatch), and they don't apply inside `e.field` targets. Only define `Coe α β` if it's total. Instances can be written `⟨...⟩`, `{ .. }`, or `where`.

## 5. Monads

Pattern: `Option`, `Except ε α` (`.error`/`.ok`), `WithLog`, `State σ α := σ → σ × α` all share `pure`/`andThen`. `infixl:55 " ~~> " => andThen` declares operators. Class:
```lean
class Monad (m : Type → Type) where
  pure : α → m α
  bind : m α → (α → m β) → m β     -- x >>= f
```
Laws: `bind (pure v) f = f v`, `bind v pure = v`, associativity. `Id` monad; when the monad is ambiguous pass `(m := Id)` ("typeclass instance problem is stuck"). `mapM`. `do` desugars: `let x ← E; rest` ⇒ `E >>= fun x => rest`; bare `E; rest` ⇒ `E >>= fun () => rest`; `let x := E` is a plain let; nested `(← E)` allowed. Real `IO` = `EIO IO.Error` = `EStateM`-style world-passing (`RealWorld` erased). `nomatch e` for uninhabited cases (`Empty`). Also: `def f (x y : α)` shared binder types, leading `.ctor`, or-patterns `| .a | .b => ..` (only common vars usable; result is duplicated per branch, so a shadowed outer name can silently be picked in one branch). Custom `Reader ρ α := ρ → α`, `Many` (lazy nondeterminism via `Unit → Many α` thunks).

## 6. Functors, Applicative Functors, and Monads

**Structure inheritance.** `structure Monster extends MythicalCreature where vulnerability : String` — stored as field `toMythicalCreature`; `Monster.mk ⟨true⟩ "sunlight"` (nested anonymous ctor!); `troll.small` works via dot-notation inserting `toMythicalCreature`, but `MythicalCreature.small troll` is a type error (no subtyping; "upcast" *erases* fields). Multiple inheritance with diamonds: first parent's copy is stored, others' fields copied; `#print` shows it. Default field values `large := size == .large` are only defaults — invariants need a `Prop` field/subtype. Classes extend classes the same way with default methods.

**Applicative.** `class Applicative f extends Functor f where pure; seq : f (α → β) → (Unit → f α) → f β`; `E1 <*> E2 = Seq.seq E1 (fun () => E2)` (thunk = laziness). `Validate ε α` accumulates errors (`NonEmptyList`), unlike `Except`; but a type with both `Applicative` and `Monad` must have `seq` agree with the bind-derived one — so `Validate` should *not* be a monad. Laws: identity, composition, homomorphism, interchange. `Alternative f extends Applicative f` with `failure`, `orElse` (`<|>`, lazy second arg via `Unit →`), `guard`; `*>`, `<*`; `OrElse`, `SeqRight` classes. Subtypes: `{x : Nat // x > 0}` = `Subtype`, values `⟨n, proof⟩`; `if h : p then .. else ..` (dependent if) binds evidence `h`; `by simp`, `by decide`, `by simp [*]` inline. Gotcha: `[Decidable (p v)]` must come *after* `v` and `p` in the binder list.

**Universes.** `Prop : Type`, `Type = Type 0 : Type 1 : ...`; `Sort 0 = Prop`, `Sort (u+1) = Type u`. No cumulativity. Universe-polymorphic defs: `inductive MyList (α : Type u) : Type u`, `Sum (α : Type u) (β : Type v) : Type (max u v)`; levels: `0`, `u`, `max u v`, `u + 1`, `imax`. Function type lives in max of both, *except* anything returning `Prop` is in `Prop`. Errors: "Invalid universe level in constructor … not less than or equal to the inductive type's resulting universe level". Full library classes are `Functor (f : Type u → Type v) : Type (max (u+1) v)` with `map`, `mapConst`; `Pure`, `Seq`, `SeqLeft`, `SeqRight`, `Bind`; `Monad extends Applicative, Bind` with defaults so only `pure`+`bind` are needed.

## 7. Monad Transformers

`ReaderT ρ m α := ρ → m α`; `abbrev ConfigIO := ReaderT Config IO` (must be `abbrev`, or library instances are hidden). Classes: `MonadReader ρ m` (`read`), `MonadWithReader` (`withReader f act`), `MonadLift m n` (`monadLift`) — Lean *auto-inserts* lifts on type mismatch, so plain `IO` actions work inside `ReaderT Config IO`; `.run cfg` unwraps. `OptionT m α := m (Option α)`, `ExceptT ε m α := m (Except ε α)`, `StateT σ m α := σ → m (α × σ)`; each has `.mk`/`.run` (needed to steer inference — cryptic "expected α but got Option α" otherwise), a `Monad` instance and `MonadLift`. Universe gotcha: `ExceptT` needs `ε` and `α` in the *same* `Type u`. Effect classes: `MonadExcept ε m` (`throw`, `tryCatch`, `try .. catch | pat => ..`), `MonadState σ m` (`get`, `set`, `modify`, `modifyGet`), `MonadStateOf`/`getThe σ`/`modifyThe σ` (`semiOutParam`) for stacks with several states; `export MonadReader (read)` re-exports. Order matters: `StateT σ (ExceptT ε Id)` rolls state back on exception; `ExceptT ε (StateT σ Id)` keeps it (like most imperative langs); `StateT`/`ReaderT` commute, `StateT`/`ExceptT` don't.

**Imperative `do`.** `if c then act` (no else ⇒ `pure ()`), `unless c do act`, `return e` (early exit of *the current* `do` — implemented via `ExceptT`), `let mut x := 0; x := x + 1` (via `StateT`; only mutable in the same block, not in nested `let rec`/`fun`/`let y := do ..`; `let y ← do ..` *is* the same block), `for x in xs do ..` (`ForIn`/`ForM`), `for h : i in 0...xs.size do xs[i]`, ranges `a...b`, `a...=b`, `a<...b`, `*...b`, parallel `for x in xs, y in ys`, `break`/`continue`, `repeat`, `while c do`, `Id.run do ..` for pure code. Pipes: `x |> f`, `f <| x`, `xs |>.reverse |>.drop 1`.

## 8. Programming with Dependent Types

```lean
inductive Vect (α : Type u) : Nat → Type u where
  | nil : Vect α 0
  | cons : α → Vect α n → Vect α (n + 1)
def Vect.zip : Vect α n → Vect β n → Vect (α × β) n
  | .nil, .nil => .nil
  | .cons x xs, .cons y ys => .cons (x, y) (zip xs ys)   -- no missing cases
```
Params (before `:`) are fixed across constructors and don't raise the universe; indices (after `:`) vary and force `Type (u+1)`-style bumps; params must precede indices; Lean auto-promotes uniform post-colon args to params ("Mismatched inductive type parameter" if you vary a named param). Dependent pattern matching refines the expected type per branch; matching a variable-indexed value can leave you unable to pick any constructor. Universe design pattern: codes + `abbrev asType : Code → Type` interpretation, then recursion over codes (type-class search cannot enumerate `BEq t.asType`; write `def beq (t) : t.asType → ..`). `mutual ... end` for mutual recursion. Typed-queries example: `abbrev Row : Schema → Type` computed by cases (`[]`, `[c]`, `c1 :: c2 :: cs` — functions must mirror the same case split), `HasCol`/`Subschema` as `Type`-valued families, evidence built with `by repeat constructor`, `Bool` coerced to `Prop`, `macro`. Pitfalls: definitional equality is by *computation*, so `Nat.plusL 0 k` reduces but `Nat.plusR 0 k` is stuck (recursion on the 2nd arg) — implementation leaks into the interface; fix with propositional equality and rewriting `proof ▸ e` (`plusR_zero_left k ▸ ys`), `congrArg`, `rfl`. Idiomatic Lean prefers subtypes + separate propositions over heavy indexed families.

## 9. Interlude: Tactics, Induction, and Proofs

`theorem t (k : Nat) : k = Nat.plusR 0 k := by induction k with | zero => rfl | succ n ih => simp [Nat.plusR]; assumption`. Tactics: `induction x with | ctor a ih => ..` (or `case succ n ih => ..`; unnamed hyps get `n✝`), `rfl`, `unfold f`, `rw [h]`/`rw [← h]`, `simp [f, g]`, `exact h` (name-brittle), `assumption`, `skip`, `intro`, `cases h`, `constructor`, `apply`, `funext`, `omega`, `simp +arith`, `fun_induction f`, `grind [facts]` (uses hypotheses; all-or-nothing), `sorry`. Combinator `t1 <;> t2` applies `t2` to all goals of `t1` ("tactic golf": `induction t <;> grind [BinTree.mirror, BinTree.count]`). Induction on any inductive type gives one IH per recursive field.

## 10. Programming, Proving, and Performance

Tail calls: only *self* tail calls are eliminated; use accumulators (`sumHelper (soFar : Nat)`); non-tail `sum` overflows around 200k elements. Prove equivalence with `funext xs; induction xs`; generalize the accumulator by putting it *after* the colon (`(n : Nat) → n + NonTail.sum xs = Tail.sumHelper n xs`) so the IH is ∀-quantified. Arrays/termination: `if h : i < arr.size then .. arr[i] ..` supplies the bounds proof; `termination_by arr.size - i` (or `termination_by?` for a suggestion); `have : measure_decreases := by grind [...]` right before the recursive call; `decreasing_by` for a custom tactic; test first with `partial`; `Nat.le` is an inductive relation (`refl`/`step`), `n < m := n + 1 ≤ m`; `div` needs `(ok : k ≠ 0)`. `Fin n` = `{val : Nat, isLt : val < n}` (literals wrap modulo `n`!), `Array.find : .. → Option (Fin arr.size × α)`. Insertion sort: `arr.swap i j`, `Fin` for indices, `fun_induction insertSorted <;> grind`; arrays mutate in place when RC = 1 — check with `dbgTraceIfShared "msg" arr` (compiled code, not `#eval`; read input from stdin so the compiler can't constant-fold). Special runtime reps: `Nat`/`Int` (bignums), `UIntN`/`USize`, `Char`, `String`, `Array` (avoid `Array.mk`/`.toList`, `String.toByteArray` in hot code — linear conversions), types and proofs erased, single-data-field structures (subtypes, `Fin`) unboxed, nullary constructors are constants.

## 11. Next Steps

Pointers to *Theorem Proving in Lean 4*, the Lean reference manual, *Metaprogramming in Lean 4*, Zulip, Mathlib community, Software Foundations (Rocq), *Type-Driven Development with Idris*, *The Little Typer*.

### Cross-cutting gotchas for Haskell/OCaml/Rust folks
- Whitespace/indentation-sensitive layout; `def` bodies via `:=`; no top-level type inference of arguments (annotate binders).
- Termination is mandatory; `partial` opts out (and bars proofs); `termination_by`/`decreasing_by`/`have` are the escape hatches.
- `{}` = unification-solved implicit, `[]` = instance-search implicit, `()` explicit; `@f` exposes everything; auto-bound implicits for free type variables.
- Type classes ≈ Haskell classes but params can be values, `outParam` controls search direction, instances are anonymous, latest wins; `deriving` limited set.
- `Prop` vs `Bool`: `=`/`<` are `Prop`, `==` is `Bool`; `if` on a `Prop` needs `Decidable`; `decide`/`simp`/`omega`/`grind` discharge obligations inline; `def`s are opaque to these — use `abbrev`.
- Structures: no subtyping; `extends` nests; dot notation is name-based and inserts coercions/projections; `⟨⟩` needs a known type.
- `do` is much richer than Haskell's (`let mut`, `for`, `return`, `←` nested), but block boundaries and `:=`-vs-`←` matter.
- Universes are explicit and non-cumulative; indices vs parameters change universe levels.


---

# Theorem Proving in Lean 4 — Study Digest

Source: https://lean-lang.org/theorem_proving_in_lean4/ (Verso edition, chapters 2–12). Everything below is from the book unless marked **[not in TPIL]**.

---

## 2. Dependent Type Theory

**Concepts.** Every term has a type; types are terms too. Universe hierarchy: `Prop = Sort 0`, `Type = Type 0 = Sort 1`, `Type u = Sort (u+1)`, `Type u : Type (u+1)`. `Prop` is impredicative and proof-irrelevant. Dependent function ("Pi") type `(a : α) → β a` generalises `α → β`; dependent pair (Sigma) `(a : α) × β a` / `Σ a : α, β a` generalises `α × β`. Arrows associate right; application associates left; `fun x y => ..` curries.

```lean
universe u
def F (α : Type u) : Type u := Prod α α        -- or def F.{u} ...
#check @List.cons   -- {α : Type u_1} → α → List α → List α
#eval (fun x : Nat => x + 5) 10               -- 15 (compiled)
#reduce (fun x : Nat => x + 5) 10             -- kernel reduction, can differ in speed
def compose (g : β → γ) (f : α → β) (x : α) := g (f x)   -- auto-bound implicits α β γ
def h (x : Nat) := let y := x + 1; y * y      -- let is definitionally unfolded (unlike have)
section
  variable {α : Type u} (x : α)               -- inserted as params only where used
  def ident := x
end
namespace Foo ... end Foo ; open Foo
```

**Implicit args.** `{α : Type}` inserted eagerly; `@f` makes all explicit (`@id Nat 1`); `(e : T)` ascription steers elaboration; `_` = "please infer". `⦃x⦄` (strict/weak implicit) only inserted before a following explicit arg. `[C α]` = instance implicit.

**Gotchas.** `#check ident` shows signature; `#check (ident)` shows the type with metavariables. Numerals default to `Nat`. Unused vars → linter warning; prefix `_`. `set_option autoImplicit false` to disable auto-bound implicits.

---

## 3. Propositions and Proofs

**Curry–Howard.** `p : Prop`, a proof is `t : p`. `theorem` = `def` but irreducible and only variables in the *statement* become params. Any two proofs of `p` are definitionally equal.

| Connective | Intro | Elim |
|---|---|---|
| `p → q` | `fun hp => ..` | application |
| `p ∧ q` | `And.intro`, `⟨hp, hq⟩` | `h.left/h.1`, `h.right/h.2` |
| `p ∨ q` | `Or.inl`, `Or.inr` | `Or.elim h f g`, `h.elim` |
| `¬p` (= `p → False`) | `fun hp => ..` | `hnp hp : False`, `absurd hp hnp : q` |
| `p ↔ q` | `Iff.intro`, `⟨mp, mpr⟩` | `h.mp`, `h.mpr` |
| `True`/`False` | `True.intro`/`trivial` | `False.elim`, `h.elim` |

Precedence: `¬` > `∧` > `∨` > `→` > `↔`. Anonymous constructor `⟨_, _⟩` works for single-constructor types (`And`, `Iff`, `Exists`, structures) — **not** `Or`; nested `⟨a, b, c⟩` right-associates.

```lean
example (h : p ∧ q) : q ∧ p :=
  have hp : p := h.left
  suffices hq : q from ⟨hq, hp⟩
  show q from h.right
open Classical
theorem dne (h : ¬¬p) : p := (em p).elim id (fun hnp => absurd hnp h)
example (h : ¬¬p) : p := byContradiction fun h1 => h h1
example : p := byCases (fun hp : p => ..) (fun hnp : ¬p => ..)
```

**Gotchas.** `sorry` closes anything (warning; equivalent to an axiom `sorryAx`; shown by `#print axioms`). `_` in a proof gives an error listing the missing goal. Peirce, `¬(p ∧ q) → ¬p ∨ ¬q`, `(p → q) → ¬p ∨ q` need `Classical`.

---

## 4. Quantifiers and Equality

`∀ x : α, p x` *is* `(x : α) → p x`; intro = `fun x => ..`, elim = application. `∃ x, p x` is `Exists (fun x => p x)`, an inductive `Prop`.

```lean
example (h : ∃ x, p x ∧ q x) : ∃ x, q x ∧ p x :=
  match h with | ⟨w, hpw, hqw⟩ => ⟨w, hqw, hpw⟩
example : (∃ x, p x ∧ q x) → ∃ x, q x ∧ p x := fun ⟨w, hpw, hqw⟩ => ⟨w, hqw, hpw⟩
example (h : ∃ x, p x) : q := Exists.elim h (fun w hw => ..)   -- Exists.elim only to Prop
```

**Equality.** `Eq.refl a`, `rfl`, `h.symm`, `Eq.trans h₁ h₂` / `h₁.trans h₂`, `Eq.subst h hp : p b` (`h : a = b`, `hp : p a`), macro `h ▸ e` (rewrites in either direction, better heuristics), `congrArg f h`, `congrFun h a`, `congr h₁ h₂`. `rfl` proves anything definitional: `2 + 3 = 5`, `(fun x => f x) a = f a`. Higher-order unification for the motive is undecidable — supply `(motive := ..)` if `▸`/`Eq.subst` fails.

**calc.** Chain any relations with `Trans` instances (mix `=`, `<`, `≤`, `↔`…):

```lean
calc a = b     := h1
  _ = c + 1    := h2
  _ < d        := Nat.lt_of_.. 
```

Also `show t from e`, `show t; exact e` in tactics. Impredicativity: `∀ p : Prop, ..` is again a `Prop`.

---

## 5. Tactics (core chapter)

`by tac₁; tac₂` or newline-separated. Focus with `case tag => ..`, bullets `·`/`.` (indentation-sensitive; error if goal not closed), or `{ }`. `apply` tags subgoals by parameter names (`left`/`right`, `mp`/`mpr`, `zero`/`succ`). `#print thm` shows the term.

**Basic**
- `intro h` / `intro x y h₁ h₂` / `intro ⟨w, hw⟩` / `intro | ⟨w, .inl h⟩ => .. | ⟨w, .inr h⟩ => ..`; `intros` (auto-named, *inaccessible* names `a✝` — use `rename_i h1 _ h2` or `unhygienic`).
- `apply e` (unify conclusion, new goals for args); `exact e` (must close; preferred); `refine ⟨_, ?_⟩` **[not in TPIL]** — `?_` opens named goals.
- `assumption`, `rfl` (any reflexive relation, defeq), `contradiction` (finds `h : ¬p`/`h : p`, `False`, distinct constructors `7 = 4`), `exfalso`/`trivial`/`left`/`right` **[Std; not in TPIL]**.
- `revert x` (inverse of intro, drags dependents), `generalize h : 3 = x` (may lose provability without the label `h`), `show t` (restate goal up to defeq: `show Nat.succ n = Nat.succ n`), `have h : t := e` / `have := e` (label `this`), `let a := 3 * 2` (unfoldable, unlike `have`), `sorry`.
- Structured: `case left => ..`, `next => ..`, `all_goals t`, `any_goals t` (succeeds if ≥1 works), `focus`, `t₁ <;> t₂` (t₂ on *all* goals produced), `first | t₁ | t₂`, `try t` (= `first | t | skip`), `repeat t` — **`repeat (try t)` loops forever**.

**Destructing / constructing**
```lean
cases h with | inl hp => .. | inr hq => ..     -- structured (order free)
cases h                                          -- unstructured; then `case inl h => ..` or `<;>`
cases n with | zero => .. | succ m => ..
cases m + 3 * k                                  -- generalises expression (does not revert hyps mentioning it)
cases Nat.lt_or_ge m n with | inl hlt => .. | inr hge => ..   -- non-hyp term: `have`s it first
rcases h with ⟨x, hx | hx⟩; obtain ⟨w, hw⟩ := h  -- [Std/Mathlib; not in TPIL] pattern forms of cases
constructor                                      -- first applicable constructor (And.intro, Iff.intro, Exists.intro w/ metavar witness)
exists x                                         -- explicit witness (Mathlib: `use x`)
match h with | ⟨_, Or.inl _⟩ => .. | ..          -- match works in tactic blocks; also `intro | pat => ..`
induction n with | zero => rfl | succ n ih => rw [Nat.add_succ, ih]
induction x, y using Nat.mod.inductionOn with | ind x y h ih => .. | base x y h => ..
injection h with h'                              -- constructor injectivity; closes goal on constructor clash
funext (a, b) (c, d)                             -- funext with patterns
```
`cases`/`induction`/`constructor` also *define data* (`def swap_pair : α × β → β × α := by intro p; cases p; constructor <;> assumption`). `cases` reverts+reintroduces dependent hyps; `induction` only on local variables (generalize first).

**Rewriting**
```lean
rw [h₂, h₁]        -- LHS→RHS, first match in traversal order; closes `t = t` with rfl afterwards
rw [← h]           -- reverse; `<-` ascii
rw [Nat.add_comm b]        -- instantiate args to pick the subterm; `Nat.add_comm _ b`
rw [Nat.add_zero] at h     -- in hypothesis; `at h ⊢`, `at *`
rw [h] at t                -- also rewrites types of data (Tuple α n → Tuple α 0)
```
`rw` fails under binders (`fun x => 0 + x`) — use `simp`, `funext`, or `conv`. Motive-not-type-correct errors → `simp only`, `cases`, or generalize the dependency.

**Simplifier**
```lean
simp                    -- @[simp] set + rfl closes; propositional rewriting (p ∧ q ↦ q given hp)
simp [h₁, ←h₂, f, *]    -- extra lemmas, reverse, unfold defs, all hyps
simp at h ; simp at *    -- location; order of `only [..]` `at` matters — check docstring
simp only [List.reverse_append] at h   -- no default set
simp [-reverse_mk_symm]  -- remove one lemma
simp +contextual         -- use `x = 0` inside then-branch of `if x = 0 ..`
simp +arith              -- linear arithmetic normalisation
simp_all                 -- simplify hyps and goal together, repeatedly (used with fun_cases)
@[simp] theorem foo ..   -- global attribute (persists in importing files, cannot be removed)
attribute [local simp] Nat.mul_comm Nat.mul_assoc Nat.mul_left_comm  -- section-scoped; ordered rewriting handles AC without looping
```
`simp` failing = "simp made no progress" error; `unfold f` and `simp [f]` unfold definitions; equation lemmas `f.eq_1` etc. `unfold` is the way to see one step of a well-founded definition (`conv => lhs; unfold div`).

**Other**
- `split` — case-split nested `if`/`match` in goal (`split <;> first | contradiction | rfl`) or `split at h`.
- `decide` — evaluate a `Decidable` instance (`example : 10 < 5 ∨ 1 > 0 := by decide`).
- `omega`, `norm_num`, `ring`, `aesop`, `ext`, `subst`, `exact?`, `apply?`, `simp?` **[not in TPIL; Std/Mathlib]** — `subst h` (h : x = e) replaces the variable; `ext`/`funext` for function/set equality; `omega` closes linear Nat/Int arithmetic; `ring` commutative (semi)ring identities.
- Extensible tactics: `syntax "triv" : tactic` + `macro_rules | `(tactic| triv) => `(tactic| assumption)`; multiple rules tried in order.
- Mixing: `exact ⟨hp, by simp⟩`; term-mode `have`/`show`/`match` inside tactic args and vice-versa.

---

## 6. Interacting with Lean

- `#guard_msgs in cmd` asserts expected messages; `#check`, `#check @f`, `#print f`, `#print axioms f`, `#eval`, `#eval!` (allow sorry), `#reduce`.
- `import A.B.C` (transitive; must be at file top). `Init` auto-imported.
- Sections & `variable`: only variables actually mentioned become params (for theorems: only those in the statement, plus explicit `include`).
- Namespaces: `def Foo.bar` ≡ `namespace Foo def bar end Foo`; `_root_.x`; `protected def` (no short alias — `Nat.rec`); `open Nat (succ zero)`, `open Nat hiding gcd`, `open Nat renaming mul → times`, `export Nat (succ add)`, `open Foo in cmd` (one-command scope).
- Attributes: `@[simp]`, `attribute [simp] foo`, `attribute [local simp] ..`, `attribute [-instance] inst`, `attribute [local instance] i`. Attributes persist across imports unless `local`/`scoped`.
- Notation: `infixl:65 " + " => HAdd.hAdd`, `infixr`, `prefix:100`, `postfix:max`, general `notation:65 lhs:65 " ~ " rhs:66 => ..`; higher number binds tighter; longest-parse rule; ambiguity resolved at elaboration.
- Coercions `↑x`; auto-inserted `Nat → Int` etc.
- `set_option pp.explicit true`, `pp.universes`, `pp.notation false`, `pp.all`, `pp.proofs`, `linter.unusedVariables false`, `autoImplicit false`, `trace.Meta.synthInstance true`, `synthInstance.maxHeartbeats`. Options are always scoped to the section/file; `set_option .. in cmd`.
- Library naming: `Nat.succ_ne_zero`, `Nat.le_of_succ_le_succ` (conclusion_of_hyps), camelCase defs, CamelCase types; dot notation `xs.map f`, `h.symm`, `p.add q` (fills first explicit arg of matching type).
- Implicit lambdas auto-inserted for expected `{α} → ..`; disable with `@fun`. Sugar `(· + 1)`, `(f · 1 ·)`, `(·.1)`. Named args `f (z := z) x`, `Eq.subst (motive := fun x => ..) h`, `..` for remaining explicit args in patterns (`Term.lambda (name := n) ..`, `Nat.add_assoc ..`). Default args `(y : Nat := 1)`.

---

## 7. Inductive Types

```lean
inductive Weekday where | sunday | monday .. deriving Repr
inductive Prod (α : Type u) (β : Type v) where | mk (fst : α) (snd : β) : Prod α β
inductive Nat where | zero : Nat | succ : Nat → Nat
inductive Vect (α : Type u) : Nat → Type u where       -- parameter α, index Nat (family)
  | nil : Vect α 0
  | cons : α → {n : Nat} → Vect α n → Vect α (n + 1)
inductive Eq {α : Sort u} (a : α) : α → Prop where | refl : Eq a a
structure Subtype {α : Sort u} (p : α → Prop) where val : α ; property : p val   -- {x // p x}
mutual inductive Even : Nat → Prop .. inductive Odd : Nat → Prop .. end
inductive Tree (α) where | mk : α → List (Tree α) → Tree α                       -- nested
```

Each type gets `T.rec` (motive, minor premises, major premise), `T.recOn`, `T.casesOn`, `T.noConfusion` (constructors injective & disjoint), `T.below`/`brecOn` (course-of-values). Constructors live in namespace `T`. Positivity required. `match` compiles to `casesOn`/`rec` (`T.match_1` auxiliaries). `Prod`/`Sum`/`Option`/`Sigma`/`Subtype`/`Inhabited` and `False`/`True`/`And`/`Or`/`Exists`/`Eq` are all inductives — the Prop versions of `Empty`/`Unit`/`Prod`/`Sum`/`Sigma`.

**Universe/elimination rules.** For non-Prop types the universe must be ≥ every constructor argument's universe. Inductive Props eliminate only into `Prop`, **except singleton elimination**: one constructor whose args are all Props or indices (`Eq`, `And`, `Acc`) can eliminate into any `Sort` — that's why `Eq.rec`/`▸` can cast data. `Or`, `Exists`, `Nonempty` cannot produce data (hence `Classical.choice` is an axiom).

Proof idioms: `cases d <;> rfl` for enumerations; `theorem subst (h : a = b) (h₂ : p a) : p b := match h with | rfl => h₂`; `nomatch h` for impossible hyps; `Nat.noConfusion h`.

---

## 8. Induction and Recursion

Equation compiler: `def f : Nat → Nat | 0 => .. | n+1 => ..` (patterns: vars, constructors, literals, `n+2`, `[]`, `a :: as`, `(m, n)`, wildcards `_`; multiple args separated by commas; overlapping patterns → first match wins; missing cases → error listing them). Params before the colon are fixed; those after participate in matching. Structural recursion holds **definitionally** (`rfl` works); `where`/`let rec` create auxiliaries `f.loop`. `Inhabited`/`default` or `Option` for "incomplete" cases.

```lean
theorem zero_add : ∀ n, add zero n = n | zero => rfl | succ n => congrArg succ (zero_add n)  -- induction = recursion
def fib : Nat → Nat | 0 => 1 | 1 => 1 | n+2 => fib (n+1) + fib n     -- #reduce fast (brecOn), #eval slow
```

**Well-founded recursion.** When structural fails Lean tries WF: `termination_by x y => (x, y)` (lexicographic via `WellFoundedRelation`, `sizeOf` default), `decreasing_by simp_wf; ..` (default `decreasing_tactic` uses `assumption`, so a `have : x - y < x := ..` before the call suffices). Underlying `Acc`, `WellFounded.fix` (must be `noncomputable` if used directly). WF definitions do **not** reduce definitionally — `div 8 2 = 4` needs `simp [div]`/`unfold`/equation lemmas, not `rfl`. `decreasing_by sorry` = axiom; `#print axioms unsound` shows `sorryAx`.

**Functional induction.** `fun_induction ack <;> simp [*]` and `fun_cases f <;> simp_all` generate cases following the *function's* recursion, with hypotheses ruling out earlier branches. `induction .. using ack.induct` older form.

**Mutual recursion**: `mutual def even .. def odd .. end`; mutual theorems `mutual theorem .. end` on nested types (`Term`/`List Term`).

**Dependent pattern matching.** On indexed families, unreachable cases may be omitted (`def head : Vect α (n+1) → α | cons a as => a`). Inaccessible patterns `.(f a)` or `_` mark terms determined by other args (avoid splitting on the index). Auto-bound `{n}` discriminants are added implicitly. `match h₀, h₁ with | ⟨x, px⟩, ⟨y, qy⟩ => ..`, `fun ⟨x, px⟩ ⟨y, qy⟩ =>`, `let (m, n) := p; ..` are all the same machinery.

---

## 9. Structures and Records

```lean
structure Point (α : Type u) where mk :: x : α ; y : α deriving Repr
#check @Point.rec ; Point.mk 1 2 ; p.x ; { x := 1, y := 2 : Point Nat } ; ⟨1, 2⟩
{ p with y := 3 } ; { p, q with x := 6 }                   -- record update (left-to-right precedence)
structure ColorPoint (α) extends Point α where c : Color   -- inheritance; fields flattened, `toPoint` projection
structure RGP (α) extends Point α, RGBValue where no_blue : blue = 0
def Point.add (p q : Point Nat) := ..  -- p.add q ; p.smul 3 = Point.smul 3 p (first arg of type Point)
```
Implicit fields `{α : Type u}`; unspecified fields inferred or error; `structure` = single-constructor inductive plus projections, namespace, `rec`.

---

## 10. Type Classes

```lean
class Add (α : Type) where add : α → α → α          -- @Add.add : {α} → [self : Add α] → α → α → α
instance : Add Nat where add := Nat.add
instance [Add α] : Add (Array α) where add x y := Array.zipWith (· + ·) x y     -- chaining
def double [Add α] (x : α) := Add.add x x
instance (priority := default + 1) i1 : Foo where ..   -- later/higher-priority tried first
(inferInstance : Add Nat) ; instance : Inhabited (Set α) := inferInstanceAs (Inhabited (α → Prop))
class HMul (α β) (γ : outParam Type) where hMul : α → β → γ   -- outParam: synth even if γ unknown; semiOutParam
@[default_instance] instance : HMul Int Int Int ..    -- resolves stuck `?m` problems; numerals: OfNat α n, nat_lit 2
local instance / scoped instance (active inside/`open Foo` or `open scoped Foo`) / attribute [-instance] i
export Inhabited (default)
```
Resolution = Prolog-like backtracking; debug with `set_option trace.Meta.synthInstance true`. `Decidable p` (`isTrue h | isFalse h`) is a `class inductive` in `Type`-like strength: `if p then a else b` = `ite` needs `[Decidable p]`; `if h : c then t else e` = `dite`. Instances for `∧ ∨ ¬ = < ≤` on `Nat`/`Int`. `open Classical` gives low-priority `propDecidable` (noncomputable). Tactic `decide` and function `decide p : Bool`, `of_decide_eq_true`. Coercions: `instance : Coe Bool Prop`, `CoeDep`, `CoeSort` (`(a b : S)` for a `Semigroup` structure), `CoeFun` (morphisms as functions), force with `↑`. Warning: class-typed defs should be `@[instance_reducible]`/`abbrev`.

---

## 11. Conversion Mode

`conv => ..` (or `conv at h`, `conv in pat => ..`) navigates: `lhs`/`rhs`, `arg i`, `congr`/`args`, `intro x` (under binders), `enter [1, x, 2]`, `pattern b * c`, `skip`, then `rw [..]`, `simp [..]`, `unfold`, `whnf`, `rfl`, `done`, `trace_state`, `tactic => ..`/`apply e` to escape. Structure with `·`. Use it to rewrite one specific occurrence or under `fun`; usually `simp`/`funext` suffice.

---

## 12. Axioms and Computation

CIC core (universes, Pi, inductives) + three additions: `axiom propext : (a ↔ b) → a = b`; quotients (`Quot`, `Quot.mk`, `Quot.ind`, `Quot.lift` are primitive; `axiom Quot.sound : r a b → Quot.mk r a = Quot.mk r b`) which imply `funext`; `axiom Classical.choice : Nonempty α → α`. `propext`/`Quot.sound` block kernel reduction (`#reduce val` stuck, `#eval` fine) but not codegen; `choice` needs `noncomputable`. `Classical.choose h`, `choose_spec`, `indefiniteDescription`, `epsilon`; Diaconescu: `choice + propext + funext ⊢ em`; `Classical.em`, `propComplete : a = True ∨ a = False`, `Decidable p` for all `p` (classical). Setoid/`Quotient`: `Quotient.mk`, `.lift`, `.ind`, `.sound`, `.exact`, `lift₂`, `≈`; idiom: define on representatives, prove `respects`, lift. `#print axioms thm` lists `propext`, `Quot.sound`, `Classical.choice`, `sorryAx`. Set extensionality: `funext fun x => propext (h x)`.

---

## Quick gotcha list
- `theorem` bodies are irreducible; use `def`/`abbrev` if you need unfolding; `def` returning a Prop triggers a linter.
- `have` forgets the value, `let` keeps it. `let rec`/`where` need to be closed over local vars.
- `rw` is syntactic (up to instances) — `n + 1` vs `Nat.succ n` may need `show`/`simp`. `rw` closes goals with `rfl` automatically; `simp` closes with `rfl`/`True`.
- `intros` names are inaccessible; prefer explicit `intro`.
- `cases e` on a non-variable expression won't touch hypotheses mentioning `e` — `revert` first or `generalize h : e = x`.
- `constructor` on `∃` leaves the witness as a metavariable — fine if later `exact` fixes it, else `exists w`.
- `simp` attribute is global once added; use `attribute [local simp]` or `simp only`.
- WF-recursive defs don't compute by `rfl`; structural ones do. `#reduce` uses kernel (fast for `fib` via `brecOn`); `#eval` compiled.
- Anonymous constructor works only for one-constructor types; `Or` needs `Or.inl`/`.inr` (or `left`/`right`).
- `open Nat` inside `namespace Hidden` where `Hidden.Nat` exists → ambiguity linter.
- `sorry`/`decreasing_by sorry` = axiom; check with `#print axioms`.
