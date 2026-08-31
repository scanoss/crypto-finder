# rust-callgraph-identity-resolution Specification

## Purpose

Rust call-site identity resolution in `internal/callgraph/rust_parser.go`,
`rust_type_semantics.go` and `rust_symbols.go`: how the `package` and `Type`
segments of a callee key are established from the syntax tree, the crate's own
declarations and the file's imports, so a key can be matched against the Rust
contract knowledge base in `internal/callgraph/contracts/rust/`.

A callee key is `package.(Type).method`, rendered `package.Type.method` after
arity splitting. The KB keys every operation on the crate that IMPLEMENTS it
(`chacha20poly1305`, `openssl_sys`, `aes`, `des`, `ring`, `hmac`, …); no
contract keys a type through another crate's facade.

**The governing rule of this capability is that a wrong identity is worse than
no identity.** A key naming the wrong crate can fire a cryptographic rule
against code that does not use that algorithm, which is a false finding. A key
that resolves to nothing merely loses a detection. Every requirement below
resolves ambiguity toward emitting NO identity rather than a guess, and the
requirement "A callee key never carries source text" exists because a
source-text key looks resolved, matches no contract, and hides the difference
between a resolved and an unresolved receiver in any coverage measurement.

Out of scope: the KB YAML itself, the export schema,
`internal/scan/supporting_calls.go` semantics, and macro expansion.

## Requirements

### Requirement: Receiver identity is resolved structurally, never from source text

The parser MUST establish a receiver's type from the syntax tree and the
declarations in scope. It MUST NOT infer a type by cutting the source text of
the statement that bound the receiver. Where a type cannot be established the
call MUST be emitted with no type, carrying only `ReceiverVar`.

#### Scenario: Every value routing carries the receiver's type

- GIVEN a matrix of every import spelling against every way a value reaches a receiver — `.await`, `.await?`, `?`, `let ... else`, a `match` arm, a block's trailing expression, a helper's declared return type, a struct field's declared type, `&`, `*`, an `unsafe` block, indexing, a cast, and a method called on a temporary or at the end of a fluent chain
- WHEN the parser resolves each call
- THEN every case MUST carry the identity of the type that declares the method
- Pinned by: `TestRustParser_ReceiverTypeSurvivesEveryValueRouting`

#### Scenario: An unresolvable receiver is untyped, not named after its variable

- GIVEN a receiver whose type cannot be established from the file or the crate
- WHEN the parser emits the call
- THEN the `Type` segment MUST be empty and MUST NOT contain the receiver variable's own name
- AND the key MUST NOT take the form `package.(variable).method`
- Pinned by: `TestRustParser_UnresolvedReceiverIsUntypedNotNamed`

#### Scenario: Every binding position carries its type

- GIVEN a value bound by `let`, `if let`, `while let`, a `match` arm, `for`, a closure parameter, or a tuple, struct or slice pattern, including an enum variant's payload and a tuple struct's positional field
- WHEN a method is called on that binding
- THEN the call MUST carry the bound value's type
- AND an explicit type annotation MUST take precedence over the initializer
- Pinned by: `TestRustParser_EveryBindingPositionCarriesItsType`

### Requirement: A callee key never carries source text

The `package` and `Type` segments of an emitted key MUST contain only resolved
identities. A keyword, a punctuation-bearing type expression, a path root, a
type name in the package position, or a variable name in the type position MUST
NOT reach a key. Where the shape has no nameable path the parser MUST emit no
type.

#### Scenario: Emitted keys are well formed

- GIVEN a corpus of call sites covering pointer, slice, array, qualified-path and unnameable-alias shapes
- WHEN the parser emits their keys
- THEN no key may contain `*`, `&`, `[`, `]`, `<`, `>`, a leading or trailing `::`, or an empty package with a non-empty type
- Pinned by: `TestRustParser_EmittedKeysAreWellFormed`, `TestRustParser_PunctuationNeverReachesAKey`

#### Scenario: A path root or a keyword never reaches a key

- GIVEN calls written through `crate::`, `self::`, `super::`, a leading `::`, and `dyn Trait`
- WHEN the parser resolves them
- THEN the keyword MUST be replaced by the module or type it names, and MUST NOT appear in any segment
- AND the edition-2018 `::` disambiguator MUST be dropped by every route that reads a path — the plain, use-list and renaming forms alike
- Pinned by: `TestRustParser_RelativeRootNeverReachesAKey`, `TestRustParser_DynKeywordNeverReachesAKey`, `TestRustParser_LeadingSeparatorNeverReachesAKey`

#### Scenario: An alias to an unnameable type stays local

- GIVEN `type State = [u64; 8];` and a call written through the alias
- WHEN the parser resolves the call
- THEN the array text MUST NOT be forwarded to the key
- Pinned by: `TestRustParser_AliasToUnnameableTypeStaysLocal`

### Requirement: Bindings, imports and type aliases are lexically scoped

Bindings, `use` declarations and `type` aliases MUST be scoped to the block,
function or module that declares them, and binding and use MUST be resolved in
one traversal that maintains Rust's lexical scopes (Rust Reference, *Names →
Scopes*). A name bound in one scope MUST NOT bind in a sibling scope, and a
declaration MUST NOT bind at call sites that lexically precede it.

#### Scenario: Sibling scopes do not leak bindings

- GIVEN two sibling blocks that each bind `c`, one to an AES cipher and one to a DES cipher
- WHEN the parser resolves a method call in each block
- THEN each call MUST carry the type bound in its own block
- Pinned by: `TestRustParser_SiblingScopesDoNotLeakBindings`, `TestRustParser_InnerBindingDoesNotEscapeItsBlock`

#### Scenario: A shadowing `let` sees the outer binding in its own initializer

- GIVEN `let c = ...;` followed by `let c = f(c);`
- WHEN the parser resolves the initializer's use of `c`
- THEN it MUST resolve to the outer binding, and the new binding MUST apply only afterwards
- Pinned by: `TestRustParser_ShadowingLetSeesTheOuterBindingInItsInitializer`

#### Scenario: An `if let` binding is visible only in the taken branch

- GIVEN `if let Ok(cipher) = Aes256Gcm::new_from_slice(key) { .. } else { .. }`
- WHEN the parser resolves calls in each branch
- THEN `cipher` MUST carry its type in the taken branch and MUST NOT bind in the `else`
- Pinned by: `TestRustParser_IfLetBindingIsScopedToItsBranch`

#### Scenario: Each `match` arm binds independently

- GIVEN a `match` whose arms bind the same name to different cipher types
- WHEN the parser resolves a call in each arm
- THEN each arm's call MUST carry that arm's type
- Pinned by: `TestRustParser_MatchArmsBindIndependently`, `TestRustParser_MatchArmGuardStillBinds`

#### Scenario: A `use` is scoped to the function, block or module that declares it

- GIVEN two functions in one module, one writing `use aes::Aes128 as Cipher;` and the other `use des::Des as Cipher;`
- WHEN the parser resolves a call in each
- THEN each MUST resolve to its own crate, and neither may adopt the other's
- AND a `use` inside a nested block MUST be read rather than dropped
- Pinned by: `TestRustParser_FunctionScopedImportsDoNotLeakToSiblings`, `TestRustParser_ScopedUseDeclarationsAreRead`, `TestRustParser_NestedBlockImportsAreRead`, `TestRustParser_RenamingImportDoesNotLeakAcrossModules`

#### Scenario: A `#[cfg(test)]` alias does not hijack production code

- GIVEN a file-level `type Cipher = Aes128;` and a `#[cfg(test)] mod tests { type Cipher = des::Des; }`
- WHEN the parser resolves a call in the production code above
- THEN it MUST carry the AES identity
- AND a type alias in a nested module MUST override an ancestor's alias of the same name inside that module
- Pinned by: `TestRustParser_TestModuleAliasDoesNotHijackProductionCode`, `TestRustParser_TypeAliasesAreScopedToTheirModule`

### Requirement: A module the crate declares shadows a same-named crate, lexically

An item in the current module MUST take precedence over an extern-prelude name
of the same kind (Rust Reference, *Names → Preludes*, *Name resolution*). This
MUST apply on the `use` path as well as the call path, and MUST apply in the
file that declares the module and nowhere else. An explicit `use` of the same
name MUST still win, and a module MUST NOT shadow itself.

#### Scenario: A local module shadows a third-party crate of the same name

- GIVEN a crate with no cryptographic dependency whose own `mod des` holds a record framer, imported as `use des::Des;`
- WHEN the parser resolves `Des::new(..)` and `d.encrypt_block(..)`
- THEN the calls MUST carry the local module's path and MUST NOT name the `des` crate
- AND the `des.yaml` weak-cipher contract MUST NOT match
- Pinned by: `TestRustParser_LocalModuleShadowsACrateOfTheSameName`, `TestRustParser_UseOfALocalModuleIsNotACrate`

#### Scenario: Shadowing does not cross files

- GIVEN an empty `mod des;` declared in one file of a crate and a real `des` crate call in another
- WHEN the parser resolves the call in the second file
- THEN it MUST carry the `des` crate identity
- Pinned by: `TestRustParser_ModuleShadowingDoesNotCrossFiles`

#### Scenario: A module is not an item of itself

- GIVEN `mod pbkdf2 { use pbkdf2::pbkdf2; }`
- WHEN the parser resolves the path's first segment
- THEN it MUST resolve to the crate, because a module is not an item of itself
- Pinned by: `TestRustParser_AModuleDoesNotShadowItself`

#### Scenario: An explicit import and a local module in precedence order

- GIVEN a local module and an explicit `use` of the same name
- THEN the explicit import MUST win
- AND a local module MUST beat a manifest dependency rename of the same name
- Pinned by: `TestRustParser_ExplicitImportBeatsALocalModuleName`, `TestRustParser_LocalModuleBeatsAManifestRename`

### Requirement: A path segment the manifest does not declare is not a crate

A first path segment that is neither a manifest-declared dependency nor the
standard library, and that the crate declares as a module of its own, MUST
resolve to that module. A declared dependency of the same name MUST still
resolve to the crate. The manifest is the evidence: a real crates.io name that
the crate does not depend on can never be the answer.

#### Scenario: An undeclared segment resolves to the crate's own module

- GIVEN a crate that writes `use cipher::SealingKey;` for its own `pub(crate) trait SealingKey` and declares no `cipher` dependency
- WHEN the parser resolves calls written through it
- THEN they MUST carry the crate's own module path
- Pinned by: `TestRustParser_AnUndeclaredDependencyIsNotACrate`

### Requirement: Glob imports resolve only when unambiguous

A glob names no members, so resolving a glob-supplied name requires evidence.
A type reached through a glob MUST be attributed to the module that DECLARES
it. Where several globs could supply a name, the crate MUST be used only when
they agree; otherwise the identity MUST be left unresolved. A glob MUST NOT
claim a name without crate-wide visibility of the crate's own declarations.

#### Scenario: An unambiguous glob resolves to its crate

- GIVEN `use aes::*;` followed by `Aes128::new(..)`
- THEN the call MUST carry the `aes` crate identity
- Pinned by: `TestRustParser_GlobImportsResolveWhenUnambiguous`

#### Scenario: Competing globs resolve to nothing

- GIVEN two glob imports from different crates that could each supply a name
- THEN the identity MUST be left unresolved rather than choosing one
- Pinned by: `TestRustParser_AmbiguousGlobImportsStayUnresolved`

#### Scenario: A glob-supplied type is attributed to its declaring module

- GIVEN a type declared once in `src/connection/assembler.rs` and reached through `use super::*` from a sibling and from a `mod tests`
- WHEN the parser resolves calls on it from each importer
- THEN every call MUST carry the declaring module, not the importing one
- AND a name two modules of the crate declare MUST stay where the source resolved it, because naming one of the two would attribute half the call sites to a module that declares something else under that name
- Pinned by: `TestRustParser_GlobResolvesToTheDeclaringModule`

#### Scenario: A glob may not claim a name without crate visibility

- GIVEN a source tree with no `Cargo.toml` anywhere above it, a `use des::*` and the crate's own `Framer` beside it
- THEN the name MUST stay local rather than being attributed to the `des` crate
- AND the claim guard MUST be lexical: a declaration in another file of the crate MUST NOT suppress a glob-supplied identity here
- Pinned by: `TestRustParser_GlobDoesNotClaimNamesWithoutCrateVisibility`, `TestRustParser_GlobClaimIsLexicalNotCrateWide`

#### Scenario: A parent that glob-re-exports a child gives the child its path

- GIVEN `pub use self::ed25519::*;` in a parent module
- THEN the child's items MUST carry the parent's path, which is the identity the contract keys on (`sodiumoxide::crypto::sign`, not the declaring file's `...::sign::ed25519`)
- Pinned by: `TestRustParser_GlobReExportedModuleCarriesTheParentPath`

### Requirement: `impl Trait for Type` is typed by the implementing type

An impl block's methods MUST be declared under the implementing TYPE, not the
trait, and `self.method()` inside those bodies MUST be typed by the type. A
trait's method signatures MUST be recorded under the trait, so a `dyn Trait`
receiver resolves through the trait rather than through another type's
same-named inherent method.

#### Scenario: A trait impl is attributed to its target

- GIVEN `impl BlockEncrypt for Aes128 { fn encrypt_block(&self, ..) { .. } }`
- THEN the declaration MUST be keyed on `Aes128`, not on `BlockEncrypt`
- Pinned by: `TestRustParser_TraitImplIsTypedByItsTargetNotItsTrait`

#### Scenario: A trait's declared return type belongs to the trait

- GIVEN a `dyn Backend` whose trait method returns an AES cipher, and an unrelated struct with a same-named inherent method returning a DES cipher
- THEN the call through the trait object MUST resolve through the trait
- Pinned by: `TestRustParser_TraitSignatureReturnTypeIsOwnedByTheTrait`

### Requirement: Ownership wrappers are distinguished by `Deref`

A wrapper that implements `Deref` MUST be seen through, because a method
written on it auto-dereferences to the value inside (Rust Reference, *Type
coercions*, *Method-call expressions*). A wrapper that does not — `Option`,
`Result`, `Vec`, `Cell`, `RefCell`, `Mutex`, `RwLock` — MUST keep its own
identity, so a method called on one of those is reported as the wrapper's. The
accessors that hand back the contents and the `?` operator MUST resolve to the
inner type. Only the constructors that take the wrapped value MUST collapse the
chain.

#### Scenario: A Deref wrapper does not hide the receiver

- GIVEN `Arc<Mutex<Cipher>>`, `Box<Cipher>` and `Rc<RefCell<Cipher>>`
- WHEN a cipher method is called on the wrapped value
- THEN the call MUST carry the cipher's identity, not `std::sync.(Arc)`
- Pinned by: `TestRustParser_WrappersDoNotHideTheReceiverIdentity`, `TestRustParser_WrapperNeverAppearsAsTheReceiverType`

#### Scenario: A method of the wrapper belongs to the wrapper

- GIVEN `lock`, `borrow`, `borrow_mut`, `unwrap`, `expect`, `into_inner` or `take` called on a value wrapper
- THEN the call MUST be attributed to the wrapper's own type and path
- AND only the standard library's locks are poisonable, so a value awaited from a tokio lock MUST NOT be typed as a `Result`
- Pinned by: `TestRustParser_WrapperMethodsBelongToTheWrapper`, `TestRustParser_CallOnTheWrapperItselfKeepsTheWrapper`

#### Scenario: Only value-taking constructors collapse the chain

- GIVEN `Arc::new(Mutex::new(cipher))` and `Vec::with_capacity(n)`
- THEN `new`, `from`, `pin` and `new_cyclic` MUST take the wrapped value's type, and `with_capacity` MUST NOT type the vector by its capacity
- AND `unwrap`/`expect` MUST unwrap only an actual wrapper, and `map_err` MUST preserve the value's type
- Pinned by: `TestRustParser_UnwrapAndMapErrKeepTheRightType`

### Requirement: Declarations resolve crate-wide, with conflicts dropped

Function return types, struct and enum-variant field types, method return
types, and the crate's declared types and modules MUST be indexed once per
crate for a whole scan and shared across workers. A recorded type MUST be
qualified with the imports of the file that DECLARED it. A name two files
declare with different types MUST be dropped rather than guessed. A file's own
declarations MUST take precedence over the crate index.

#### Scenario: A factory in one module types a receiver in another

- GIVEN `src/factory.rs` returning an `Aes128` and `let c = make(); c.encrypt_block(..)` in `src/consumer.rs`
- THEN the receiver MUST carry the AES identity
- Pinned by: `TestRustParser_CrateIndexResolvesAcrossFiles`

#### Scenario: An ambiguous crate-wide name is dropped, and stays dropped

- GIVEN two files declaring the same name with different types
- THEN the crate index MUST record neither, because an ambiguous answer would report an algorithm the code does not use
- AND a THIRD file repeating the first MUST NOT resurrect it: the drop is sticky, or directory walk order decides which cipher a struct field is reported as holding
- AND the same stickiness MUST hold for a contradicted crate alias
- Pinned by: `TestRustParser_CrateIndexDropsConflictingDeclarations`, `TestRustParser_SameNamedDeclarationsInSiblingModulesStaySeparate`, `TestRustParser_AConflictingDeclarationStaysDropped`, `TestRustParser_AConflictingCrateAliasStaysDropped`

#### Scenario: A file's own declarations win

- GIVEN a bare type name declared both locally and in the crate index
- THEN the local declaration MUST win
- Pinned by: `TestRustParser_FileDeclarationsBeatTheCrateIndex`, `TestRustParser_SiblingModuleKeepsItsOwnTypeAgainstAnImportedName`

#### Scenario: A relative import keeps its crate root when indexed

- GIVEN a declaring file whose import is rooted at `crate::`, `self::` or `super::`
- THEN the recorded type MUST keep the resolved absolute path, not lose the root
- Pinned by: `TestRustParser_CrateIndexKeepsTheCrateRootOfARelativeImport`

### Requirement: A single-file module extends the package path

A `src/rsa.rs` is the module `rsa`, exactly as `src/rsa/mod.rs` would be, and
the contract KB is authored that way (`openssl::rsa::Rsa.generate`). The file
module MUST appear in the package path of both calls and declarations, so two
sibling files' same-named functions do not collapse onto one graph key.

#### Scenario: A file module appears in calls and declarations

- GIVEN a call and a declaration inside `src/crypto.rs` of a crate named `myproject`
- THEN both MUST carry the package `myproject::crypto`
- Pinned by: `TestRustParser_FileModulesExtendThePackagePath`, `TestRustParser_FileModuleAppearsInDeclarationKeys`

### Requirement: A pure pass-through re-export names the crate it re-exports

A module whose ONLY item is `pub use <name>::*`, where `<name>` matches the
module's own name, MUST be reported against the crate it re-exports. The
contract KB keys every operation on the crate that implements it, and a facade
containing no cryptography must not be credited with a cryptographic
operation. The discriminator MUST stay narrow: any other item in the module and
the local module wins, which is what preserves the shadowing requirement above.

#### Scenario: A facade module resolves to the canonical crate

- GIVEN `pub mod native_tls { pub use native_tls::*; }`
- THEN a call reached through it MUST be keyed `native_tls.(TlsStream).get_mut`
- AND the caller key MUST still name the facade crate, so the call chain records how the code arrived
- Pinned by: `TestRustParser_PureReExportModuleNamesTheOwningCrate`

### Requirement: A generic receiver resolves through its trait bounds

A bounded type parameter MUST carry the bound trait's identity, from either the
parameter list or a `where` clause. An unbounded parameter MUST carry none. A
generic declared on an `impl` block MUST apply to every method in it, and a
lifetime in a parameter's type MUST NOT prevent resolution.

#### Scenario: A bound supplies the receiver's identity

- GIVEN `fn f<C: BlockEncrypt>(c: &C) { c.encrypt_block(..) }`
- THEN the call MUST resolve through `BlockEncrypt` and MUST NOT emit `myapp.(C).encrypt_block`
- Pinned by: `TestRustParser_GenericReceiverResolvesThroughItsBound`

### Requirement: Prelude types belong to the standard library

`Result`, `Option`, `Vec`, `Box` and the rest of the standard prelude are in
scope with no import. A prelude type — whether the source WRITES it (in an
annotation, a parameter, or the constructor call itself) or it is INFERRED
from a constructor's return via a binding — MUST be attributed to `std` and
MUST NOT be emitted under the analyzed crate's own package. A crate that
declares its own alias of a prelude name MUST still win.

#### Scenario: A written or inferred prelude type resolves to the standard library

- GIVEN `fn a(v: Vec<u8>) -> usize { v.len() }`, `fn b(o: Option<u8>) { o.unwrap() }`, `let _v = Vec::from(p);` and `let v = Vec::from(p); v.clone();`
- THEN each MUST be attributed to `std`
- Pinned by: `TestRustParser_PreludeTypeBoundary`

### Requirement: Path spellings resolve to the module or type they name

`crate::`, `self::`, `super::`, a leading `::`, `use crate::{a, b}`,
`use x::{self, Y}`, `use PATH as NAME`, `Self::`, a `-> Self` return, and
`super::` in a type alias MUST all resolve. `super::` MUST NOT pop past the
crate root.

#### Scenario: Relative roots and list imports resolve

- GIVEN calls written through each spelling above
- THEN each MUST carry the module or type it names, with no empty package
- Pinned by: `TestRustParser_PathSpellingsResolveToModules`, `TestRustParser_RelativePathRootsResolveToModules`, `TestRustParser_SuperDoesNotPopPastTheCrateRoot`, `TestRustParser_SelfRenamingImportResolvesModulePath`

#### Scenario: An imported module keeps its own segment

- GIVEN `use ring::aead::quic;` and a crate's own `crypto::hmac` module
- THEN the imported module's segment MUST be kept, so a crate's own `hmac` module is not reported as the `hmac` crate
- Pinned by: `TestRustParser_ImportedModuleKeepsItsSegment`

### Requirement: Type aliases resolve transitively and carry their crate

An alias chain MUST be followed to its target, an alias whose target is a bare
type name MUST NOT be dropped, and an alias to an imported type MUST carry that
type's crate.

#### Scenario: Alias chains and bare-name aliases

- GIVEN `type A = B; type B = aes::Aes128;` and `type A2 = A1;`
- THEN a call through either MUST carry the `aes` identity
- Pinned by: `TestRustParser_TypeAliasChainsResolveTransitively`, `TestRustParser_LocalTypeAliasResolvesToAliasedPath`, `TestRustBareTypeAliasCarriesItsCrate`, `TestRustParser_LocalTypeAliasReachesContracts`

### Requirement: Inline modules and trait default bodies are walked

Inline `mod x { ... }` blocks, trait default-method bodies, and `use`
declarations inside functions, impl blocks and modules MUST be walked for
declarations, imports and calls. A crate that organizes its code in inline
modules MUST NOT contribute nothing.

#### Scenario: Inline modules contribute declarations and calls

- Pinned by: `TestRustParser_InlineModulesContributeDeclarationsAndCalls`, `TestRustParser_TraitDefaultMethodBodiesAreWalked`

### Requirement: The parser's grammar assumptions are pinned by tests

Every node kind the parser names, every field it reads and every symbol it
dispatches on MUST be asserted to exist in the vendored tree-sitter Rust
grammar, so a grammar bump that removes or renames one fails a test rather
than silently resolving nothing.

#### Scenario: Grammar facts are asserted

- Pinned by: `TestRustGrammar_EveryNodeKindTheParserNamesExists`, `TestRustGrammar_EveryFieldTheParserReadsResolves`, `TestRustGrammar_EverySymbolTheParserDispatchesOnResolves`, `TestRustGrammar_ResolvedSymbolsMatchTheirNodes`, `TestRustGrammar_KnownStalenessIsStillPresent`

### Requirement: Turbofish generic arguments resolve to the receiver's identity

A call written with explicit generic arguments MUST resolve to the type the
turbofish names, on both the callee and the receiver path. A turbofish on a
METHOD rather than a type MUST NOT contribute a contract type, because the
generic argument there is the method's, not the receiver's.

#### Scenario: A turbofish constructor keeps the receiver's identity

- GIVEN `Blowfish::<LE>::new_from_slice(key)` and a method called on the bound value
- THEN both calls MUST carry the `blowfish` crate identity
- Pinned by: `TestRustParserResolvesTurbofishCalls`, `TestRustParser_TurbofishConstructorKeepsReceiverIdentity`, `TestRustParser_TurbofishReceiverTypesResolveExactCalleeKeys`, `TestRustParser_TurbofishInDeclaredTypesResolvesExactCalleeKeys`

#### Scenario: A turbofish on a method records no contract type

- Pinned by: `TestRustParser_TurbofishOnMethodRecordsNoContractType`

#### Scenario: A parameter turbofish the grammar cannot parse degrades gracefully

- GIVEN a turbofish in a position the vendored grammar rejects
- THEN the parser MUST recover and continue rather than losing the file
- Pinned by: `TestRustParser_ParameterTurbofishSurvivesGrammarErrorRecovery`, `TestRustGrammar_ParameterTurbofishStillFailsToParse`

### Requirement: Return sources and call targets are recorded

A function's returned value MUST be recorded as a return source so a caller can
type the value it receives. A returned constructor call MUST populate the call
target. A bare or unknown return MUST record none, and return sources MUST NOT
escape the function that declares them.

#### Scenario: A returned factory call populates the call target

- Pinned by: `TestRustParser_ReturnFactory_PopulatesCallTarget`, `TestRustParser_ReturnIdentifier_PopulatesReturnSources`

#### Scenario: An unknown or bare return records nothing

- Pinned by: `TestRustParser_UnknownAndBareReturn_NoReturnSources`, `TestRustParser_ReturnSources_RespectFunctionScope`

### Requirement: Call positions follow the repository's column convention

A recorded call's line and column MUST follow the one-based, end-exclusive
convention the rest of the pipeline expects, so a finding's position matches
what the scanner reports.

#### Scenario: Columns are one-based and end-exclusive

- Pinned by: `TestRustParser_CallColumnsAreOneBasedExclusive`, `TestRustParser_PackageSeparator`

### Requirement: File selection honours the scan's test-inclusion setting

Test files and test directories MUST be skipped by default and included when
the scan asks for them, so a `#[cfg(test)]` body never contributes a finding to
a default scan.

#### Scenario: Test files are skipped by default and included on request

- Pinned by: `TestRustParser_SkipTestFiles`, `TestRustParser_SkipDirs`, `TestRustParser_IncludeTestsIncludesTestFilesAndDirs`

#### Scenario: An inline `#[cfg(test)]` module is skipped by default

- GIVEN a crate whose shipped code uses AES and whose `#[cfg(test)] mod tests` exercises DES
- WHEN a default scan runs
- THEN the DES calls MUST NOT be emitted, so the weak-cipher contract does not match code that never ships
- AND a scan that asks for tests MUST still see them
- Pinned by: `TestRustParser_CfgTestModulesAreSkippedByDefault`

#### Scenario: The gate reads the predicate, not the spelling

- GIVEN `#[cfg(test)]`, `#[cfg(all(test, unix))]` and `#[cfg(any(test, feature = "x"))]`
- THEN each MUST gate the module
- AND `#[cfg(not(test))]` MUST NOT: it names the module as PRODUCTION code, and dropping it loses a real detection
- AND `#[cfg(feature = "test-utils")]` MUST NOT: its "test-utils" is string content, not the bare `test` flag, and the module ships
- AND an attribute stack or a comment between the attribute and the `mod` MUST NOT defeat the gate
- Pinned by: `TestRustParser_OnlyTheTestCfgGatesAModule`

#### Scenario: A test-only module's declarations stay out of the crate index

- GIVEN a `#[cfg(test)] mod tests` declaring a factory returning a DES cipher, called from the crate's production code
- WHEN a default scan runs
- THEN the receiver MUST NOT be typed from that declaration, because a declaration that ships only under `cargo test` cannot type shipped code
- Pinned by: `TestRustParser_CfgTestDeclarationsStayOutOfTheCrateIndex`

### Requirement: A crate's own root package matches the identity a consumer resolves

Cargo lets a manifest's `[package] name` use hyphens, but substitutes
underscores for the identifier code actually references — `use aes_gcm::...`,
never `use aes-gcm::...`. Scanning a hyphenated crate as its own target MUST
attribute its declarations to the underscore form, the same identity a
contract keys on and the same identity that crate carries when reached as
another crate's dependency, or a contract can never match while scanning its
own library.

#### Scenario: A hyphenated manifest name becomes the crate identifier

- GIVEN `Cargo.toml` declaring `name = "aes-gcm"`
- THEN the crate's own root package MUST be `aes_gcm`, not `aes-gcm`
- Pinned by: `TestDetectRootModule/rust-hyphenated-name-becomes-the-crate-identifier`

## Known gaps

These are measured shortfalls, not decisions. Each is real, each is recorded so
it is not rediscovered as news, and each names its size so a future change can
be judged against it.

### A prelude type inferred from a constructor keeps the crate's package — CLOSED

`let v = Vec::from(p); v.clone()` used to emit `pkg.(Vec).clone` rather than
`std.(Vec).clone`. The written spellings resolved correctly; only the inferred
one did not, because a bare wrapping constructor (`Vec::from`, with no `::` of
its own) duplicated its head into the wrapper text passed downstream
(`Vec::Vec<..>`), which the qualified-path reader then took for a module named
`Vec` holding a type also named `Vec`, falling back to the analyzed crate's
package. Closed two ways: `resolveRustReceiverType` now checks the prelude
table at both fallback points regardless of how a type got there, and
`rustScopedCallType` stopped duplicating a path-less constructor's own head
into `Vec::Vec<..>` in the first place (`TestRustParser_BareWrappingConstructorKeepsTheStandardLibraryPackage`,
`TestRustParser_PreludeTypeBoundary`). Was measured at 64 of 109,880 edges
across 53 published crates (`Box` 28, `Result` 18, `Vec` 16, `Option` 2); it
was a subset of the wrapper-package gap below, so the same fix closes the
share of that gap this exact shape produced.

### A crate's own package segment is taken verbatim from the manifest — CLOSED

Scanning a hyphenated crate's own source used to yield `aes-gcm.(AesGcm).encrypt`,
while the same crate reached as a dependency yielded the identifier form
`aes_gcm`. Contracts fire on consumers, so the consumer form is the one that
matters, but a contract could never match while scanning its own library.
Closed by normalizing the manifest's hyphenated `[package] name` to the
underscore form `DetectRootModule` already used for a dependency
(`TestDetectRootModule/rust-hyphenated-name-becomes-the-crate-identifier`).

### A receiver is not always seen through a wrapper

About 2,100 edges carry a wrapper (`Result`, `Option`, `Vec`, `Box`) in the
type field with a non-standard-library package. The bare-constructor shape
above was one confirmed source; the fix has not been re-measured against the
full 53-crate corpus, so this gap stays open until that re-measurement
confirms how much of the 2,100 it closes. Still the largest remaining shape
class, and the one to keep attacking.

### An operation on a type returned by a dependency's instance method is untyped

A contract keyed on such a type cannot fire when the value reaches it only
through that method. Chains through the analyzed crate's OWN methods resolve —
the crate index supplies the return type — and a value that reaches a typed
struct field or a static constructor chain resolves too, so `Prk.expand` and
`Okm.fill` do match where rustls stores the key in a field. What does not
resolve is the fluent spelling: `h.update(d); h.finalize()` keys
`sha2.Sha256.finalize`, while `h.chain_update(d).finalize()` keys nothing.
Measured at 126 edges whose method name matches a contract method but whose
receiver is honestly untyped. Closing it means having the parser consume the
KB's `return:` field, which today only fills return types for declarations
already in the graph. It costs no contract its construction or its update
surface, so a contract remains authorable for every shape in the backlog.

### A generic parameter can still reach the type field

About 190 keys carry a single-letter type with the crate's own package. A glob
can no longer claim one, but a bare parameter reaching the type field with the
local package is a separate family.

## Decisions deliberately not implemented

These were measured and declined. **They are settled: do not reopen them
without new evidence, and do not report them as defects.** Each records what
was measured and why the current behaviour is the right trade under the
governing rule.

### A crate's own `Result` alias keeps its identity

A crate declaring `pub type Result<T> = ...` keeps it, so
`sequoia_openpgp.(Result).unwrap` is intended, not a defect. Measured at 1435
edges, 996 of them sequoia's. No contract keys `Result.unwrap`, so the shape
fabricates no cryptographic identity; distinguishing an alias from a struct
would move all 1435 edges for a shape no rule can reach.

### A generic or associated-type prefix stays unresolved

`C::FieldBytesSize::method`, `T::Ref::from_ptr` and the like are left
unresolved. Measured at 47 edges. All 61 contract keys sharing those method
names name a concrete type in a specific crate, so these edges cannot match by
construction — the concrete type is unknowable at a generic site. The shape
does put a type-parameter name where a package belongs, which is noted as a
cosmetic consequence, not a finding.

**Partially reopened**: `trait_associated_types` (added for `KeyInit`,
`Digest`, `BlockSizeUser`, `AeadCore`) gives `C::FieldBytesSize` a real
identity when `C` is bound to `elliptic_curve::Curve`, because that one
associated type resolves to the same `GenericArray`-family answer regardless
of which concrete curve substitutes `C` — the "concrete type is unknowable"
premise does not hold for a size type shared across implementors. `Curve::Uint`
is deliberately NOT cataloged: it is not a size type, and its real type varies
per curve in a way this KB cannot state as one constant. `T::Ref::from_ptr` and
similar shapes tied to a genuinely per-implementor type remain unresolved —
this decision stays in force for those.

### Slice and primitive receivers carry no type

`fn f(d: &[u8]) -> usize { d.len() }` emits `pkg.len` with `receiver_var` set,
rather than `pkg.([u8]).len`. The old key asserted that the local package
declares a type named `[u8]`. Named-type parameter receivers are unaffected.

### Macro-generated declarations are not expanded

A type produced by a declaration macro (`foreign_type_and_impl_send_sync!` in
openssl and boring) is invisible to the declared-type facts. Expanding macro
bodies is out of scope for this capability.

### Cross-crate re-export chains are not followed

Only re-exports within the crate being analyzed are resolved. Following a
dependency's re-export of a third crate would require parsing that
dependency's sources for a shape that measurement showed to be rare in Rust.
