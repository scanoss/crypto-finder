# Crypto Dependency Intelligence

This context defines the language used to describe cryptographic evidence and
its relationships inside a dependency.

## Language

**Crypto finding**:
A rule-backed evidence record describing cryptographic behavior or metadata at
a dependency source location. A finding has one opaque finding ID.
_Avoid_: Asset variant, policy finding

**Metadata anchor**:
The dependency callable whose observed arguments or selected variant determine
the metadata carried by a crypto finding. It is not necessarily where the
cryptographic computation executes.
_Avoid_: Final function, execution method

**Crypto entry point**:
A dependency callable indexed by canonical signature so consumers can discover
the crypto findings and supporting calls reachable from it.
_Avoid_: Metadata anchor, execution method, lifecycle role

**Supporting call**:
A client-visible dependency call associated with the same crypto usage as a
finding and classified by its lifecycle role: factory, configuration,
operation, or output.
_Avoid_: Forward call, secondary finding

**Operation supporting call**:
The supporting call where the cryptographic computation is performed, such as
a block-processing or finalization method.
_Avoid_: Final function, operation entry point

**Forward call**:
A real implementation call made by a dependency function to another dependency
function.
_Avoid_: Subsequent client call, lifecycle edge

**Call graph**:
The directed graph of real implementation calls within analyzable dependency
source.
_Avoid_: Client invocation sequence, lifecycle graph

**Call chain**:
One ordered path through a call graph from an anchor to a reachable function.
_Avoid_: Fluent chain, receiver lifecycle

**Receiver lifecycle**:
The ordered client-visible calls made on the same logical object or value, where
earlier calls may configure later calls without forming implementation edges.
_Avoid_: Call graph, forward closure

**Canonical signature**:
The normalized callable identity containing the declaring type, method,
parameter types, and return type.
_Avoid_: Method name, name-and-arity key

**Finding ID**:
The opaque identifier assigned to one crypto finding and used for cross-record
references.
_Avoid_: Asset variant ID, downstream CBOM UUID

**Parameter condition**:
A structured predicate describing which argument value or type makes a crypto
finding applicable.
_Avoid_: Policy condition, free-text condition
