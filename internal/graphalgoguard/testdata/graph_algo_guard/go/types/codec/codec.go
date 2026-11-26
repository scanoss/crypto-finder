package codec

type Encoding struct{ name string }

func New(name string) *Encoding { return &Encoding{name} }

func (e *Encoding) Encode(src []byte) string { return e.name + string(src) }

var Std = New("std")

// Sealer is an interface its callers hold without knowing the implementation.
type Sealer interface{ Seal(src []byte) []byte }

func NewSealer() Sealer { return New("sealer") }

func (e *Encoding) Seal(src []byte) []byte { return src }
