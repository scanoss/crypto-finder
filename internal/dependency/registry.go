package dependency

import "fmt"

// Registry maps ecosystem names to their resolver implementations.
type Registry struct {
	resolvers map[string]Resolver
}

// NewRegistry creates a new empty resolver registry.
func NewRegistry() *Registry {
	return &Registry{
		resolvers: make(map[string]Resolver),
	}
}

// Register adds a resolver for the given ecosystem name.
func (r *Registry) Register(name string, resolver Resolver) {
	r.resolvers[name] = resolver
}

// Get returns the resolver for the given ecosystem name.
func (r *Registry) Get(name string) (Resolver, error) {
	resolver, ok := r.resolvers[name]
	if !ok {
		return nil, fmt.Errorf("no resolver registered for ecosystem %q", name)
	}
	return resolver, nil
}
