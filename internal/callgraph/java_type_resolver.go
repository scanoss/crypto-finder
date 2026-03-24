package callgraph

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

// JavaBytecodeTypeResolver reads compiled .class files from Maven-cached JARs
// to extract method signatures with full type information. This provides
// accurate parameter and return types without requiring a JDK or compilation.
type JavaBytecodeTypeResolver struct {
	// mavenRepoPath is the root of the Maven local repository (e.g., ~/.m2/repository).
	mavenRepoPath string
}

// NewJavaBytecodeTypeResolver creates a resolver that reads bytecode from Maven JARs.
func NewJavaBytecodeTypeResolver() *JavaBytecodeTypeResolver {
	home, _ := os.UserHomeDir()
	return &JavaBytecodeTypeResolver{
		mavenRepoPath: filepath.Join(home, ".m2", "repository"),
	}
}

// methodSignature holds parsed method type information from bytecode.
type methodSignature struct {
	className  string   // e.g., "JwtBuilder"
	methodName string   // e.g., "signWith"
	paramTypes []string // e.g., ["SignatureAlgorithm", "byte[]"]
	returnType string   // e.g., "JwtBuilder"
	fullClass  string   // e.g., "io.jsonwebtoken.JwtBuilder"
}

// ResolveTypes enriches the call graph with type information from Java bytecode.
func (r *JavaBytecodeTypeResolver) ResolveTypes(graph *CallGraph, sourceRoots []PackageDir) error {
	// Build method index and type hierarchy from all available JARs
	index := make(map[string][]methodSignature) // "ClassName.methodName" → signatures
	hierarchy := make(map[string][]string)        // "JwtBuilder" → ["ClaimsMutator"]

	for _, root := range sourceRoots {
		jarPath := r.findCompiledJAR(root.ImportPath)
		if jarPath == "" {
			continue
		}

		classInfos, err := r.extractFromJAR(jarPath)
		if err != nil {
			log.Debug().Err(err).Str("jar", jarPath).Msg("Failed to read JAR for type resolution")
			continue
		}

		for _, info := range classInfos {
			for _, sig := range info.methods {
				key := sig.className + "." + sig.methodName
				index[key] = append(index[key], sig)
			}
			if len(info.interfaces) > 0 {
				hierarchy[info.className] = info.interfaces
			}
		}
	}

	// Propagate parent interface methods to child types.
	// If JwtBuilder extends ClaimsMutator, then JwtBuilder.setId inherits ClaimsMutator.setId.
	for childType, parents := range hierarchy {
		for _, parentType := range parents {
			for key, parentSigs := range index {
				if !strings.HasPrefix(key, parentType+".") {
					continue
				}
				methodName := key[len(parentType)+1:]
				childKey := childType + "." + methodName
				if _, exists := index[childKey]; exists {
					continue // child already declares this method
				}
				// Inherit parent's signatures under the child type name
				inherited := make([]methodSignature, len(parentSigs))
				for i, sig := range parentSigs {
					inherited[i] = sig
					inherited[i].className = childType
				}
				index[childKey] = inherited
			}
		}
	}

	// Store hierarchy on the graph for use by the fluent chain resolver
	if graph.TypeHierarchy == nil {
		graph.TypeHierarchy = make(map[string][]string)
	}
	for k, v := range hierarchy {
		graph.TypeHierarchy[k] = v
	}

	if len(index) == 0 {
		return nil
	}

	// Enrich function declarations with parameter types from bytecode
	resolved := 0
	for _, fn := range graph.Functions {
		if fn.ID.Type == "" {
			continue
		}
		key := fn.ID.Type + "." + BaseFunctionName(fn.ID.Name)
		sigs := index[key]
		if len(sigs) == 0 {
			continue
		}

		// Find matching signature by arity
		arity := len(fn.Parameters)
		for _, sig := range sigs {
			if len(sig.paramTypes) != arity {
				continue
			}
			// Enrich parameter types — prefer bytecode types over generic type params
			enriched := false
			for i := range fn.Parameters {
				if i < len(sig.paramTypes) && shouldOverrideType(fn.Parameters[i].Type, sig.paramTypes[i]) {
					fn.Parameters[i].Type = sig.paramTypes[i]
					enriched = true
				}
			}
			// Enrich return type if missing
			if fn.ReturnType == "" && sig.returnType != "" {
				fn.ReturnType = sig.returnType
				enriched = true
			}
			if enriched {
				resolved++
			}
			break
		}
	}

	// Also resolve unresolved calls using the index
	callsResolved := 0
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			calleeKey := call.Callee.String()
			if _, ok := graph.Functions[calleeKey]; ok {
				continue // already resolved
			}

			// Try to find callee type in bytecode index
			typeName := call.Callee.Type
			if typeName == "" || strings.Contains(typeName, "(") {
				continue // no type or fluent chain
			}
			methodName := BaseFunctionName(call.Callee.Name)
			key := typeName + "." + methodName
			sigs := index[key]
			if len(sigs) == 0 {
				continue
			}

			// Find best match by arity
			arity := len(call.Arguments)
			for _, sig := range sigs {
				if len(sig.paramTypes) != arity && arity > 0 {
					continue
				}

				// Rewrite callee to the correct package
				newID := FunctionID{
					Package: sig.fullClass[:strings.LastIndex(sig.fullClass, ".")],
					Type:    sig.className,
					Name:    call.Callee.Name,
				}
				newKey := newID.String()
				if _, ok := graph.Functions[newKey]; ok {
					call.Callee = newID
					addCaller(graph.Callers, newKey, fn.ID.String())
					callsResolved++
				}
				break
			}
		}
	}

	log.Info().
		Int("declarations_enriched", resolved).
		Int("calls_resolved", callsResolved).
		Int("methods_indexed", len(index)).
		Msg("Java bytecode type resolution complete")

	return nil
}

// findCompiledJAR locates the compiled JAR for a Maven dependency.
// importPath format: "groupId:artifactId" (e.g., "io.jsonwebtoken:jjwt-api")
func (r *JavaBytecodeTypeResolver) findCompiledJAR(importPath string) string {
	parts := strings.SplitN(importPath, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	groupID := parts[0]
	artifactID := parts[1]

	// Convert groupId to directory path
	groupDir := strings.ReplaceAll(groupID, ".", string(filepath.Separator))
	artifactDir := filepath.Join(r.mavenRepoPath, groupDir, artifactID)

	// Find any version directory with a JAR
	entries, err := os.ReadDir(artifactDir)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		version := entry.Name()
		jarPath := filepath.Join(artifactDir, version, artifactID+"-"+version+".jar")
		if _, err := os.Stat(jarPath); err == nil {
			return jarPath
		}
	}
	return ""
}

// extractFromJAR reads all .class files from a JAR and extracts method signatures and type hierarchy.
func (r *JavaBytecodeTypeResolver) extractFromJAR(jarPath string) ([]*classFileInfo, error) {
	reader, err := zip.OpenReader(jarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JAR %s: %w", jarPath, err)
	}
	defer reader.Close()

	var results []*classFileInfo
	for _, f := range reader.File {
		if !strings.HasSuffix(f.Name, ".class") {
			continue
		}
		baseName := filepath.Base(f.Name)
		if strings.Contains(baseName, "$") {
			continue // skip inner classes
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		info, err := parseClassFile(data, f.Name)
		if err != nil {
			log.Debug().Err(err).Str("class", f.Name).Msg("Failed to parse class file")
			continue
		}
		results = append(results, info)
	}

	return results, nil
}

// shouldOverrideType returns true when a bytecode type should replace a tree-sitter type.
// This handles cases like generic type parameters (K, T, E) that tree-sitter extracts
// from source but bytecode has the erased, fully-qualified type.
func shouldOverrideType(treeSitterType, bytecodeType string) bool {
	if treeSitterType == "" {
		return true
	}
	// Single uppercase letter = generic type parameter (K, T, E, V, etc.)
	if len(treeSitterType) == 1 && treeSitterType[0] >= 'A' && treeSitterType[0] <= 'Z' {
		return true
	}
	// Generic with bounds like "? super K" or "K extends Key"
	if strings.Contains(treeSitterType, "?") || strings.Contains(treeSitterType, " extends ") || strings.Contains(treeSitterType, " super ") {
		return true
	}
	return false
}

// --- Java .class file parser (minimal — only reads constant pool + methods) ---

// classFileInfo holds the parsed result from a single .class file.
type classFileInfo struct {
	className     string            // simple name, e.g. "JwtBuilder"
	fullClassName string            // e.g. "io.jsonwebtoken.JwtBuilder"
	interfaces    []string          // simple parent interface names, e.g. ["ClaimsMutator"]
	methods       []methodSignature // method signatures
}

// parseClassFile extracts method signatures and interface hierarchy from a .class file.
func parseClassFile(data []byte, _ string) (*classFileInfo, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("class file too short")
	}

	// Magic number check
	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != 0xCAFEBABE {
		return nil, fmt.Errorf("invalid class file magic: %x", magic)
	}

	// Parse constant pool
	offset := 8 // skip magic (4) + minor_version (2) + major_version (2)
	cpCount := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	cp, newOffset, err := parseConstantPool(data, offset, cpCount)
	if err != nil {
		return nil, err
	}
	offset = newOffset

	// Skip access_flags (2) + this_class (2)
	if offset+4 > len(data) {
		return nil, fmt.Errorf("unexpected end of class file")
	}
	thisClassIdx := int(binary.BigEndian.Uint16(data[offset+2:]))
	offset += 4

	// Get class name from constant pool
	className := ""
	fullClassName := ""
	if thisClassIdx > 0 && thisClassIdx < len(cp) {
		if cp[thisClassIdx].tag == 7 { // CONSTANT_Class
			nameIdx := cp[thisClassIdx].intValue
			if nameIdx > 0 && nameIdx < len(cp) {
				fullClassName = strings.ReplaceAll(cp[nameIdx].strValue, "/", ".")
				if lastDot := strings.LastIndex(fullClassName, "."); lastDot >= 0 {
					className = fullClassName[lastDot+1:]
				} else {
					className = fullClassName
				}
			}
		}
	}

	if className == "" {
		return nil, fmt.Errorf("could not determine class name")
	}

	// Skip super_class (2)
	offset += 2

	// Read interfaces
	if offset+2 > len(data) {
		return nil, fmt.Errorf("unexpected end reading interfaces")
	}
	interfacesCount := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	var interfaces []string
	for range interfacesCount {
		if offset+2 > len(data) {
			break
		}
		ifaceIdx := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if ifaceIdx > 0 && ifaceIdx < len(cp) && cp[ifaceIdx].tag == 7 {
			nameIdx := cp[ifaceIdx].intValue
			if nameIdx > 0 && nameIdx < len(cp) {
				ifaceName := strings.ReplaceAll(cp[nameIdx].strValue, "/", ".")
				if lastDot := strings.LastIndex(ifaceName, "."); lastDot >= 0 {
					interfaces = append(interfaces, ifaceName[lastDot+1:])
				}
			}
		}
	}

	// Skip fields
	offset, err = skipFieldsOrMethods(data, offset, cp)
	if err != nil {
		return nil, fmt.Errorf("failed to skip fields: %w", err)
	}

	// Parse methods
	if offset+2 > len(data) {
		return nil, fmt.Errorf("unexpected end reading methods count")
	}
	methodsCount := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	var sigs []methodSignature
	for range methodsCount {
		if offset+8 > len(data) {
			break
		}
		// access_flags (2) + name_index (2) + descriptor_index (2) + attributes_count (2)
		nameIdx := int(binary.BigEndian.Uint16(data[offset+2:]))
		descIdx := int(binary.BigEndian.Uint16(data[offset+4:]))
		attrCount := int(binary.BigEndian.Uint16(data[offset+6:]))
		offset += 8

		// Skip attributes
		for range attrCount {
			if offset+6 > len(data) {
				return &classFileInfo{className: className, fullClassName: fullClassName, interfaces: interfaces, methods: sigs}, nil
			}
			attrLen := int(binary.BigEndian.Uint32(data[offset+2:]))
			offset += 6 + attrLen
		}

		methodName := ""
		descriptor := ""
		if nameIdx > 0 && nameIdx < len(cp) {
			methodName = cp[nameIdx].strValue
		}
		if descIdx > 0 && descIdx < len(cp) {
			descriptor = cp[descIdx].strValue
		}

		if methodName == "" || descriptor == "" || methodName == "<clinit>" {
			continue
		}

		params, ret := parseMethodDescriptor(descriptor)
		sigs = append(sigs, methodSignature{
			className:  className,
			methodName: methodName,
			paramTypes: params,
			returnType: ret,
			fullClass:  fullClassName,
		})
	}

	return &classFileInfo{
		className:     className,
		fullClassName: fullClassName,
		interfaces:    interfaces,
		methods:       sigs,
	}, nil
}

type cpEntry struct {
	tag      uint8
	strValue string
	intValue int
}

func parseConstantPool(data []byte, offset, count int) ([]cpEntry, int, error) {
	cp := make([]cpEntry, count)
	i := 1 // constant pool indices start at 1
	for i < count {
		if offset >= len(data) {
			return cp, offset, fmt.Errorf("unexpected end of constant pool at index %d", i)
		}
		tag := data[offset]
		offset++

		switch tag {
		case 1: // CONSTANT_Utf8
			if offset+2 > len(data) {
				return cp, offset, fmt.Errorf("truncated utf8 at index %d", i)
			}
			length := int(binary.BigEndian.Uint16(data[offset:]))
			offset += 2
			if offset+length > len(data) {
				return cp, offset, fmt.Errorf("truncated utf8 string at index %d", i)
			}
			cp[i] = cpEntry{tag: tag, strValue: string(data[offset : offset+length])}
			offset += length
		case 3, 4: // CONSTANT_Integer, CONSTANT_Float
			if offset+4 > len(data) {
				return cp, offset, fmt.Errorf("truncated int/float at index %d", i)
			}
			cp[i] = cpEntry{tag: tag, intValue: int(binary.BigEndian.Uint32(data[offset:]))}
			offset += 4
		case 5, 6: // CONSTANT_Long, CONSTANT_Double (takes 2 entries)
			if offset+8 > len(data) {
				return cp, offset, fmt.Errorf("truncated long/double at index %d", i)
			}
			cp[i] = cpEntry{tag: tag}
			offset += 8
			i++ // long/double takes 2 entries
		case 7: // CONSTANT_Class
			if offset+2 > len(data) {
				return cp, offset, fmt.Errorf("truncated class at index %d", i)
			}
			cp[i] = cpEntry{tag: tag, intValue: int(binary.BigEndian.Uint16(data[offset:]))}
			offset += 2
		case 8: // CONSTANT_String
			if offset+2 > len(data) {
				return cp, offset, fmt.Errorf("truncated string at index %d", i)
			}
			cp[i] = cpEntry{tag: tag, intValue: int(binary.BigEndian.Uint16(data[offset:]))}
			offset += 2
		case 9, 10, 11: // CONSTANT_Fieldref, CONSTANT_Methodref, CONSTANT_InterfaceMethodref
			if offset+4 > len(data) {
				return cp, offset, fmt.Errorf("truncated ref at index %d", i)
			}
			cp[i] = cpEntry{tag: tag}
			offset += 4
		case 12: // CONSTANT_NameAndType
			if offset+4 > len(data) {
				return cp, offset, fmt.Errorf("truncated name_and_type at index %d", i)
			}
			cp[i] = cpEntry{tag: tag}
			offset += 4
		case 15: // CONSTANT_MethodHandle
			if offset+3 > len(data) {
				return cp, offset, fmt.Errorf("truncated method_handle at index %d", i)
			}
			cp[i] = cpEntry{tag: tag}
			offset += 3
		case 16: // CONSTANT_MethodType
			if offset+2 > len(data) {
				return cp, offset, fmt.Errorf("truncated method_type at index %d", i)
			}
			cp[i] = cpEntry{tag: tag}
			offset += 2
		case 17, 18: // CONSTANT_Dynamic, CONSTANT_InvokeDynamic
			if offset+4 > len(data) {
				return cp, offset, fmt.Errorf("truncated dynamic at index %d", i)
			}
			cp[i] = cpEntry{tag: tag}
			offset += 4
		case 19, 20: // CONSTANT_Module, CONSTANT_Package
			if offset+2 > len(data) {
				return cp, offset, fmt.Errorf("truncated module/package at index %d", i)
			}
			cp[i] = cpEntry{tag: tag}
			offset += 2
		default:
			return cp, offset, fmt.Errorf("unknown constant pool tag %d at index %d", tag, i)
		}
		i++
	}
	return cp, offset, nil
}

func skipFieldsOrMethods(data []byte, offset int, _ []cpEntry) (int, error) {
	if offset+2 > len(data) {
		return offset, fmt.Errorf("unexpected end reading count")
	}
	count := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	for range count {
		if offset+8 > len(data) {
			return offset, fmt.Errorf("unexpected end in field/method")
		}
		attrCount := int(binary.BigEndian.Uint16(data[offset+6:]))
		offset += 8
		for range attrCount {
			if offset+6 > len(data) {
				return offset, fmt.Errorf("unexpected end in attribute")
			}
			attrLen := int(binary.BigEndian.Uint32(data[offset+2:]))
			offset += 6 + attrLen
		}
	}
	return offset, nil
}

// parseMethodDescriptor parses a JVM method descriptor string.
// Example: "(Lio/jsonwebtoken/SignatureAlgorithm;[B)Lio/jsonwebtoken/JwtBuilder;"
// Returns: params=["SignatureAlgorithm", "byte[]"], return="JwtBuilder"
func parseMethodDescriptor(desc string) (params []string, returnType string) {
	if len(desc) == 0 || desc[0] != '(' {
		return nil, ""
	}

	i := 1 // skip '('
	for i < len(desc) && desc[i] != ')' {
		typeName, newI := parseJVMType(desc, i)
		if newI <= i {
			break // prevent infinite loop
		}
		params = append(params, typeName)
		i = newI
	}

	// Skip ')'
	if i < len(desc) {
		i++
	}

	// Parse return type
	if i < len(desc) {
		returnType, _ = parseJVMType(desc, i)
	}

	return params, returnType
}

// parseJVMType parses a single JVM type from a descriptor at position i.
// Returns the human-readable type name and the new position.
func parseJVMType(desc string, i int) (string, int) {
	if i >= len(desc) {
		return "", i
	}

	switch desc[i] {
	case 'B':
		return "byte", i + 1
	case 'C':
		return "char", i + 1
	case 'D':
		return "double", i + 1
	case 'F':
		return "float", i + 1
	case 'I':
		return "int", i + 1
	case 'J':
		return "long", i + 1
	case 'S':
		return "short", i + 1
	case 'V':
		return "void", i + 1
	case 'Z':
		return "boolean", i + 1
	case '[':
		elemType, newI := parseJVMType(desc, i+1)
		return elemType + "[]", newI
	case 'L':
		semicolon := strings.Index(desc[i:], ";")
		if semicolon < 0 {
			return "", len(desc)
		}
		fullPath := desc[i+1 : i+semicolon]
		// Convert "io/jsonwebtoken/SignatureAlgorithm" → "io.jsonwebtoken.SignatureAlgorithm"
		return strings.ReplaceAll(fullPath, "/", "."), i + semicolon + 1
	default:
		return "", i + 1
	}
}
