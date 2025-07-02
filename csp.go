// Package csp provides a secure and fluent API for building and compiling
// Content Security Policies (CSP).
package csp

import (
	"sort"
	"strings"
	"sync"
)

// These are the constants for all standard CSP directives.
// Using these constants prevents typos and ensures correctness.
// Source: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
const (
	// Fetch directives
	ChildSrc      = "child-src"
	ConnectSrc    = "connect-src"
	DefaultSrc    = "default-src"
	FontSrc       = "font-src"
	FrameSrc      = "frame-src"
	ImgSrc        = "img-src"
	ManifestSrc   = "manifest-src"
	MediaSrc      = "media-src"
	ObjectSrc     = "object-src"
	PrefetchSrc   = "prefetch-src" // Deprecated but supported
	ScriptSrc     = "script-src"
	ScriptSrcAttr = "script-src-attr"
	ScriptSrcElem = "script-src-elem"
	StyleSrc      = "style-src"
	StyleSrcAttr  = "style-src-attr"
	StyleSrcElem  = "style-src-elem"
	WorkerSrc     = "worker-src"

	// Document directives
	BaseURI     = "base-uri"
	PluginTypes = "plugin-types" // Deprecated
	Sandbox     = "sandbox"

	// Navigation directives
	FormAction     = "form-action"
	FrameAncestors = "frame-ancestors"
	NavigateTo     = "navigate-to" // Experimental

	// Reporting directives
	ReportTo  = "report-to"
	ReportURI = "report-uri" // Deprecated

	// Other directives
	BlockAllMixedContent    = "block-all-mixed-content"
	RequireSRIFor           = "require-sri-for"
	TrustedTypes            = "trusted-types"
	UpgradeInsecureRequests = "upgrade-insecure-requests"
)

// These are the constants for common CSP keyword sources and schemes.
// Using these constants improves readability and avoids errors with quoting.
const (
	// Keyword Sources
	SourceSelf          = "'self'"
	SourceUnsafeInline  = "'unsafe-inline'"
	SourceUnsafeEval    = "'unsafe-eval'"
	SourceNone          = "'none'"
	SourceNonce         = noncePlaceholder
	SourceStrictDynamic = "'strict-dynamic'"
	SourceReportSample  = "'report-sample'"
	SourceUnsafeHashes  = "'unsafe-hashes'" // CSP3

	// Scheme Sources
	SchemeBlob  = "blob:"
	SchemeData  = "data:"
	SchemeFile  = "filesystem:"
	SchemeHTTP  = "http:"
	SchemeHTTPS = "https:"
	SchemeMedia = "mediastream:"
)

// noncePlaceholder is the internal text that will be replaced by the actual nonce value.
const noncePlaceholder = "{{nonce}}"

// valuelessDirectives is a set of CSP directives that are valid without any value.
var valuelessDirectives = map[string]struct{}{
	BlockAllMixedContent:    {},
	UpgradeInsecureRequests: {},
	Sandbox:                 {}, // Can be used with or without values
}

// Nonce returns a correctly formatted nonce source string for a static nonce value.
// This function is idempotent; if the provided string is already a valid nonce
// source, it is returned as-is after trimming whitespace.
func Nonce(nonce string) string {
	nonceValue := strings.TrimPrefix(strings.Trim(strings.TrimSpace(nonce), "'"), "nonce-")
	return "'nonce-" + nonceValue + "'"
}

// Hash returns a correctly formatted hash source string.
// This function is idempotent; if the provided value is already a valid hash
// source for the given algorithm, it is returned as-is after trimming whitespace.
func Hash(algo string, base64Value string) string {
	hashValue := strings.Trim(strings.TrimSpace(base64Value), "'")

	// Check if the hash value already looks like a hash
	if dashIndex := strings.Index(hashValue, "-"); dashIndex > 0 {
		potentialAlgo := hashValue[:dashIndex]
		if strings.HasPrefix(potentialAlgo, "sha") {
			hashValue = hashValue[dashIndex+1:]
		}
	}

	return "'" + algo + "-" + hashValue + "'"
}

// Policy represents a Content Security Policy. It provides a thread-safe
// way to define and compile CSP headers, with support for lazy compilation
// and per-request nonce injection.
type Policy struct {
	mu         sync.Mutex
	directives map[string]map[string]struct{} // Using a map for sources ensures automatic deduplication.
	cache      string                         // Cached policy string with placeholders.
	isCompiled bool                           // Flag indicating if the policy has been compiled.
	needsNonce bool                           // Flag indicating if the compiled policy has a nonce placeholder.
}

// New creates and returns a new, empty Policy.
func New() *Policy {
	return &Policy{directives: make(map[string]map[string]struct{})}
}

// Add appends one or more sources to a given directive.
// For valueless directives (e.g., "sandbox"), provide no sources.
// Calling Add with no sources for a non-valueless directive has no effect.
// Any modification to the policy will cause the compiled version to be regenerated
// on the next call to Compile.
func (p *Policy) Add(directive string, sources ...string) {
	key := strings.ToLower(strings.TrimSpace(directive))
	if key == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	var validSources []string
	if len(sources) > 0 {
		// Filter out empty sources before locking
		validSources = make([]string, 0, len(sources))
		for _, source := range sources {
			s := strings.TrimSpace(source)
			if s != "" {
				validSources = append(validSources, s)
			}
		}
		// If all provided sources were empty, do nothing
		if len(validSources) == 0 {
			return
		}
	} else {
		// No sources provided. Only proceed if it's a known valueless directive
		if _, isValueless := valuelessDirectives[key]; !isValueless {
			return
		}
	}

	if _, ok := p.directives[key]; !ok {
		p.directives[key] = make(map[string]struct{})
	}

	for _, s := range validSources {
		p.directives[key][s] = struct{}{}
	}

	p.invalidateCache()
}

// Set replaces any existing sources for a given directive with the new ones.
// For non-valueless directives, providing no valid sources (or no sources at all)
// will remove the directive from the policy.
// For valueless directives (e.g., "sandbox"), providing no sources sets the
// directive without any value.
// Any modification to the policy will cause the compiled version to be regenerated
// on the next call to Compile.
func (p *Policy) Set(directive string, sources ...string) {
	key := strings.ToLower(strings.TrimSpace(directive))
	if key == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	defer p.invalidateCache()

	newSources := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		s := strings.TrimSpace(source)
		if s != "" {
			newSources[s] = struct{}{}
		}
	}

	// If no valid sources are provided, check if the directive can be valueless
	if len(newSources) == 0 {
		if _, ok := valuelessDirectives[key]; !ok {
			// If it's not a known valueless directive, remove it
			delete(p.directives, key)
			return
		}
		// Fall through to set valueless directive
	}

	p.directives[key] = newSources
}

// Remove removes a directive entirely from the policy.
// Any modification to the policy will cause the compiled version to be regenerated
// on the next call to Compile.
func (p *Policy) Remove(directive string) {
	key := strings.ToLower(strings.TrimSpace(directive))

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.directives[key]; ok {
		delete(p.directives, key)
		p.invalidateCache()
	}
}

// Compile generates the CSP header string from the policy.
// The directives are sorted alphabetically for a consistent, testable output.
// The sources within each directive are also sorted.
// The first call to Compile will build and cache the policy string. Subsequent
// calls are highly optimized. If a nonce is required, it will be injected.
func (p *Policy) Compile(nonce ...string) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Lazy compilation: if the cache is invalid, build it
	if !p.isCompiled {
		p.buildCacheUnsafe()
	}

	// If no nonce is required, return the cached policy
	if !p.needsNonce {
		return p.cache
	}

	// If a nonce is required by the policy and one was provided, inject it
	nonceValue := SourceNonce
	if len(nonce) > 0 && nonce[0] != "" {
		nonceValue = nonce[0]
	}
	return strings.ReplaceAll(p.cache, SourceNonce, Nonce(nonceValue))
}

// buildCacheUnsafe constructs the policy string and caches it.
// It assumes the caller holds the mutex.
func (p *Policy) buildCacheUnsafe() {
	defer func() { p.isCompiled = true }()

	if len(p.directives) == 0 {
		p.cache = ""
		p.needsNonce = false
		return
	}

	directiveKeys := make([]string, 0, len(p.directives))
	for k := range p.directives {
		directiveKeys = append(directiveKeys, k)
	}
	sort.Strings(directiveKeys)

	var b strings.Builder
	var hasNonce bool
	for i, key := range directiveKeys {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(key)

		sourcesMap := p.directives[key]
		if len(sourcesMap) == 0 {
			continue
		}

		b.WriteByte(' ')
		sourceKeys := make([]string, 0, len(sourcesMap))
		for s := range sourcesMap {
			sourceKeys = append(sourceKeys, s)
		}
		sort.Strings(sourceKeys)

		for j, s := range sourceKeys {
			if j > 0 {
				b.WriteByte(' ')
			}

			hasNonce = hasNonce || s == SourceNonce
			b.WriteString(s)
		}
	}

	p.cache = b.String()
	p.needsNonce = hasNonce
}

// invalidateCache clears the compiled policy, forcing a rebuild on the next Compile call.
// This must be called by any method that modifies the directives.
func (p *Policy) invalidateCache() {
	p.isCompiled = false
	p.cache = ""
	p.needsNonce = false
}
