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

// valuelessDirectives is a set of CSP directives that are valid without any value.
var valuelessDirectives = map[string]struct{}{
	BlockAllMixedContent:    {},
	UpgradeInsecureRequests: {},
	Sandbox:                 {}, // Can be used with or without values.
}

// Nonce returns a correctly formatted nonce source string.
// Example: 'nonce-R4nd0m'
func Nonce(nonce string) string {
	return "'nonce-" + nonce + "'"
}

// Hash returns a correctly formatted hash source string.
// Example: 'sha256-Abc123=='
func Hash(algo, base64Value string) string {
	return "'" + algo + "-" + base64Value + "'"
}

// Policy represents a Content Security Policy. It provides a thread-safe
// way to define and compile CSP headers.
type Policy struct {
	mu         sync.RWMutex
	directives map[string]map[string]struct{} // Using a map for sources ensures automatic deduplication.
}

// New creates and returns a new, empty Policy.
func New() *Policy {
	return &Policy{
		directives: make(map[string]map[string]struct{}),
	}
}

// Add appends one or more sources to a given directive.
// For valueless directives (e.g., "sandbox"), provide no sources.
// Calling Add with no sources for a non-valueless directive has no effect.
func (p *Policy) Add(directive string, sources ...string) {
	key := strings.ToLower(strings.TrimSpace(directive))
	if key == "" {
		return
	}

	var validSources []string
	if len(sources) > 0 {
		// Filter out empty sources before locking.
		validSources = make([]string, 0, len(sources))
		for _, source := range sources {
			s := strings.TrimSpace(source)
			if s != "" {
				validSources = append(validSources, s)
			}
		}
		// If all provided sources were empty, do nothing.
		if len(validSources) == 0 {
			return
		}
	} else {
		// No sources provided. Only proceed if it's a known valueless directive.
		if _, isValueless := valuelessDirectives[key]; !isValueless {
			return
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.directives[key]; !ok {
		p.directives[key] = make(map[string]struct{})
	}

	for _, s := range validSources {
		p.directives[key][s] = struct{}{}
	}
}

// Set replaces any existing sources for a given directive with the new ones.
// For non-valueless directives, providing no valid sources (or no sources at all)
// will remove the directive from the policy.
// For valueless directives (e.g., "sandbox"), providing no sources sets the
// directive without any value.
func (p *Policy) Set(directive string, sources ...string) {
	key := strings.ToLower(strings.TrimSpace(directive))
	if key == "" {
		return
	}

	newSources := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		s := strings.TrimSpace(source)
		if s != "" {
			newSources[s] = struct{}{}
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

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
func (p *Policy) Remove(directive string) {
	key := strings.ToLower(strings.TrimSpace(directive))
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.directives, key)
}

// Compile generates the CSP header string from the policy.
// The directives are sorted alphabetically for a consistent, testable output.
// The sources within each directive are also sorted.
func (p *Policy) Compile() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.directives) == 0 {
		return ""
	}

	// Sort directives for consistent output.
	directiveKeys := make([]string, 0, len(p.directives))
	for k := range p.directives {
		directiveKeys = append(directiveKeys, k)
	}
	sort.Strings(directiveKeys)

	var b strings.Builder
	for i, key := range directiveKeys {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(key)

		sourcesMap := p.directives[key]
		if len(sourcesMap) > 0 {
			// Sort sources for consistent output.
			sourceKeys := make([]string, 0, len(sourcesMap))
			for s := range sourcesMap {
				sourceKeys = append(sourceKeys, s)
			}
			sort.Strings(sourceKeys)

			b.WriteByte(' ')
			b.WriteString(strings.Join(sourceKeys, " "))
		}
	}
	return b.String()
}
