package csp

import (
	"fmt"
	"sync"
	"testing"
)

// TestHelpers tests the correctness of the Nonce, ParseHash, and Hash helper functions.
func TestHelpers(t *testing.T) {
	t.Parallel()

	t.Run("Nonce", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name     string
			input    string
			expected string
		}{
			{"Simple nonce", "abc", "'nonce-abc'"},
			{"Nonce with spaces", "  abc  ", "'nonce-abc'"},
			{"Already quoted", "'nonce-123'", "'nonce-123'"},
			{"Already quoted with spaces", "  'nonce-123'  ", "'nonce-123'"},
			{"No nonce- prefix", "'abc'", "'nonce-abc'"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				if got := Nonce(tt.input); got != tt.expected {
					t.Errorf("Nonce(%q) = %q, want %q", tt.input, got, tt.expected)
				}
			})
		}
	})

	t.Run("ParseHash", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name        string
			algo        string
			value       string
			expected    string
			expectError bool
		}{
			{"Valid sha256", "sha256", "eHl6", "'sha256-eHl6'", false}, // "eHl6" is base64 for "xyz"
			{"Valid sha384", "sha384", "eHl6", "'sha384-eHl6'", false},
			{"Valid sha512", "sha512", "eHl6", "'sha512-eHl6'", false},
			{"With spaces", "sha256", "  eHl6  ", "'sha256-eHl6'", false},
			{"Already quoted", "sha256", "'sha256-eHl6'", "'sha256-eHl6'", false},
			{"Unsupported algorithm", "md5", "eHl6", "", true},
			{"Invalid base64", "sha256", "not-base-64!", "", true},
			{"Mismatched idempotency check", "sha256", "'sha384-eHl6'", "", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				got, err := ParseHash(tt.algo, tt.value)
				if tt.expectError {
					if err == nil {
						t.Errorf("ParseHash(%q, %q) expected error, got none", tt.algo, tt.value)
					}
				} else {
					if err != nil {
						t.Errorf("ParseHash(%q, %q) unexpected error: %v", tt.algo, tt.value, err)
					}
					if got != tt.expected {
						t.Errorf("ParseHash(%q, %q) = %q, want %q", tt.algo, tt.value, got, tt.expected)
					}
				}
			})
		}
	})

	t.Run("Hash", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name     string
			algo     string
			value    string
			expected string
		}{
			{"Valid fallback", "sha256", "eHl6", "'sha256-eHl6'"},
			{"Invalid fallback (bad base64)", "sha256", "invalid!base64", ""},
			{"Invalid fallback (bad algo)", "md5", "eHl6", ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				if got := Hash(tt.algo, tt.value); got != tt.expected {
					t.Errorf("Hash(%q, %q) = %q, want %q", tt.algo, tt.value, got, tt.expected)
				}
			})
		}
	})
}

// TestPolicy_New verifies that the New function returns a valid Policy
// object with an empty directives map.
func TestPolicy_New(t *testing.T) {
	t.Parallel()

	p := New()
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if p.directives == nil {
		t.Fatal("New() did not initialize directives map")
	}
	if len(p.directives) != 0 {
		t.Errorf("Expected 0 directives, got %d", len(p.directives))
	}
}

// TestPolicy_Add tests the Add method of the Policy object.
// It verifies that the Add method correctly adds sources to directives,
// handles duplicate sources, and handles valueless directives.
func TestPolicy_Add(t *testing.T) {
	t.Parallel()

	type addAction struct {
		directive string
		sources   []string
	}

	tests := []struct {
		name           string
		actions        []addAction
		checkDirective string
		wantSources    map[string]bool // nil means directive should not exist
		wantTotalDirs  int
	}{
		{
			name: "add to new directive",
			actions: []addAction{
				{DefaultSrc, []string{SourceSelf}},
			},
			checkDirective: DefaultSrc,
			wantSources:    map[string]bool{SourceSelf: true},
			wantTotalDirs:  1,
		},
		{
			name: "add to existing directive",
			actions: []addAction{
				{DefaultSrc, []string{SourceSelf}},
				{DefaultSrc, []string{"https://example.com"}},
			},
			checkDirective: DefaultSrc,
			wantSources:    map[string]bool{SourceSelf: true, "https://example.com": true},
			wantTotalDirs:  1,
		},
		{
			name: "add duplicate source",
			actions: []addAction{
				{DefaultSrc, []string{SourceSelf}},
				{DefaultSrc, []string{SourceSelf}},
			},
			checkDirective: DefaultSrc,
			wantSources:    map[string]bool{SourceSelf: true},
			wantTotalDirs:  1,
		},
		{
			name: "add with only empty sources",
			actions: []addAction{
				{DefaultSrc, []string{"   ", ""}},
			},
			checkDirective: DefaultSrc,
			wantSources:    nil,
			wantTotalDirs:  0,
		},
		{
			name: "add with no sources",
			actions: []addAction{
				{DefaultSrc, []string{}},
			},
			checkDirective: DefaultSrc,
			wantSources:    nil,
			wantTotalDirs:  0,
		},
		{
			name: "add with mixed valid and empty sources",
			actions: []addAction{
				{DefaultSrc, []string{" ", SourceSelf, ""}},
			},
			checkDirective: DefaultSrc,
			wantSources:    map[string]bool{SourceSelf: true},
			wantTotalDirs:  1,
		},
		{
			name: "add valueless directive",
			actions: []addAction{
				{BlockAllMixedContent, nil},
			},
			checkDirective: BlockAllMixedContent,
			wantSources:    map[string]bool{},
			wantTotalDirs:  1,
		},
		{
			name: "add directive case insensitivity",
			actions: []addAction{
				{"Script-SRC", []string{SourceSelf}},
				{ScriptSrc, []string{"https://example.com"}},
			},
			checkDirective: ScriptSrc,
			wantSources:    map[string]bool{SourceSelf: true, "https://example.com": true},
			wantTotalDirs:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := New()
			for _, action := range tt.actions {
				p.Add(action.directive, action.sources...)
			}
			if tt.wantSources == nil {
				if _, ok := p.directives[tt.checkDirective]; ok {
					t.Errorf("directive %q should not exist", tt.checkDirective)
				}
			} else {
				got, ok := p.directives[tt.checkDirective]
				if !ok {
					t.Fatalf("directive %q was not added", tt.checkDirective)
				}
				if len(got) != len(tt.wantSources) {
					t.Errorf("expected %d sources, got %d", len(tt.wantSources), len(got))
				}
				for k := range tt.wantSources {
					if _, ok := got[k]; !ok {
						t.Errorf("expected source %q to be present", k)
					}
				}
			}
			if len(p.directives) != tt.wantTotalDirs {
				t.Errorf("expected %d total directives, got %d", tt.wantTotalDirs, len(p.directives))
			}
		})
	}
}

// TestPolicy_Set verifies that the Set method of the Policy object
// correctly replaces the sources for a directive, removes the directive
// if no valid sources are provided, and handles valueless directives.
func TestPolicy_Set(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		directive         string
		sources           []string
		wantDirective     map[string]bool
		wantTotalDirs     int
		checkCompileEmpty bool
	}{
		{
			name:              "valid sources",
			directive:         DefaultSrc,
			sources:           []string{SourceNone},
			wantDirective:     map[string]bool{SourceNone: true},
			wantTotalDirs:     1,
			checkCompileEmpty: false,
		},
		{
			name:              "only empty sources removes directive",
			directive:         DefaultSrc,
			sources:           []string{" ", "   "},
			wantDirective:     nil,
			wantTotalDirs:     0,
			checkCompileEmpty: true,
		},
		{
			name:              "empty directive",
			directive:         "",
			sources:           []string{SourceNone},
			wantDirective:     nil,
			wantTotalDirs:     0,
			checkCompileEmpty: true,
		},
		{
			name:              "empty slice removes directive",
			directive:         DefaultSrc,
			sources:           nil,
			wantDirective:     nil,
			wantTotalDirs:     0,
			checkCompileEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := New()
			p.Add(tt.directive, SourceSelf)
			p.Set(tt.directive, tt.sources...)

			if tt.wantDirective == nil {
				if _, ok := p.directives[DefaultSrc]; ok {
					t.Errorf("directive %q should have been removed", tt.directive)
				}
			} else {
				got := p.directives[tt.directive]
				if len(got) != len(tt.wantDirective) {
					t.Errorf("expected %d sources, got %d", len(tt.wantDirective), len(got))
				}
				for k := range tt.wantDirective {
					if _, ok := got[k]; !ok {
						t.Errorf("expected source %q to be present", k)
					}
				}
			}
			if len(p.directives) != tt.wantTotalDirs {
				t.Errorf("expected %d total directives, got %d", tt.wantTotalDirs, len(p.directives))
			}
			if tt.checkCompileEmpty {
				if got := p.Compile(); got != "" {
					t.Errorf("expected compiled policy to be empty, got %q", got)
				}
			}
		})
	}
}

// TestPolicy_Remove verifies that the Remove method of the Policy object
// correctly removes a directive from the policy if it exists.
// It also verifies that the Remove method does not panic if the directive
// does not exist.
func TestPolicy_Remove(t *testing.T) {
	t.Parallel()
	p := New()
	p.Add(DefaultSrc, SourceSelf)
	p.Add(ScriptSrc, SourceSelf)
	p.Remove(DefaultSrc)

	if _, ok := p.directives[DefaultSrc]; ok {
		t.Errorf("Directive %q should have been removed", DefaultSrc)
	}
	if len(p.directives) != 1 {
		t.Errorf("Expected 1 directive after Remove, got %d", len(p.directives))
	}
}

// TestPolicy_Compile tests the Compile method of the Policy object.
// It verifies that the Compile method correctly generates the CSP header string
// from the policy, sorts the directives alphabetically, and sorts the sources
// alphabetically within each directive. It also verifies that the Compile
// method handles valueless directives and nonces correctly.
func TestPolicy_Compile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setup      func(*Policy)
		preCompile bool
		nonce      []string
		expected   string
	}{
		{
			name:     "empty policy",
			setup:    func(p *Policy) {},
			expected: "",
		},
		{
			name: "single directive",
			setup: func(p *Policy) {
				p.Add(DefaultSrc, SourceSelf)
			},
			expected: "default-src 'self'",
		},
		{
			name: "multiple sources sorted",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, "https://b.com", "https://a.com", SourceSelf)
			},
			expected: "script-src 'self' https://a.com https://b.com",
		},
		{
			name: "multiple directives sorted",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, SourceSelf)
				p.Add(DefaultSrc, SourceNone)
			},
			expected: "default-src 'none'; script-src 'self'",
		},
		{
			name: "valueless directive",
			setup: func(p *Policy) {
				p.Add(UpgradeInsecureRequests)
			},
			expected: "upgrade-insecure-requests",
		},
		{
			name: "mixed directives",
			setup: func(p *Policy) {
				p.Add(UpgradeInsecureRequests)
				p.Add(DefaultSrc, SourceSelf)
				p.Add(FrameAncestors, SourceNone)
			},
			expected: "default-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
		},
		{
			name: "using helpers",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, SourceSelf, Nonce("abc"), Hash("sha256", "eHl6"))
			},
			expected: "script-src 'nonce-abc' 'self' 'sha256-eHl6'",
		},
		{
			name: "cached policy with nonce injection",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, SourceSelf, SourceNonce)
			},
			preCompile: true,
			nonce:      []string{"real-nonce"},
			expected:   "script-src 'self' 'nonce-real-nonce'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := New()
			tt.setup(p)
			if tt.preCompile {
				p.Compile() // Prime the cache to ensure isCompiled is true
			}
			result := p.Compile(tt.nonce...)
			if result != tt.expected {
				t.Errorf("\nexpected: %s\ngot:      %s", tt.expected, result)
			}
		})
	}
}

func TestPolicy_Clone(t *testing.T) {
	t.Parallel()
	p := New()
	p.Add(DefaultSrc, SourceSelf)
	p.Add(ScriptSrc, SourceNonce)

	cloned := p.Clone()

	// Verify independence
	cloned.Add(ScriptSrc, "https://cloned.com")
	if len(p.directives[ScriptSrc]) != 1 {
		t.Error("Modifying clone affected original")
	}
	if len(cloned.directives[ScriptSrc]) != 2 {
		t.Error("Clone did not retain original sources")
	}
}

func TestPolicy_Strict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sources []string
		wantErr bool
	}{
		{
			name:    "valid policy",
			sources: []string{SourceSelf, "https://example.com", "*", "*.example.com", "data:", "https:"},
			wantErr: false,
		},
		{
			name:    "invalid wildcard",
			sources: []string{"invalid*"},
			wantErr: true,
		},
		{
			name:    "malformed scheme https",
			sources: []string{"https"},
			wantErr: true,
		},
		{
			name:    "malformed scheme http",
			sources: []string{"http"},
			wantErr: true,
		},
		{
			name:    "malformed scheme data",
			sources: []string{"data"},
			wantErr: true,
		},
		{
			name:    "malformed scheme wss",
			sources: []string{"wss"},
			wantErr: true,
		},
		{
			name:    "malformed scheme blob",
			sources: []string{"blob"},
			wantErr: true,
		},
		{
			name:    "malformed scheme filesystem",
			sources: []string{"filesystem"},
			wantErr: true,
		},
		{
			name:    "malformed scheme mediastream",
			sources: []string{"mediastream"},
			wantErr: true,
		},
		{
			name:    "malformed scheme ws",
			sources: []string{"ws"},
			wantErr: true,
		},
		{
			name:    "invalid characters in scheme prefix",
			sources: []string{"my_scheme:value"},
			wantErr: false,
		},
		{
			name:    "malformed custom scheme",
			sources: []string{"customscheme:value"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := New()
			p.Add(DefaultSrc, tt.sources...)

			err := p.Strict()
			if (err != nil) != tt.wantErr {
				t.Errorf("Strict() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPolicy_String(t *testing.T) {
	t.Parallel()
	p := New()
	p.Add(DefaultSrc, SourceSelf)

	// Verify fmt.Stringer implementation
	//nolint:gocritic,staticcheck // We are testing the fmt.Stringer interface
	result := fmt.Sprintf("%s", p)
	expected := "default-src 'self'"
	if result != expected {
		t.Errorf("String() = %q, want %q", result, expected)
	}
}

// TestPolicy_CacheInvalidation tests that modifications to the policy object
// correctly invalidate the internal cache of the compiled policy string. This
// includes adding a new directive, setting an existing directive, and removing
// an existing directive.
func TestPolicy_CacheInvalidation(t *testing.T) {
	t.Parallel()

	t.Run("Add invalidates cache", func(t *testing.T) {
		t.Parallel()
		p := New()
		p.Add(DefaultSrc, SourceSelf)
		p.Compile() // build cache
		if !p.isCompiled {
			t.Fatal("Policy should be compiled")
		}
		p.Add(ScriptSrc, SourceSelf) // should invalidate cache
		if p.isCompiled {
			t.Fatal("Cache was not invalidated after Add")
		}
	})

	t.Run("Set invalidates cache", func(t *testing.T) {
		t.Parallel()
		p := New()
		p.Add(DefaultSrc, SourceSelf)
		p.Compile() // build cache
		if !p.isCompiled {
			t.Fatal("Policy should be compiled")
		}
		p.Set(DefaultSrc, SourceNone) // should invalidate cache
		if p.isCompiled {
			t.Fatal("Cache was not invalidated after Set")
		}
	})

	t.Run("Remove invalidates cache", func(t *testing.T) {
		t.Parallel()
		p := New()
		p.Add(DefaultSrc, SourceSelf)
		p.Compile() // build cache
		if !p.isCompiled {
			t.Fatal("Policy should be compiled")
		}
		p.Remove(DefaultSrc) // should invalidate cache
		if p.isCompiled {
			t.Fatal("Cache was not invalidated after Remove")
		}
	})
}

// TestPolicy_Compile_NonceLogic tests the logic of the Compile method
// for nonce injection.
func TestPolicy_Compile_NonceLogic(t *testing.T) {
	t.Parallel()

	testNonceValue := "r4nd0m-v4lu3"

	tests := []struct {
		name         string
		setup        func(*Policy)
		compileNonce []string
		expected     string
	}{
		{
			name: "Policy with nonce, compiled with nonce",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, SourceSelf, SourceNonce)
			},
			compileNonce: []string{testNonceValue},
			expected:     "script-src 'self' 'nonce-r4nd0m-v4lu3'",
		},
		{
			name: "Policy with nonce, compiled with empty nonce string",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, SourceNonce)
			},
			compileNonce: []string{""},
			expected:     "script-src 'nonce-{{nonce}}'",
		},
		{
			name: "Policy with nonce only, compiled with no nonce argument",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, SourceNonce)
			},
			compileNonce: []string{},
			expected:     "script-src 'nonce-{{nonce}}'",
		},
		{
			name: "Policy with nonce and other sources, compiled with no nonce argument",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, SourceSelf, SourceNonce)
			},
			compileNonce: []string{},
			expected:     "script-src 'self' 'nonce-{{nonce}}'",
		},
		{
			name: "Policy without nonce, compiled with nonce",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, SourceSelf)
			},
			compileNonce: []string{testNonceValue},
			expected:     "script-src 'self'",
		},
		{
			name: "Policy with static and dynamic nonces",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, SourceNonce, Nonce("static-123"))
			},
			compileNonce: []string{testNonceValue},
			expected:     "script-src 'nonce-static-123' 'nonce-r4nd0m-v4lu3'",
		},
		{
			name: "Empty policy compiled with nonce",
			setup: func(p *Policy) {
			},
			compileNonce: []string{testNonceValue},
			expected:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := New()
			tt.setup(p)
			result := p.Compile(tt.compileNonce...)
			if result != tt.expected {
				t.Errorf("\nExpected: %s\nGot:      %s", tt.expected, result)
			}
		})
	}
}

// TestPolicy_LazyCompilation tests the lazy compilation of the Policy object.
// It verifies that the first call to Compile will build and cache the policy
// string, and that subsequent calls will use the cached value until the policy
// is modified. It also verifies that modifying the policy will invalidate the
// cache, and that re-compiling the policy will generate a new cached value.
func TestPolicy_LazyCompilation(t *testing.T) {
	t.Parallel()

	p := New()
	p.Add(DefaultSrc, SourceSelf)

	// First compile, should build the cache
	_ = p.Compile()
	if !p.isCompiled {
		t.Fatal("Policy should be compiled after first call")
	}
	cachedValue := p.cache

	// Use Compile again to verify cache reuse instead of direct field access
	p.cache = "test-cache-value" // Manually change cache to see if it's reused
	result := p.Compile()
	if result != "test-cache-value" {
		t.Fatal("Compile should have used the cached value")
	}

	// Modify policy, should invalidate cache
	p.Add(ScriptSrc, SourceSelf)
	if p.isCompiled {
		t.Fatal("Policy should not be compiled after modification")
	}

	// Re-compile, should build a new cache
	_ = p.Compile()
	if !p.isCompiled {
		t.Fatal("Policy should be compiled again after modification")
	}
	if p.cache == cachedValue {
		t.Fatal("Policy should have a new cached value after modification and recompilation")
	}
}

// TestPolicy_Set_ValuelessDirective verifies that the Set method of the Policy object
// correctly sets a valueless directive without any value when called with no arguments.
// It also verifies that the compiled policy string is updated correctly.
func TestPolicy_Set_ValuelessDirective(t *testing.T) {
	t.Parallel()

	p := New()
	p.Add(Sandbox, "allow-forms") // Start with a value
	p.Set(Sandbox)                // Set with no arguments

	if _, ok := p.directives[Sandbox]; !ok {
		t.Fatalf("Valueless directive %q should have been set", Sandbox)
	}

	expected := "sandbox"
	if got := p.Compile(); got != expected {
		t.Errorf("Expected compiled policy to be %q, got %q", expected, got)
	}
}

// TestPolicy_EdgeCases tests the edge cases of the Policy object.
// It verifies that adding an empty directive does not modify the policy,
// and that removing a non-existent directive does not invalidate the cache.
func TestPolicy_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("Add with empty directive", func(t *testing.T) {
		t.Parallel()
		p := New()
		p.Add("   ", SourceSelf)
		if len(p.directives) != 0 {
			t.Errorf("Policy should have 0 directives, but has %d", len(p.directives))
		}
	})

	t.Run("Remove non-existent directive", func(t *testing.T) {
		t.Parallel()
		p := New()
		p.Add(DefaultSrc, SourceSelf)
		p.Compile() // Build cache
		if !p.isCompiled {
			t.Fatal("Policy should be compiled")
		}

		p.Remove(ScriptSrc) // Try to remove a directive that is not present

		if len(p.directives) != 1 {
			t.Errorf("Policy should still have 1 directive, but has %d", len(p.directives))
		}
		if !p.isCompiled {
			t.Error("Cache should not be invalidated when removing a non-existent directive")
		}
	})
}

// TestPolicy_Concurrency tests the thread safety of the Policy object.
// It verifies that multiple concurrent writes and reads will not cause race
// conditions or data corruption.
func TestPolicy_Concurrency(t *testing.T) {
	t.Parallel()

	p := New()
	var wg sync.WaitGroup
	numRoutines := 100

	// Concurrent writes (Add)
	wg.Add(numRoutines)
	for i := range numRoutines {
		go func(i int) {
			defer wg.Done()
			p.Add(ScriptSrc, fmt.Sprintf("https://host-%d.com", i))
		}(i)
	}
	wg.Wait()

	// Concurrent Set and Remove
	wg.Add(numRoutines)
	for i := range numRoutines {
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				p.Set(StyleSrc, fmt.Sprintf("https://style-%d.com", i))
			} else {
				p.Remove(FontSrc)
			}
		}(i)
	}
	wg.Wait()

	// Concurrent reads
	wg.Add(numRoutines)
	for i := range numRoutines {
		go func(i int) {
			defer wg.Done()
			nonce := fmt.Sprintf("nonce-%d", i)
			_ = p.Compile(nonce)
		}(i)
	}
	wg.Wait()
}

// --- Benchmarks ---

// BenchmarkPolicy_Compile benchmarks the Compile method of the Policy object.
// It tests the performance of compiling a policy with a single nonce value.
// The benchmark is run with the allocations reporter enabled to provide insight
// into the performance cost of the cache.
func BenchmarkPolicy_Compile(b *testing.B) {
	p := New()
	p.Add(DefaultSrc, SourceSelf)
	p.Add(ScriptSrc, SourceSelf, SourceNonce, "https://cdn.example.com", "https://apis.example.com")
	p.Add(StyleSrc, SourceSelf, "https://fonts.example.com")
	p.Add(FontSrc, "https://fonts.example.com")
	p.Add(ImgSrc, SourceSelf, SchemeData)
	p.Add(FrameAncestors, SourceNone)
	p.Add(UpgradeInsecureRequests)

	// The first compile is expensive as it builds the cache.
	p.Compile("first-nonce")

	nonce := "B3nh1LfcP7/T8aR4y1a+5A=="

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = p.Compile(nonce)
	}
}
