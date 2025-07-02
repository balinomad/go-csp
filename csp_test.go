package csp

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestPolicy_New(t *testing.T) {
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

func TestPolicy_Add(t *testing.T) {
	t.Run("Add to new directive", func(t *testing.T) {
		p := New()
		p.Add(DefaultSrc, SourceSelf)
		if _, ok := p.directives[DefaultSrc]; !ok {
			t.Fatalf("Directive %q was not added", DefaultSrc)
		}
		if _, ok := p.directives[DefaultSrc][SourceSelf]; !ok {
			t.Errorf("Source %q was not added to directive %q", SourceSelf, DefaultSrc)
		}
	})

	t.Run("Add to existing directive", func(t *testing.T) {
		p := New()
		p.Add(DefaultSrc, SourceSelf)
		p.Add(DefaultSrc, "https://example.com")
		if len(p.directives[DefaultSrc]) != 2 {
			t.Errorf("Expected 2 sources, got %d", len(p.directives[DefaultSrc]))
		}
	})

	t.Run("Add duplicate source", func(t *testing.T) {
		p := New()
		p.Add(DefaultSrc, SourceSelf)
		p.Add(DefaultSrc, SourceSelf)
		if len(p.directives[DefaultSrc]) != 1 {
			t.Errorf("Expected 1 source after adding duplicate, got %d", len(p.directives[DefaultSrc]))
		}
	})

	t.Run("Add with only empty sources", func(t *testing.T) {
		p := New()
		p.Add(DefaultSrc, "   ", "")
		if len(p.directives) != 0 {
			t.Errorf("Policy should be empty after adding only blank sources, but has %d directives", len(p.directives))
		}
	})

	t.Run("Add with mixed valid and empty sources", func(t *testing.T) {
		p := New()
		p.Add(DefaultSrc, " ", SourceSelf, "")
		if len(p.directives[DefaultSrc]) != 1 {
			t.Errorf("Expected 1 source, got %d", len(p.directives[DefaultSrc]))
		}
		if _, ok := p.directives[DefaultSrc][SourceSelf]; !ok {
			t.Error("Valid source was not added")
		}
	})

	t.Run("Add valueless directive", func(t *testing.T) {
		p := New()
		p.Add(BlockAllMixedContent)
		if _, ok := p.directives[BlockAllMixedContent]; !ok {
			t.Fatalf("Directive %q was not added", BlockAllMixedContent)
		}
		if len(p.directives[BlockAllMixedContent]) != 0 {
			t.Errorf("Valueless directive should have 0 sources, got %d", len(p.directives[BlockAllMixedContent]))
		}
	})
}

func TestPolicy_Set(t *testing.T) {
	t.Run("Set with valid sources", func(t *testing.T) {
		p := New()
		p.Add(DefaultSrc, SourceSelf)
		p.Set(DefaultSrc, SourceNone)

		if len(p.directives[DefaultSrc]) != 1 {
			t.Fatalf("Expected 1 source after Set, got %d", len(p.directives[DefaultSrc]))
		}
		if _, ok := p.directives[DefaultSrc][SourceNone]; !ok {
			t.Error("Set did not correctly replace the sources")
		}
	})

	t.Run("Set with only empty sources should remove directive", func(t *testing.T) {
		p := New()
		p.Add(DefaultSrc, SourceSelf)
		p.Set(DefaultSrc, " ", "   ")

		if _, ok := p.directives[DefaultSrc]; ok {
			t.Errorf("Directive %q should have been removed after Set with empty sources", DefaultSrc)
		}
	})

	t.Run("Set with empty slice should remove directive", func(t *testing.T) {
		p := New()
		p.Add(DefaultSrc, SourceSelf)
		p.Set(DefaultSrc) // Set with no arguments

		if _, ok := p.directives[DefaultSrc]; ok {
			t.Fatalf("Directive %q should have been removed", DefaultSrc)
		}
		if len(p.directives) != 0 {
			t.Errorf("Expected 0 directives after Set with no arguments, got %d", len(p.directives))
		}
		if p.Compile() != "" {
			t.Errorf("Expected compiled policy to be empty, got %q", p.Compile())
		}
	})
}

func TestPolicy_Remove(t *testing.T) {
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

func TestPolicy_Compile(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(*Policy)
		expected string
	}{
		{
			name:     "Empty policy",
			setup:    func(p *Policy) {},
			expected: "",
		},
		{
			name: "Single directive",
			setup: func(p *Policy) {
				p.Add(DefaultSrc, SourceSelf)
			},
			expected: "default-src 'self'",
		},
		{
			name: "Multiple sources sorted",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, "https://b.com", "https://a.com", SourceSelf)
			},
			expected: "script-src 'self' https://a.com https://b.com",
		},
		{
			name: "Multiple directives sorted",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, SourceSelf)
				p.Add(DefaultSrc, SourceNone)
			},
			expected: "default-src 'none'; script-src 'self'",
		},
		{
			name: "Valueless directive",
			setup: func(p *Policy) {
				p.Add(UpgradeInsecureRequests)
			},
			expected: "upgrade-insecure-requests",
		},
		{
			name: "Mixed directives",
			setup: func(p *Policy) {
				p.Add(UpgradeInsecureRequests)
				p.Add(DefaultSrc, SourceSelf)
				p.Add(FrameAncestors, SourceNone)
			},
			expected: "default-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
		},
		{
			name: "Using helpers",
			setup: func(p *Policy) {
				p.Add(ScriptSrc, SourceSelf, Nonce("abc"), Hash("sha256", "xyz"))
			},
			expected: "script-src 'nonce-abc' 'self' 'sha256-xyz'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := New()
			tc.setup(p)
			result := p.Compile()
			if result != tc.expected {
				t.Errorf("\nExpected: %s\nGot:      %s", tc.expected, result)
			}
		})
	}
}

func TestPolicy_CacheInvalidation(t *testing.T) {
	t.Run("Add invalidates cache", func(t *testing.T) {
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

func TestPolicy_Compile_NonceLogic(t *testing.T) {
	testNonceValue := "r4nd0m-v4lu3"

	testCases := []struct {
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

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := New()
			tc.setup(p)
			result := p.Compile(tc.compileNonce...)
			if result != tc.expected {
				t.Errorf("\nExpected: %s\nGot:      %s", tc.expected, result)
			}
		})
	}
}

func TestPolicy_LazyCompilation(t *testing.T) {
	p := New()
	p.Add(DefaultSrc, SourceSelf)

	// First compile, should build the cache
	_ = p.Compile()
	if !p.isCompiled {
		t.Fatal("Policy should be compiled after first call")
	}
	cachedValue := p.cache

	// Second compile, should use the cache
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

func TestPolicy_Concurrency(t *testing.T) {
	p := New()
	var wg sync.WaitGroup
	numRoutines := 100

	// Concurrent writes
	wg.Add(numRoutines)
	for i := 0; i < numRoutines; i++ {
		go func(i int) {
			defer wg.Done()
			p.Add(ScriptSrc, fmt.Sprintf("https://host-%d.com", i))
		}(i)
	}
	wg.Wait()

	// Add a directive that needs a nonce
	p.Add(DefaultSrc, SourceNonce)

	// Concurrent reads (via Compile)
	wg.Add(numRoutines)
	for i := 0; i < numRoutines; i++ {
		go func(i int) {
			defer wg.Done()
			nonce := fmt.Sprintf("nonce-%d", i)
			header := p.Compile(nonce)
			if !strings.Contains(header, nonce) {
				t.Errorf("Compiled header does not contain the correct nonce. Got: %s", header)
			}
		}(i)
	}
	wg.Wait()

	// Check final state
	if len(p.directives[ScriptSrc]) != numRoutines {
		t.Errorf("Expected %d script sources, got %d", numRoutines, len(p.directives[ScriptSrc]))
	}
	if _, ok := p.directives[DefaultSrc][SourceNonce]; !ok {
		t.Error("Expected to find SourceNonce in default-src")
	}
}

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

	for i := 0; i < b.N; i++ {
		_ = p.Compile(nonce)
	}
}

// Add these new test functions to csp_test.go

func TestHelpers(t *testing.T) {
	t.Run("Nonce", func(t *testing.T) {
		testCases := []struct {
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

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if got := Nonce(tc.input); got != tc.expected {
					t.Errorf("Nonce(%q) = %q, want %q", tc.input, got, tc.expected)
				}
			})
		}
	})

	t.Run("Hash", func(t *testing.T) {
		testCases := []struct {
			name     string
			algo     string
			value    string
			expected string
		}{
			{"Simple hash", "sha256", "xyz", "'sha256-xyz'"},
			{"With spaces", "sha384", "  xyz  ", "'sha384-xyz'"},
			{"Already quoted", "sha256", "'sha256-abc'", "'sha256-abc'"},
			{"Already quoted with spaces", "sha512", "  'sha512-abc'  ", "'sha512-abc'"},
			// Tests that the function correctly re-formats a value that looks like a hash of a different algo
			{"Idempotent check mismatch", "sha256", "'sha384-abc'", "'sha256-abc'"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if got := Hash(tc.algo, tc.value); got != tc.expected {
					t.Errorf("Hash(%q, %q) = %q, want %q", tc.algo, tc.value, got, tc.expected)
				}
			})
		}
	})
}

func TestPolicy_Set_ValuelessDirective(t *testing.T) {
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

func TestPolicy_EdgeCases(t *testing.T) {
	t.Run("Add with empty directive", func(t *testing.T) {
		p := New()
		p.Add("   ", SourceSelf)
		if len(p.directives) != 0 {
			t.Errorf("Policy should have 0 directives, but has %d", len(p.directives))
		}
	})

	t.Run("Remove non-existent directive", func(t *testing.T) {
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
