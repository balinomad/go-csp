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

func TestPolicy_Concurrency(t *testing.T) {
	p := New()
	var wg sync.WaitGroup
	numRoutines := 100

	// Concurrent writes
	for i := 0; i < numRoutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p.Add(ScriptSrc, fmt.Sprintf("https://host-%d.com", i))
			p.Add(DefaultSrc, SourceSelf)
		}(i)
	}
	wg.Wait()

	// Concurrent reads (via Compile)
	for i := 0; i < numRoutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.Compile()
		}()
	}
	wg.Wait()

	// Check final state
	compiled := p.Compile()
	if !strings.HasPrefix(compiled, "default-src 'self';") {
		t.Error("Compiled output missing default-src")
	}
	if len(p.directives[ScriptSrc]) != numRoutines {
		t.Errorf("Expected %d script sources, got %d", numRoutines, len(p.directives[ScriptSrc]))
	}
}

func BenchmarkPolicy_Compile(b *testing.B) {
	p := New()
	p.Add(DefaultSrc, SourceSelf)
	p.Add(ScriptSrc, SourceSelf, "https://cdn.example.com", "https://apis.example.com")
	p.Add(StyleSrc, SourceSelf, "https://fonts.example.com")
	p.Add(FontSrc, "https://fonts.example.com")
	p.Add(ImgSrc, SourceSelf, SchemeData)
	p.Add(FrameAncestors, SourceNone)
	p.Add(UpgradeInsecureRequests)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = p.Compile()
	}
}
