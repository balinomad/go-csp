[![GoDoc](https://pkg.go.dev/badge/github.com/balinomad/go-csp?status.svg)](https://pkg.go.dev/github.com/balinomad/go-csp?tab=doc)
[![GoMod](https://img.shields.io/github/go-mod/go-version/balinomad/go-csp)](https://github.com/balinomad/go-csp)
[![Size](https://img.shields.io/github/languages/code-size/balinomad/go-csp)](https://github.com/balinomad/go-csp)
[![License](https://img.shields.io/github/license/balinomad/go-csp)](./LICENSE)
[![Go](https://github.com/balinomad/go-csp/actions/workflows/go.yml/badge.svg)](https://github.com/balinomad/go-csp/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/balinomad/go-csp)](https://goreportcard.com/report/github.com/balinomad/go-csp)
[![codecov](https://codecov.io/github/balinomad/go-csp/graph/badge.svg?token=L1K68IIN51)](https://codecov.io/github/balinomad/go-csp)

# csp

*A secure, fluent, and thread-safe builder for Content Security Policies (CSP) in Go.*

This package provides a comprehensive and easy-to-use API for dynamically creating and managing Content Security Policies. It's designed to be efficient, correct, and safe for concurrent use in high-performance web applications and middleware.

## ✨ Features

- **Fluent API:** An expressive and easy-to-use interface for building complex policies.
- **Thread-Safe:** Designed from the ground up for safe concurrent access and modification.
- **Correct & Consistent:** Automatically sorts directives and sources to produce a consistent, canonical header string every time.
- **Dynamic Nonce Injection:** Simple per-request nonce injection for the highest level of script security.
- **Comprehensive:** Includes constants for all standard CSP directives and keyword sources to prevent typos.
- **Helper Functions:** Simple helpers for generating correctly formatted `nonce` and `hash` sources.
- **Zero Dependencies:** A lightweight package that integrates into any project without external dependencies.
- **High Performance:** Uses efficient string building and lazy compilation to minimize allocations and CPU overhead on repeated calls.

## 📌 Installation

```bash
go get github.com/balinomad/go-csp@latest
```

## 🚀 Usage

### Basic Setup

Creating a policy is simple. Start with `New()` and use the `Add` or `Set` methods to build your policy.

```go
import "github.com/balinomad/go-csp"

// Create a new, empty policy
p := csp.New()

// Add a simple directive
// -> "default-src 'self'"
p.Add(csp.DefaultSrc, csp.SourceSelf)

// The Compile method generates the final header string
header := p.Compile()
```

### Building a Complex Policy

Easily build a robust policy by chaining methods. The package handles deduplication and sorting automatically.

```go
p := csp.New()

// Set a default policy
p.Set(csp.DefaultSrc, csp.SourceSelf)

// Add sources for scripts and styles
p.Add(csp.ScriptSrc, csp.SourceSelf, "[https://cdn.example.com](https://cdn.example.com)", "[https://apis.google.com](https://apis.google.com)")
p.Add(csp.StyleSrc, csp.SourceSelf, "[https://fonts.googleapis.com](https://fonts.googleapis.com)")

// Add a valueless directive
p.Add(csp.UpgradeInsecureRequests)

// Compile the policy
// -> "default-src 'self'; script-src 'self' [https://apis.google.com](https://apis.google.com) [https://cdn.example.com](https://cdn.example.com); style-src 'self' [https://fonts.googleapis.com](https://fonts.googleapis.com); upgrade-insecure-requests"
header := p.Compile()
```
### Dynamic Nonces

For maximum security, a unique nonce should be generated for each request. This library makes it easy to inject a nonce at compile time.

First, add the `SourceNonce` placeholder to your policy during setup.

```go
// Do this once during application startup
p := csp.New()
p.Add(csp.ScriptSrc, csp.SourceSelf, csp.SourceNonce)
```

Then, in your HTTP handler, generate a random value and pass it to `Compile`.

```go
import (
    "crypto/rand"
    "encoding/base64"
    "io"
    "net/http"
)

// Assume 'p' is your shared csp.Policy instance from setup.
func MyHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Generate a new random nonce for each request.
    nonceBytes := make([]byte, 16)
    io.ReadFull(rand.Reader, nonceBytes)
    nonce := base64.StdEncoding.EncodeToString(nonceBytes)

    // 2. Compile the policy, injecting the per-request nonce.
    header := p.Compile(nonce)
    w.Header().Set("Content-Security-Policy", header)

    // 3. Use the same nonce in your HTML script tags.
    // ... render your template with <script nonce="{{.CSPNonce}}">
}
```

### Modifying a Policy

You can easily modify or remove directives from an existing policy.

```go
// Start with an existing policy
p := csp.New()
p.Add(csp.DefaultSrc, csp.SourceSelf)
p.Add(csp.ScriptSrc, "[https://a.com](https://a.com)")

// Overwrite the script-src directive completely
p.Set(csp.ScriptSrc, csp.SourceSelf, "[https://b.com](https://b.com)")

// Remove the default-src directive
p.Remove(csp.DefaultSrc)

// -> "script-src 'self' [https://b.com](https://b.com)"
header := p.Compile()
```

## 📘 API Reference

### Constructor

| Function | Description |
|----------|-------------|
| `New()`  | Creates a new, empty, thread-safe `Policy`. |

### Policy Methods

| Method | Description |
|--------|-------------|
| `Add(directive, sources...)` | Appends one or more sources to a directive. Automatically handles duplicates. |
| `Set(directive, sources...)` | Replaces all sources for a directive. Removes the directive if no sources are provided. |
| `Remove(directive)` | Removes a directive entirely from the policy. |
| `Compile(nonce ...string)` | Generates the final, sorted CSP header string. If a nonce is passed, it replaces the `SourceNonce` placeholder. |

### Helpers

| Function | Description |
|----------|-------------|
| `Nonce(value)` | Returns a correctly formatted static nonce source (e.g., `'nonce-value'`). |
| `Hash(algo, value)` | Returns a correctly formatted hash source (e.g., `'sha256-value'`). |

### Constants

The package provides string constants for all standard directives (e.g., `csp.DefaultSrc`, `csp.ScriptSrc`) and common sources (e.g., `csp.SourceSelf`, `csp.SourceNone`, `csp.SchemeData`). Using these constants is recommended to avoid typos and ensure correctness.

## ⚡ Concurrency

The `Policy` object is thread-safe. You can safely call its methods (`Add`, `Set`, `Remove`, `Compile`) from multiple goroutines simultaneously. This makes it ideal for use in HTTP middleware or other concurrent contexts where a single policy object might be shared and modified. All access is synchronized internally with a `sync.RWMutex`.

## ⚖️ License

This package is open-source and available under the [MIT License](LICENSE).
