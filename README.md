[![Go](https://github.com/balinomad/go-csp/actions/workflows/go.yml/badge.svg)](https://github.com/balinomad/go-csp/actions/workflows/go.yml)

# go-csp

*A secure, fluent, and thread-safe builder for Content Security Policies (CSP) in Go.*

This package provides a comprehensive and easy-to-use API for dynamically creating and managing Content Security Policies. It's designed to be efficient, correct, and safe for concurrent use in high-performance web applications and middleware.

## ✨ Features

- **Fluent API:** An expressive and easy-to-use interface for building complex policies.
- **Thread-Safe:** Designed from the ground up for safe concurrent access and modification.
- **Correct & Consistent:** Automatically sorts directives and sources to produce a consistent, canonical header string every time.
- **Comprehensive:** Includes constants for all standard CSP directives and keyword sources to prevent typos.
- **Helper Functions:** Simple helpers for generating correctly formatted `nonce` and `hash` sources.
- **Zero Dependencies:** A lightweight package that integrates into any project without external dependencies.
- **High Performance:** Uses efficient string building and map lookups to minimize allocations and CPU overhead.

## 🚀 Usage

### Basic Setup

Creating a policy is simple. Start with `New()` and use the `Add` method to include directives.

```go
import "[github.com/balinomad/go-csp](https://github.com/balinomad/go-csp)"

// Create a new, empty policy
p := csp.New()

// Add a simple directive
// -> "default-src 'self'"
p.Add(csp.DefaultSrc, csp.SourceSelf)

// The Compile method generates the final header string
header := p.Compile()
```

### Building a Complex Policy

Easily build a robust policy by adding multiple directives and sources. The package handles deduplication and sorting automatically.

```go
p := csp.New()

// Set a default policy
p.Set(csp.DefaultSrc, csp.SourceSelf)

// Add sources for scripts
p.Add(csp.ScriptSrc, csp.SourceSelf, "[https://cdn.example.com](https://cdn.example.com)", "[https://apis.google.com](https://apis.google.com)")

// Add sources for styles
p.Add(csp.StyleSrc, csp.SourceSelf, "[https://fonts.googleapis.com](https://fonts.googleapis.com)")

// Add a valueless directive
p.Add(csp.UpgradeInsecureRequests)

// Compile the policy
// -> "default-src 'self'; script-src 'self' [https://apis.google.com](https://apis.google.com) [https://cdn.example.com](https://cdn.example.com); style-src 'self' [https://fonts.googleapis.com](https://fonts.googleapis.com); upgrade-insecure-requests"
header := p.Compile()
```

### Using Nonce and Hash Helpers

The `Nonce` and `Hash` helpers ensure your sources are formatted correctly according to the CSP specification.

```go
p := csp.New()

// Add a nonce and a hash to the script-src directive
p.Add(
    csp.ScriptSrc,
    csp.SourceSelf,
    csp.Nonce("random-nonce-value"),
    csp.Hash("sha256", "some-base64-encoded-hash"),
)

// -> "script-src 'self' 'nonce-random-nonce-value' 'sha256-some-base64-encoded-hash'"
header := p.Compile()
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

## 📌 Installation

```bash
go get github.com/balinomad/go-csp@latest
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
| `Compile()` | Generates the final, sorted CSP header string. |

### Helpers

| Function | Description |
|----------|-------------|
| `Nonce(value)` | Returns a correctly formatted nonce source (e.g., `'nonce-value'`). |
| `Hash(algo, value)` | Returns a correctly formatted hash source (e.g., `'sha256-value'`). |

### Constants

The package provides string constants for all standard directives (e.g., `csp.DefaultSrc`, `csp.ScriptSrc`) and common sources (e.g., `csp.SourceSelf`, `csp.SourceNone`, `csp.SchemeData`). Using these constants is recommended to avoid typos and ensure correctness.

## ⚡ Concurrency

The `Policy` object is thread-safe. You can safely call its methods (`Add`, `Set`, `Remove`, `Compile`) from multiple goroutines simultaneously. This makes it ideal for use in HTTP middleware or other concurrent contexts where a single policy object might be shared and modified. All access is synchronized internally with a `sync.RWMutex`.

## ⚖️ License

This package is open-source and available under the [MIT License](LICENSE).
