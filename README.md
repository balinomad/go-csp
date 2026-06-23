[![GoDoc](https://pkg.go.dev/badge/github.com/balinomad/go-csp?status.svg)](https://pkg.go.dev/github.com/balinomad/go-csp?tab=doc)
[![GoMod](https://img.shields.io/github/go-mod/go-version/balinomad/go-csp)](https://github.com/balinomad/go-csp)
[![Size](https://img.shields.io/github/languages/code-size/balinomad/go-csp)](https://github.com/balinomad/go-csp)
[![License](https://img.shields.io/github/license/balinomad/go-csp)](./LICENSE)
[![Go](https://github.com/balinomad/go-csp/actions/workflows/go.yml/badge.svg)](https://github.com/balinomad/go-csp/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/balinomad/go-csp)](https://goreportcard.com/report/github.com/balinomad/go-csp)
[![codecov](https://codecov.io/github/balinomad/go-csp/graph/badge.svg?token=L1K68IIN51)](https://codecov.io/github/balinomad/go-csp)

# csp

_A secure, fluent, and thread-safe builder for Content Security Policies (CSP) in Go._

This package provides a comprehensive API for dynamically creating and managing Content Security Policies. It is designed to be correct, allocation-efficient, and safe for concurrent use in high-throughput web servers and middleware.

## Features

- **Fluent API:** Expressive interface for building and mutating complex policies.
- **Thread-Safe:** Designed for concurrent access using `sync.RWMutex`.
- **Canonical Output:** Automatically deduplicates and sorts directives and sources to produce consistent header strings.
- **Dynamic Nonce Injection:** Supports per-request nonce injection coupled with lazy string compilation to minimize allocation overhead.
- **Strict Validation:** Validates schemes, wildcards, and cryptographic hash formats to prevent malformed headers.
- **Zero Dependencies:** A lightweight, standard-library-only package.

## Installation

```bash
go get github.com/balinomad/go-csp@latest
```

## Usage

### Middleware Integration (net/http)

`go-csp` is designed to be initialized once at application startup and shared safely across concurrent HTTP handlers.

```go
package main

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"

	"github.com/balinomad/go-csp"
)

// CSPMiddleware wraps an HTTP handler, injecting a secure, per-request CSP header.
func CSPMiddleware(policy *csp.Policy) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Generate a cryptographically secure random nonce for the request
			nonceBytes := make([]byte, 16)
			if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			nonce := base64.StdEncoding.EncodeToString(nonceBytes)

			// Compile the policy, injecting the generated nonce, and set the header
			w.Header().Set("Content-Security-Policy", policy.Compile(nonce))

			// Typically, you would also inject this nonce into the request context
			// here so it can be accessed by your HTML template rendering engine.

			next.ServeHTTP(w, r)
		})
	}
}

func main() {
	// Initialize the global policy
	p := csp.New()
	p.Add(csp.DefaultSrc, csp.SourceSelf)
	p.Add(csp.ScriptSrc, csp.SourceSelf, csp.SourceNonce)
	p.Add(csp.StyleSrc, csp.SourceSelf, "https://fonts.googleapis.com")
	p.Add(csp.UpgradeInsecureRequests)

	// Validate the policy configuration before starting the server
	if err := p.Strict(); err != nil {
		panic("invalid CSP configuration: " + err.Error())
	}

	// Set up routing
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<h1>Secure Page</h1>"))
	})

	// Wrap the multiplexer with the CSP middleware
	handler := CSPMiddleware(p)(mux)

	http.ListenAndServe(":8080", handler)
}
```

### Third-Party Router Integration

Because `go-csp` is framework-agnostic, it integrates seamlessly with popular Go web frameworks.

#### Chi (or any standard net/http router)

Chi utilizes standard `net/http` middleware signatures, so the standard `CSPMiddleware` defined above works without modification.

```go
r := chi.NewRouter()
r.Use(CSPMiddleware(p))
r.Get("/", myHandler)
```

#### Gin

Gin uses a custom signature (`gin.HandlerFunc`). Wrap the policy compilation inside Gin's context.

```go
import (
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/balinomad/go-csp"
	"github.com/gin-gonic/gin"
)

func CSPGinMiddleware(policy *csp.Policy) gin.HandlerFunc {
	return func(c *gin.Context) {
		nonceBytes := make([]byte, 16)
		io.ReadFull(rand.Reader, nonceBytes)
		nonce := base64.StdEncoding.EncodeToString(nonceBytes)

		c.Header("Content-Security-Policy", policy.Compile(nonce))
		c.Set("CSPNonce", nonce) // Pass to context for template rendering

		c.Next()
	}
}

// Usage:
// r := gin.Default()
// r.Use(CSPGinMiddleware(p))
```

### Echo

Integration with Echo requires the `echo.MiddlewareFunc` signature.

```go
import (
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/balinomad/go-csp"
	"github.com/labstack/echo/v4"
)

func CSPEchoMiddleware(policy *csp.Policy) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			nonceBytes := make([]byte, 16)
			io.ReadFull(rand.Reader, nonceBytes)
			nonce := base64.StdEncoding.EncodeToString(nonceBytes)

			c.Response().Header().Set("Content-Security-Policy", policy.Compile(nonce))
			c.Set("CSPNonce", nonce) // Pass to context for template rendering

			return next(c)
		}
	}
}

// Usage:
// e := echo.New()
// e.Use(CSPEchoMiddleware(p))
```

### Modifying Policies Dynamically

The `Policy` object supports real-time modification or cloning for specific routes.

```go
// Overwrite a directive completely
p.Set(csp.ScriptSrc, csp.SourceSelf, "https://analytics.example.com")

// Remove a directive entirely
p.Remove(csp.DefaultSrc)

// Create an isolated copy for a specific handler that requires altered rules
clonedPolicy := p.Clone()
clonedPolicy.Add(csp.FrameAncestors, "https://trusted-partner.com")
```

## API Reference

### Constructor

| Function | Description                                 |
| -------- | ------------------------------------------- |
| `New()`  | Creates a new, empty, thread-safe `Policy`. |

### Policy Methods

| Method                       | Description                                                                                                                                                                |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Add(directive, sources...)` | Appends one or more sources to a directive. Automatically handles duplicates.                                                                                              |
| `Set(directive, sources...)` | Replaces all sources for a directive. Removes the directive if no sources are provided.                                                                                    |
| `Remove(directive)`          | Removes a directive entirely from the policy.                                                                                                                              |
| `Compile(nonce ...string)`   | Generates the final CSP header string. If a nonce is passed, it replaces the `SourceNonce` placeholder. Subsequent calls use a cached string until the policy is modified. |

### Helpers

| Function                 | Description                                                                        |
| ------------------------ | ---------------------------------------------------------------------------------- |
| `Nonce(value)`           | Returns a correctly formatted static nonce source (e.g., `'nonce-value'`).         |
| `ParseHash(algo, value)` | Validates and formats a base64 cryptographic hash source (e.g., `'sha256-value'`). |

### Constants and Extensibility

The package provides string constants for standard W3C standard directives (e.g., `csp.DefaultSrc`, `csp.ScriptSrc`) and keyword sources (e.g., `csp.SourceSelf`, `csp.SourceNone`, `csp.SchemeData`). Utilizing these constants is recommended to enforce correctness and prevent typos.

In cases where experimental or custom directives are required, raw strings may be passed directly to the `Add` and `Set` methods:

```go
p.Add("trusted-types", "my-policy-name")
```

This ensures compatibility with evolving standards without requiring updates to the library.

## Concurrency

The `Policy` object is strictly thread-safe. All mutations (`Add`, `Set`, `Remove`) and reads (`Compile`, `Strict`, `Clone`) are synchronized internally via `sync.RWMutex`. It is safe to share a single `Policy` instance across an application's entire middleware stack.

## Testing

Run tests with race condition detection enabled:

```bash
go test -race ./...
```

Run benchmarks (includes memory allocation reporting):

```bash
go test -bench=. -benchmem
```

## License

This package is open-source and available under the [MIT License](LICENSE).
