# Contributing

## Requirements

- Go 1.26 or newer.
- Optional: [Task](https://taskfile.dev) for the local pipeline.

## Local checks

`task check` runs lint, race tests, vulnerability scan, and the
linux/arm64 build. Without Task, run the same commands:

```sh
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run --timeout=4m
CGO_ENABLED=1 go test -race -count=1 -shuffle=on ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /dev/null ./...
```

## Pull requests

- Keep changes focused, one concern per pull request.
- Add or update tests for behaviour changes.
- Update `CHANGELOG.md` under `Unreleased` for user-visible changes.
- Ensure `task check` passes. CI must be green before merge.

## Security

Do not report vulnerabilities in issues or pull requests. Follow
[SECURITY.md](SECURITY.md).
