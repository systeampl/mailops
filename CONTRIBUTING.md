# Contributing

Thanks for helping improve `mailops` and the SysTeam Ops Tools ecosystem.

Open an issue before a large behavioral or machine-output change. Keep changes
focused, preserve stable JSON/YAML field names, and document user-facing
changes in `CHANGELOG.md`.

Before submitting a pull request, run:

```bash
go fmt ./...
go mod verify
go test -race -shuffle=on -count=1 ./...
go vet ./...
go build -trimpath -buildvcs=false ./...
```

Tests should be deterministic and should not require public network access.
Report security issues privately as described in `SECURITY.md`.
