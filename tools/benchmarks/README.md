# tools/benchmarks

Standalone benchmark programs for Qeet ID performance profiling.

These are distinct from `go test -bench` micro-benchmarks — they test end-to-end
throughput and latency of critical paths with realistic workloads and full DB/network.

## Run

```bash
# JWT signing throughput
go run ./tools/benchmarks/jwt_signing

# Password hashing throughput (bcrypt cost calibration)
go run ./tools/benchmarks/password_hashing

# Audit log write throughput
go run ./tools/benchmarks/audit_write -- -n 10000

# DB connection pool under concurrency
go run ./tools/benchmarks/db_pool -- -conns 50 -duration 30s
```

## Adding a benchmark

Each benchmark is a standalone `main` package under its own subdirectory:

```
tools/benchmarks/
├── jwt_signing/main.go
├── password_hashing/main.go
├── audit_write/main.go
└── db_pool/main.go
```

Benchmarks read connection config from the same `.env` as the server.
Run `make db-up migrate-up` before running DB-dependent benchmarks.
