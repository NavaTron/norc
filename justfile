# NavaTron NORC - Justfile for build automation
# Run `just --list` to see all available commands

set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]

# List all available commands
default:
    @just --list

# Run all CI checks (used by CI and for local verification)
ci: fmt lint test audit deny fuzz-smoke

# Build all packages in release mode
build:
    cargo build --release --all-features

# Build all packages in debug mode  
build-dev:
    cargo build --all-features

# Run all tests
test:
    cargo test --all-features --workspace

# Run tests with coverage
test-coverage:
    cargo llvm-cov --all-features --workspace --html

# Format all code
fmt:
    cargo fmt --all --check

# Fix formatting
fmt-fix:
    cargo fmt --all

# Run clippy lints
lint:
    cargo clippy --all-targets --all-features --workspace -- -D warnings

# Fix clippy lints where possible
lint-fix:
    cargo clippy --all-targets --all-features --workspace --fix --allow-dirty

# Check for security vulnerabilities
audit:
    cargo audit

# Check dependency licenses and supply chain
deny:
    cargo deny check

# Run all benchmarks
bench:
    cargo bench --workspace

# Quick smoke test of fuzzing targets
fuzz-smoke:
    @echo "Running fuzz smoke tests..."
    # Run each fuzzer for 10 seconds to ensure they compile and start
    @if (Test-Path "fuzz") { \
        Get-ChildItem fuzz/fuzz_targets/*.rs | ForEach-Object { \
            $target = $_.BaseName; \
            Write-Host "Testing fuzz target: $target"; \
            cargo fuzz run $target -- -max_total_time=10 \
        } \
    }

# Run specific fuzz target for longer period
fuzz target time="300":
    cargo fuzz run {{target}} -- -max_total_time={{time}}

# Clean all build artifacts
clean:
    cargo clean

# Install development dependencies
install-dev-deps:
    @echo "Installing development dependencies..."
    cargo install cargo-audit
    cargo install cargo-deny
    cargo install cargo-llvm-cov
    cargo install cargo-fuzz
    rustup component add llvm-tools-preview

# Generate documentation
docs:
    cargo doc --all-features --no-deps --open

# Check for unused dependencies
check-unused:
    cargo machete

# Run the server in development mode
run-server *args:
    cargo run --bin navatron-server -- {{args}}

# Run the client in development mode  
run-client *args:
    cargo run --bin navatron-client -- {{args}}

# Generate test certificates for development
gen-test-certs:
    @echo "Generating test certificates..."
    @if (-not (Test-Path "certs")) { New-Item -ItemType Directory -Name "certs" }
    # Generate CA private key
    openssl genrsa -out certs/ca-key.pem 4096
    # Generate CA certificate
    openssl req -new -x509 -sha256 -key certs/ca-key.pem -out certs/ca-cert.pem -days 365 -subj "/C=US/ST=CA/L=Test/O=NavaTron/CN=Test CA"
    # Generate server private key
    openssl genrsa -out certs/server-key.pem 4096
    # Generate server certificate signing request
    openssl req -new -key certs/server-key.pem -out certs/server.csr -subj "/C=US/ST=CA/L=Test/O=NavaTron/CN=localhost"
    # Generate server certificate
    openssl x509 -req -in certs/server.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/server-cert.pem -days 365 -sha256
    # Clean up CSR
    Remove-Item certs/server.csr
    @echo "Test certificates generated in ./certs/"

# Start local development environment
dev-env: gen-test-certs
    @echo "Starting development environment..."
    @echo "Server will use certificates from ./certs/"
    @echo "Run 'just run-server --cert ./certs/server-cert.pem --key ./certs/server-key.pem' to start server"
    @echo "Run 'just run-client --server localhost:8443' to start client"

# Check everything before committing
pre-commit: fmt lint test

# Full security scan
security-scan: audit deny
    @echo "Running additional security checks..."
    cargo clippy --all-targets --all-features -- -W clippy::suspicious

# Update all dependencies
update:
    cargo update

# Show dependency tree
deps:
    cargo tree --all-features

# Profile build times
profile-build:
    cargo clean
    cargo build --all-features --timings

# Check for outdated dependencies
outdated:
    cargo outdated --root-deps-only