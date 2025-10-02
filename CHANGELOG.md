# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - Phase 2, Week 6

#### Admin API (Task 10)
- REST API for certificate management with 7 endpoints
- Certificate listing and filtering
- Certificate upload and rotation
- Certificate deletion
- Revocation status checking via API
- Health check endpoint
- Authentication and authorization middleware
- Comprehensive audit logging for all operations
- 12 request/response models with validation

#### Diagnostic Tools (Task 11)
- CLI diagnostic tool (`norc-diag`) with 6 subcommands
- Certificate validation testing (`validate`)
- Revocation check testing (`revocation`) supporting OCSP and CRL
- Health check utilities (`health`)
- Configuration validation (`config`)
- Certificate inspection and analysis (`inspect`)
- Comprehensive diagnostics runner (`all`)
- Colored terminal output for better readability
- Structured logging for all diagnostic operations

#### CI/CD Integration (Task 12)
- GitHub Actions workflow for continuous integration
- Multi-platform test matrix (Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64)
- Automated testing on pull requests and pushes
- Code coverage reporting with cargo-llvm-cov (80% threshold)
- Security scanning with cargo-audit and cargo-deny
- Performance benchmarks with criterion
- Release workflow for automated binary builds
- Container image builds for Docker/Kubernetes
- Codecov integration
- Clippy linting with strict rules
- Rustfmt configuration for consistent code style

### Added - Phase 2, Week 5

#### Observability Infrastructure (Tasks 6-9)
- Prometheus metrics collection (35 metrics)
- Structured logging with tracing (19 functions)
- Distributed tracing support (28 spans)
- Health check system (6 health types)
- 67 comprehensive tests

### Changed
- Updated Cargo.toml with benchmark configuration
- Added criterion as workspace dependency
- Enhanced error handling with stricter clippy rules

### Security
- Added cargo-deny configuration for license and vulnerability checking
- Configured security scanning in CI pipeline
- Implemented automated vulnerability detection
- Added container security best practices in Dockerfiles

## [0.1.0] - 2024-10-02

### Added
- Initial project structure
- Protocol specification
- Server requirements documentation
- Basic transport layer
- Client and server core implementations
- Persistence layer with SQLite
- Configuration management
- TUI interface
- CLI interface

### Infrastructure
- Workspace setup with multiple crates
- Cargo workspace configuration
- Rust toolchain specification (1.90.0)
- Apache 2.0 license

[Unreleased]: https://github.com/NavaTron/norc/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/NavaTron/norc/releases/tag/v0.1.0
