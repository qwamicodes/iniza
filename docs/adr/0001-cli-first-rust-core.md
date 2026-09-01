# Build the supported CLI on a reusable Rust core

Iniza will prove the complete migration workflow through a supported Rust CLI before building a desktop client. Migration policy, bundle handling, project protection, recovery, verification, and restore behavior belong to reusable Rust core APIs; current and future interfaces remain adapters so they cannot silently diverge on safety or format semantics.
