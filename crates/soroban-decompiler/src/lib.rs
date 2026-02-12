//! Soroban WASM smart contract decompiler.
//!
//! Reconstructs idiomatic Rust source code from compiled Soroban WASM
//! binaries by combining contract specification metadata with WASM
//! bytecode analysis.
//!
//! # Architecture
//!
//! The decompilation pipeline has four stages:
//!
//! 1. **Spec extraction** ([`spec_extract`]) — reads `contractspecv0`
//!    custom sections to recover type definitions and function signatures.
//! 2. **WASM analysis** ([`wasm_analysis`]) — parses the WASM binary,
//!    traces dispatcher chains, simulates the stack, and extracts host
//!    function call sequences with resolved arguments.
//! 3. **Pattern recognition** ([`pattern_recognizer`]) — maps host call
//!    sequences to high-level SDK operations (e.g. `env.storage().get()`)
//!    and produces an intermediate representation ([`ir`]).
//! 4. **Code generation** ([`codegen`]) — emits Rust token streams from
//!    the IR and formats them with `prettyplease`.
//!
//! # Public Modules
//!
//! - [`host_functions`] — Soroban host function database loaded from
//!   `env.json`.
//! - [`ir`] — High-level intermediate representation types.
//! - [`wasm_analysis`] — WASM module analysis and stack simulation.
//! - [`wasm_imports`] — WASM import resolution against the host
//!   function database.

pub mod host_functions;
pub mod ir;
pub mod wasm_analysis;
pub mod wasm_imports;

mod codegen;
mod pattern_recognizer;
mod spec_extract;

use anyhow::Result;
use stellar_xdr::curr::ScSpecEntry;

/// Options controlling the decompilation process.
pub struct DecompileOptions {
    /// When `true`, only emit type definitions and function signatures
    /// without attempting to decompile function bodies.
    pub signatures_only: bool,
}

/// Extract contract spec entries from a compiled Soroban WASM.
pub fn extract_spec(wasm: &[u8]) -> Result<Vec<ScSpecEntry>> {
    spec_extract::extract_spec(wasm)
}

/// Resolve all host function imports in a WASM binary.
pub fn resolve_imports(
    wasm: &[u8],
) -> Result<Vec<wasm_imports::ResolvedImport>> {
    wasm_imports::resolve_imports(wasm)
}

/// Analyze WASM function bodies, resolving exports and host calls.
pub fn analyze(
    wasm: &[u8],
) -> Result<wasm_analysis::AnalyzedModule> {
    wasm_analysis::AnalyzedModule::from_wasm(wasm)
}

/// Decompile a Soroban WASM binary into Rust source code.
pub fn decompile(
    wasm: &[u8],
    options: &DecompileOptions,
) -> Result<String> {
    let entries = spec_extract::extract_spec(wasm)?;
    if options.signatures_only {
        codegen::generate_rust(&entries, None)
    } else {
        let analysis = wasm_analysis::AnalyzedModule::from_wasm(wasm)?;
        codegen::generate_rust(&entries, Some(&analysis))
    }
}
