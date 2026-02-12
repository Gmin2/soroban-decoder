//! Soroban WASM smart contract decompiler.
//!
//! This crate reconstructs idiomatic Rust source code from compiled Soroban
//! WASM binaries. It combines the contract specification metadata embedded in
//! the WASM custom sections with bytecode-level stack simulation to produce
//! output that closely resembles the original contract source, including type
//! definitions, function signatures, storage operations, authentication calls,
//! and cross-contract invocations.
//!
//! # Quick start
//!
//! The simplest way to use the crate is through the top-level [`decompile`]
//! function, which runs the full pipeline and returns formatted Rust source:
//!
//! ```no_run
//! use soroban_decompiler::{decompile, DecompileOptions};
//!
//! let wasm = std::fs::read("contract.wasm").unwrap();
//! let options = DecompileOptions { signatures_only: false };
//! let source = decompile(&wasm, &options).unwrap();
//! println!("{source}");
//! ```
//!
//! # Architecture
//!
//! The decompilation pipeline runs in four stages. Each stage is also
//! available as a standalone entry point for tools that need intermediate
//! results.
//!
//! 1. **Spec extraction** ([`spec_extract`]) -- reads `contractspecv0` custom
//!    sections to recover struct definitions, enum variants, error codes,
//!    event schemas, and function signatures with fully typed and named
//!    parameters. Entry point: [`extract_spec`].
//!
//! 2. **WASM analysis** ([`wasm_analysis`]) -- parses the binary with
//!    `walrus`, traces through Soroban dispatcher chains, and simulates the
//!    stack for each implementation function. The simulator tracks values
//!    through locals, memory stores, function calls, and control flow
//!    branches, resolving host function call arguments back to their origins
//!    (parameters, constants, or earlier call results). Callee memory writes
//!    are propagated to the caller so that helper functions that store through
//!    pointer parameters have their results visible in the calling function.
//!    Entry point: [`analyze`].
//!
//! 3. **Pattern recognition** ([`pattern_recognizer`]) -- maps host call
//!    sequences to high-level Soroban SDK operations. For example, a
//!    `symbol_new_from_linear_memory` followed by `get_contract_data` becomes
//!    `env.storage().instance().get(symbol_short!("KEY"))`. This stage also
//!    resolves struct field accesses through map unpack operations, detects
//!    i128 round-trips, strips Soroban Val encoding boilerplate, and runs
//!    dead variable elimination and common subexpression elimination. The
//!    output is a typed intermediate representation defined in [`ir`].
//!
//! 4. **Code generation** ([`codegen`]) -- walks the IR and emits Rust token
//!    streams using `syn` and `quote`, then formats the result with
//!    `prettyplease`. Reconstructs `#[contracttype]` definitions,
//!    `#[contracterror]` error enums, `#[contractimpl]` function bodies, and
//!    the top-level `#[contract]` struct with appropriate `use` imports.
//!
//! # Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`spec_extract`] | Contract specification extraction from WASM custom sections |
//! | [`wasm_analysis`] | WASM binary parsing, dispatcher tracing, and stack simulation |
//! | [`wasm_imports`] | WASM import table resolution against the host function database |
//! | [`host_functions`] | Soroban host function database loaded from the bundled `env.json` |
//! | [`ir`] | High-level intermediate representation bridging analysis and codegen |
//! | [`pattern_recognizer`] | Host call sequence to SDK operation mapping |
//! | [`codegen`] | Rust source code generation from IR |

pub mod codegen;
pub mod host_functions;
pub mod ir;
pub mod pattern_recognizer;
pub mod spec_extract;
pub mod wasm_analysis;
pub mod wasm_imports;

use anyhow::Result;
use stellar_xdr::curr::ScSpecEntry;

/// Options controlling the decompilation process.
///
/// Pass this to [`decompile`] to configure which parts of the pipeline run.
pub struct DecompileOptions {
    /// When `true`, skip bytecode analysis entirely and only emit type
    /// definitions and function signatures recovered from the contract spec.
    ///
    /// This is significantly faster and useful when only the contract
    /// interface is needed (for bindings generation, documentation, or
    /// ABI inspection).
    pub signatures_only: bool,
}

/// Extract contract spec entries from a compiled Soroban WASM binary.
///
/// Reads the `contractspecv0` custom section and deserializes it into a list
/// of [`ScSpecEntry`] values covering struct definitions, enum variants,
/// error codes, event schemas, and function signatures.
///
/// This is the first stage of the decompilation pipeline and can be called
/// independently when only the contract metadata is needed.
///
/// # Errors
///
/// Returns an error if the WASM binary does not contain a valid
/// `contractspecv0` section or if the XDR deserialization fails.
pub fn extract_spec(wasm: &[u8]) -> Result<Vec<ScSpecEntry>> {
    spec_extract::extract_spec(wasm)
}

/// Resolve all host function imports in a WASM binary.
///
/// Iterates the WASM import table and matches each function import against
/// the bundled Soroban host function database ([`host_functions`]). Returns
/// one [`wasm_imports::ResolvedImport`] per import, with semantic names
/// filled in for recognized host functions and `None` for unrecognized ones.
///
/// # Errors
///
/// Returns an error if the WASM binary cannot be parsed.
pub fn resolve_imports(
    wasm: &[u8],
) -> Result<Vec<wasm_imports::ResolvedImport>> {
    wasm_imports::resolve_imports(wasm)
}

/// Analyze WASM function bodies, resolving exports and host calls.
///
/// Parses the WASM binary, builds the host function import mapping, and
/// returns an [`wasm_analysis::AnalyzedModule`] that provides per-function
/// analysis including dispatcher tracing and stack simulation.
///
/// # Errors
///
/// Returns an error if `walrus` cannot parse the WASM binary.
pub fn analyze(
    wasm: &[u8],
) -> Result<wasm_analysis::AnalyzedModule> {
    wasm_analysis::AnalyzedModule::from_wasm(wasm)
}

/// Decompile a Soroban WASM binary into formatted Rust source code.
///
/// Runs the full four-stage pipeline (spec extraction, WASM analysis,
/// pattern recognition, code generation) and returns the result as a
/// `prettyplease`-formatted Rust source string.
///
/// When [`DecompileOptions::signatures_only`] is `true`, skips the analysis
/// and pattern recognition stages entirely, producing only type definitions
/// and function stubs with `todo!()` bodies.
///
/// # Errors
///
/// Returns an error if spec extraction fails, the WASM binary cannot be
/// parsed, or the generated token stream is not valid Rust syntax.
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
