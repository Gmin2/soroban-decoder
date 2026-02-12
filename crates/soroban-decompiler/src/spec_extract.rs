//! Contract specification extraction from WASM custom sections.
//!
//! Soroban contracts compiled with the Soroban SDK embed a `contractspecv0`
//! custom section in the WASM binary. This section contains XDR-encoded
//! metadata describing every public function, struct, enum, error type, and
//! event defined in the contract. The metadata includes full type information
//! and parameter names, making it possible to reconstruct accurate type
//! definitions and function signatures without analyzing the bytecode at all.
//!
//! This module wraps [`soroban_spec::read::from_wasm`] and serves as the
//! entry point to the first stage of the decompilation pipeline.

use anyhow::{Context, Result};
use soroban_spec::read::from_wasm;
use stellar_xdr::curr::ScSpecEntry;

/// Extract contract spec entries from a compiled Soroban WASM binary.
///
/// Locates the `contractspecv0` custom section in the WASM binary, reads its
/// raw bytes, and deserializes them into a vector of [`ScSpecEntry`] values.
/// Each entry describes one public item in the contract: a function, struct,
/// enum, error enum, or event.
///
/// # Errors
///
/// Returns an error if the WASM binary does not contain a `contractspecv0`
/// section or if the XDR payload cannot be deserialized.
pub fn extract_spec(wasm: &[u8]) -> Result<Vec<ScSpecEntry>> {
    from_wasm(wasm).context("failed to extract contract spec from WASM")
}
