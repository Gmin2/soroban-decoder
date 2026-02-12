use anyhow::{Context, Result};
use soroban_spec::read::from_wasm;
use stellar_xdr::curr::ScSpecEntry;

/// Extract contract spec entries from a compiled Soroban WASM.
pub fn extract_spec(wasm: &[u8]) -> Result<Vec<ScSpecEntry>> {
    from_wasm(wasm).context("failed to extract contract spec from WASM")
}
