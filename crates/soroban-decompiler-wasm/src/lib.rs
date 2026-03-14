use wasm_bindgen::prelude::*;

/// Decompile a Soroban WASM binary into Rust source code.
///
/// Takes raw WASM bytes and returns formatted Rust source.
/// Set `signatures_only` to true to skip bytecode analysis and only emit
/// type definitions and function stubs.
#[wasm_bindgen]
pub fn decompile(wasm_bytes: &[u8], signatures_only: Option<bool>) -> Result<String, JsError> {
    let opts = soroban_decompiler::DecompileOptions {
        signatures_only: signatures_only.unwrap_or(false),
    };
    soroban_decompiler::decompile(wasm_bytes, &opts).map_err(|e| JsError::new(&e.to_string()))
}

/// Extract the contract spec as JSON.
///
/// Returns a JSON string containing all struct definitions, enum variants,
/// error codes, event schemas, and function signatures.
#[wasm_bindgen]
pub fn inspect(wasm_bytes: &[u8]) -> Result<String, JsError> {
    let entries = soroban_decompiler::extract_spec(wasm_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let json = format!("{:?}", entries);
    Ok(json)
}

/// Resolve WASM host function imports as JSON.
///
/// Returns a JSON array of all resolved imports with their semantic names.
#[wasm_bindgen]
pub fn imports(wasm_bytes: &[u8]) -> Result<String, JsError> {
    let resolved = soroban_decompiler::resolve_imports(wasm_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let json = format!("{:?}", resolved);
    Ok(json)
}

/// Score decompiled output against original source.
///
/// Returns a JSON object with type, signature, and body accuracy scores.
#[wasm_bindgen]
pub fn score(original: &str, decompiled: &str) -> Result<String, JsError> {
    let score = soroban_decompiler_bench::score_contract(original, decompiled)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&score).map_err(|e| JsError::new(&e.to_string()))
}

/// Full benchmark report for a contract pair as JSON.
///
/// Returns detailed comparison data including per-function scores,
/// statement alignments, and type comparisons.
#[wasm_bindgen]
pub fn benchmark(name: &str, original: &str, decompiled: &str) -> Result<String, JsError> {
    let report = soroban_decompiler_bench::benchmark_contract(name, original, decompiled)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&report).map_err(|e| JsError::new(&e.to_string()))
}
