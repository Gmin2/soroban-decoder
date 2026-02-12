//! WASM import table resolution against the Soroban host function database.
//!
//! Every Soroban contract imports host functions through the WASM import table.
//! These imports use short, obfuscated export names (like `"l"` for the
//! `ledger` module, `"_"` for individual functions). This module iterates the
//! import section, resolves each entry through [`crate::host_functions::lookup`],
//! and returns a list of [`ResolvedImport`] values with both the raw and
//! semantic names.

use anyhow::{Context, Result};
use wasmparser::{Parser, Payload};

use crate::host_functions;

/// A single function import from the WASM binary, resolved against the host
/// function database.
///
/// When the import matches a known Soroban host function, the `semantic_*`
/// fields are populated. When it does not match (e.g. a custom import or an
/// unknown host version), those fields are `None`.
#[derive(Debug)]
pub struct ResolvedImport {
    /// Raw WASM module name from the import table.
    pub module: String,
    /// Raw WASM field name (function name) from the import table.
    pub field: String,
    /// Semantic module name if resolved (e.g. `"ledger"`, `"address"`).
    pub semantic_module: Option<String>,
    /// Semantic function name if resolved (e.g. `"get_contract_data"`).
    pub semantic_name: Option<String>,
    /// Argument type names from the host function spec.
    pub args: Vec<String>,
    /// Return type name from the host function spec.
    pub return_type: Option<String>,
}

/// Extract all function imports from a WASM binary and resolve them
/// through the host function database.
///
/// Returns one [`ResolvedImport`] per function import in the WASM binary.
///
/// # Errors
///
/// Returns an error if the WASM binary cannot be parsed.
pub fn resolve_imports(wasm: &[u8]) -> Result<Vec<ResolvedImport>> {
    let mut imports = Vec::new();

    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload.context("failed to parse WASM")?;
        if let Payload::ImportSection(reader) = payload {
            for import in reader {
                let import = import.context("failed to read import")?;
                if let wasmparser::TypeRef::Func(_) = import.ty {
                    let module = import.module;
                    let field = import.name;

                    let resolved = match host_functions::lookup(module, field) {
                        Some(hf) => ResolvedImport {
                            module: module.to_string(),
                            field: field.to_string(),
                            semantic_module: Some(hf.module.to_string()),
                            semantic_name: Some(hf.name.to_string()),
                            args: hf.args.iter().map(|a| a.r#type.to_string()).collect(),
                            return_type: Some(hf.return_type.to_string()),
                        },
                        None => ResolvedImport {
                            module: module.to_string(),
                            field: field.to_string(),
                            semantic_module: None,
                            semantic_name: None,
                            args: Vec::new(),
                            return_type: None,
                        },
                    };
                    imports.push(resolved);
                }
            }
        }
    }

    Ok(imports)
}
