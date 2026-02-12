use anyhow::{Context, Result};
use wasmparser::{Parser, Payload};

use crate::host_functions;

#[derive(Debug)]
pub struct ResolvedImport {
    pub module: String,
    pub field: String,
    pub semantic_module: Option<String>,
    pub semantic_name: Option<String>,
    pub args: Vec<String>,
    pub return_type: Option<String>,
}

/// Extract all function imports from a WASM binary and resolve them
/// through the host function database.
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
