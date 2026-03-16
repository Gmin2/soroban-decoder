use serde::Serialize;
use stellar_xdr::curr::{ScSpecEntry, ScSpecTypeDef, ScSpecUdtUnionCaseV0};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn decompile(wasm_bytes: &[u8], signatures_only: Option<bool>) -> Result<String, JsError> {
    let opts = soroban_decompiler::DecompileOptions {
        signatures_only: signatures_only.unwrap_or(false),
    };
    soroban_decompiler::decompile(wasm_bytes, &opts).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn inspect(wasm_bytes: &[u8]) -> Result<String, JsError> {
    let entries = soroban_decompiler::extract_spec(wasm_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let spec = spec_to_json(&entries, wasm_bytes.len());
    serde_json::to_string(&spec).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn imports(wasm_bytes: &[u8]) -> Result<String, JsError> {
    let resolved = soroban_decompiler::resolve_imports(wasm_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let out = imports_to_json(&resolved);
    serde_json::to_string(&out).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn score(original: &str, decompiled: &str) -> Result<String, JsError> {
    let s = soroban_decompiler_bench::score_contract(original, decompiled)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&s).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn benchmark(name: &str, original: &str, decompiled: &str) -> Result<String, JsError> {
    let r = soroban_decompiler_bench::benchmark_contract(name, original, decompiled)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&r).map_err(|e| JsError::new(&e.to_string()))
}

// --- JSON serialization (mirrors CLI approach) ---

#[derive(Serialize)]
struct SpecOut {
    wasm_size: usize,
    functions: Vec<FnOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    structs: Vec<StructOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    enums: Vec<EnumOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<EnumOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    events: Vec<StructOut>,
}

#[derive(Serialize)]
struct FnOut {
    name: String,
    inputs: Vec<FieldOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
}

#[derive(Serialize)]
struct FieldOut {
    name: String,
    r#type: String,
}

#[derive(Serialize)]
struct StructOut {
    name: String,
    fields: Vec<FieldOut>,
}

#[derive(Serialize)]
struct EnumOut {
    name: String,
    variants: Vec<VariantOut>,
}

#[derive(Serialize)]
struct VariantOut {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<u32>,
}

fn spec_to_json(entries: &[ScSpecEntry], wasm_size: usize) -> SpecOut {
    let mut functions = Vec::new();
    let mut structs = Vec::new();
    let mut enums = Vec::new();
    let mut errors = Vec::new();
    let mut events = Vec::new();

    for entry in entries {
        match entry {
            ScSpecEntry::FunctionV0(f) => {
                functions.push(FnOut {
                    name: f.name.to_utf8_string_lossy(),
                    inputs: f
                        .inputs
                        .iter()
                        .map(|i| FieldOut {
                            name: i.name.to_utf8_string_lossy(),
                            r#type: fmt_type(&i.type_),
                        })
                        .collect(),
                    output: f.outputs.to_option().map(|t| fmt_type(&t)),
                });
            }
            ScSpecEntry::UdtStructV0(s) => {
                structs.push(StructOut {
                    name: s.name.to_utf8_string_lossy(),
                    fields: s
                        .fields
                        .iter()
                        .map(|f| FieldOut {
                            name: f.name.to_utf8_string_lossy(),
                            r#type: fmt_type(&f.type_),
                        })
                        .collect(),
                });
            }
            ScSpecEntry::UdtUnionV0(u) => {
                enums.push(EnumOut {
                    name: u.name.to_utf8_string_lossy(),
                    variants: u
                        .cases
                        .iter()
                        .map(|c| match c {
                            ScSpecUdtUnionCaseV0::VoidV0(v) => VariantOut {
                                name: v.name.to_utf8_string_lossy(),
                                types: None,
                                value: None,
                            },
                            ScSpecUdtUnionCaseV0::TupleV0(t) => VariantOut {
                                name: t.name.to_utf8_string_lossy(),
                                types: Some(t.type_.iter().map(|ty| fmt_type(ty)).collect()),
                                value: None,
                            },
                        })
                        .collect(),
                });
            }
            ScSpecEntry::UdtEnumV0(e) => {
                enums.push(EnumOut {
                    name: e.name.to_utf8_string_lossy(),
                    variants: e
                        .cases
                        .iter()
                        .map(|c| VariantOut {
                            name: c.name.to_utf8_string_lossy(),
                            types: None,
                            value: Some(c.value),
                        })
                        .collect(),
                });
            }
            ScSpecEntry::UdtErrorEnumV0(e) => {
                errors.push(EnumOut {
                    name: e.name.to_utf8_string_lossy(),
                    variants: e
                        .cases
                        .iter()
                        .map(|c| VariantOut {
                            name: c.name.to_utf8_string_lossy(),
                            types: None,
                            value: Some(c.value),
                        })
                        .collect(),
                });
            }
            ScSpecEntry::EventV0(e) => {
                events.push(StructOut {
                    name: e.name.to_utf8_string_lossy(),
                    fields: e
                        .params
                        .iter()
                        .map(|p| FieldOut {
                            name: p.name.to_utf8_string_lossy(),
                            r#type: fmt_type(&p.type_),
                        })
                        .collect(),
                });
            }
        }
    }

    SpecOut { wasm_size, functions, structs, enums, errors, events }
}

#[derive(Serialize)]
struct ImportsOut {
    total: usize,
    resolved: usize,
    unresolved: usize,
    imports: Vec<ImportOut>,
}

#[derive(Serialize)]
struct ImportOut {
    module: String,
    field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_name: Option<String>,
    args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    return_type: Option<String>,
}

fn imports_to_json(resolved: &[soroban_decompiler::wasm_imports::ResolvedImport]) -> ImportsOut {
    let total = resolved.len();
    let res = resolved.iter().filter(|i| i.semantic_name.is_some()).count();
    ImportsOut {
        total,
        resolved: res,
        unresolved: total - res,
        imports: resolved
            .iter()
            .map(|i| ImportOut {
                module: i.module.clone(),
                field: i.field.clone(),
                semantic_module: i.semantic_module.clone(),
                semantic_name: i.semantic_name.clone(),
                args: i.args.clone(),
                return_type: i.return_type.clone(),
            })
            .collect(),
    }
}

fn fmt_type(t: &ScSpecTypeDef) -> String {
    match t {
        ScSpecTypeDef::Val => "Val".into(),
        ScSpecTypeDef::Bool => "bool".into(),
        ScSpecTypeDef::Void => "()".into(),
        ScSpecTypeDef::Error => "Error".into(),
        ScSpecTypeDef::U32 => "u32".into(),
        ScSpecTypeDef::I32 => "i32".into(),
        ScSpecTypeDef::U64 => "u64".into(),
        ScSpecTypeDef::I64 => "i64".into(),
        ScSpecTypeDef::U128 => "u128".into(),
        ScSpecTypeDef::I128 => "i128".into(),
        ScSpecTypeDef::U256 => "U256".into(),
        ScSpecTypeDef::I256 => "I256".into(),
        ScSpecTypeDef::Timepoint => "Timepoint".into(),
        ScSpecTypeDef::Duration => "Duration".into(),
        ScSpecTypeDef::Bytes => "Bytes".into(),
        ScSpecTypeDef::String => "String".into(),
        ScSpecTypeDef::Symbol => "Symbol".into(),
        ScSpecTypeDef::Address => "Address".into(),
        ScSpecTypeDef::MuxedAddress => "MuxedAddress".into(),
        ScSpecTypeDef::Option(o) => format!("Option<{}>", fmt_type(&o.value_type)),
        ScSpecTypeDef::Result(r) => {
            format!("Result<{}, {}>", fmt_type(&r.ok_type), fmt_type(&r.error_type))
        }
        ScSpecTypeDef::Vec(v) => format!("Vec<{}>", fmt_type(&v.element_type)),
        ScSpecTypeDef::Map(m) => {
            format!("Map<{}, {}>", fmt_type(&m.key_type), fmt_type(&m.value_type))
        }
        ScSpecTypeDef::Tuple(t) => {
            let types: Vec<String> = t.value_types.iter().map(|ty| fmt_type(ty)).collect();
            format!("({})", types.join(", "))
        }
        ScSpecTypeDef::BytesN(b) => format!("BytesN<{}>", b.n),
        ScSpecTypeDef::Udt(u) => u.name.to_utf8_string_lossy(),
    }
}
