use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use stellar_xdr::curr::{
    ScSpecEntry, ScSpecTypeDef, ScSpecUdtUnionCaseV0,
};

use soroban_decompiler::wasm_analysis::{
    AnalyzedBlock, StackValue,
};
use soroban_decompiler::{decompile, DecompileOptions};

#[derive(Parser)]
#[command(name = "soroban-decompile")]
#[command(about = "Decompile Soroban WASM smart contracts back to Rust source code")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decompile a Soroban WASM file to Rust source
    Decompile {
        /// Path to the input .wasm file
        #[arg(short, long)]
        input: PathBuf,

        /// Path to write the output .rs file (prints to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Only extract type definitions and function signatures (skip body decompilation)
        #[arg(long)]
        signatures_only: bool,
    },
    /// Inspect contract spec (types, functions) as JSON
    Inspect {
        /// Path to the input .wasm file
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Resolve WASM host function imports and show their semantic names
    Imports {
        /// Path to the input .wasm file
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Analyze WASM function bodies: trace dispatchers, resolve host calls
    Analyze {
        /// Path to the input .wasm file
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Debug: dump stack analysis for a specific export function
    DebugStack {
        /// Path to the input .wasm file
        #[arg(short, long)]
        input: PathBuf,
        /// Export function name to debug
        #[arg(short, long)]
        func: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Decompile {
            input,
            output,
            signatures_only,
        } => {
            let wasm = read_wasm(&input)?;
            let options = DecompileOptions { signatures_only };
            let rust_source = decompile(&wasm, &options)?;

            match output {
                Some(path) => {
                    fs::write(&path, &rust_source)
                        .with_context(|| format!("failed to write {}", path.display()))?;
                    eprintln!("Decompiled output written to {}", path.display());
                }
                None => {
                    print!("{rust_source}");
                }
            }
        }
        Commands::Inspect { input } => {
            let wasm = read_wasm(&input)?;
            let entries = soroban_decompiler::extract_spec(&wasm)?;
            let json = spec_to_json(&entries, wasm.len())?;
            println!("{json}");
        }
        Commands::Imports { input } => {
            let wasm = read_wasm(&input)?;
            let imports = soroban_decompiler::resolve_imports(&wasm)?;
            let json = imports_to_json(&imports)?;
            println!("{json}");
        }
        Commands::Analyze { input } => {
            let wasm = read_wasm(&input)?;
            let analyzed = soroban_decompiler::analyze(&wasm)?;
            let analyses = analyzed.analyze_all_exports();
            let json = analyses_to_json(&analyses)?;
            println!("{json}");
        }
        Commands::DebugStack { input, func } => {
            let wasm = read_wasm(&input)?;
            let analyzed = soroban_decompiler::analyze(&wasm)?;
            let analysis = analyzed.analyze_export(&func)?;
            let stack = analyzed.analyze_function_stack(analysis.impl_func_id);
            println!("Export: {func}");
            println!("Export FuncId: {:?}", analysis.export_func_id);
            println!("Impl FuncId: {:?}", analysis.impl_func_id);
            println!("Dispatcher traced: {}", analysis.export_func_id != analysis.impl_func_id);
            println!("Wasm params: {}", analyzed.wasm_param_count(analysis.impl_func_id));
            println!("\n--- Host Calls ({}) ---", stack.host_calls.len());
            for (i, call) in stack.host_calls.iter().enumerate() {
                println!("[{}] {} (call_site_id={})", i, call.host_func.name, call.call_site_id);
                for (j, arg) in call.args.iter().enumerate() {
                    println!("    arg[{}]: {:?}", j, arg);
                }
            }
            println!("\n--- Return Expr ---");
            println!("{:?}", stack.return_expr);
            println!("\n--- Blocks ---");
            fn dump_blocks(
                blocks: &[AnalyzedBlock],
                indent: usize,
            ) {
                let pad = " ".repeat(indent);
                for block in blocks {
                    match block {
                        AnalyzedBlock::HostCall(call) => {
                            println!(
                                "{pad}HostCall: {} (id={})",
                                call.host_func.name,
                                call.call_site_id,
                            );
                            for (j, arg) in call.args.iter().enumerate() {
                                println!("{pad}  arg[{j}]: {arg:?}");
                            }
                        }
                        AnalyzedBlock::If {
                            condition,
                            then_block,
                            else_block,
                        } => {
                            println!("{pad}If ({condition:?}) {{");
                            dump_blocks(then_block, indent + 2);
                            if !else_block.is_empty() {
                                println!("{pad}}} else {{");
                                dump_blocks(else_block, indent + 2);
                            }
                            println!("{pad}}}");
                        }
                        AnalyzedBlock::Loop {
                            body,
                            has_back_edge,
                        } => {
                            println!(
                                "{pad}Loop (back_edge={has_back_edge}) {{",
                            );
                            dump_blocks(body, indent + 2);
                            println!("{pad}}}");
                        }
                    }
                }
            }
            dump_blocks(&stack.blocks, 0);
            println!("\n--- Memory State ---");
            let mut entries: Vec<_> = stack
                .memory_state
                .iter()
                .filter(|(_, v)| !matches!(v, StackValue::Unknown))
                .collect();
            entries.sort_by_key(|((lid, off), _)| (lid.index(), *off));
            for ((lid, off), val) in entries {
                println!("  ({:?}, {}) = {:?}", lid, off, val);
            }
        }
    }

    Ok(())
}

fn read_wasm(path: &PathBuf) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

// -- JSON serialization (CLI-only concern) --

fn spec_to_json(entries: &[ScSpecEntry], wasm_size: usize) -> Result<String> {
    let mut functions = Vec::new();
    let mut structs = Vec::new();
    let mut enums = Vec::new();
    let mut errors = Vec::new();
    let mut events = Vec::new();

    for entry in entries {
        match entry {
            ScSpecEntry::FunctionV0(f) => {
                functions.push(FnJson {
                    name: f.name.to_utf8_string_lossy(),
                    inputs: f.inputs.iter().map(|i| FieldJson {
                        name: i.name.to_utf8_string_lossy(),
                        r#type: format_type(&i.type_),
                    }).collect(),
                    output: f.outputs.to_option().map(|t| format_type(&t)),
                });
            }
            ScSpecEntry::UdtStructV0(s) => {
                structs.push(StructJson {
                    name: s.name.to_utf8_string_lossy(),
                    fields: s.fields.iter().map(|f| FieldJson {
                        name: f.name.to_utf8_string_lossy(),
                        r#type: format_type(&f.type_),
                    }).collect(),
                });
            }
            ScSpecEntry::UdtUnionV0(u) => {
                enums.push(EnumJson {
                    name: u.name.to_utf8_string_lossy(),
                    variants: u.cases.iter().map(|c| match c {
                        ScSpecUdtUnionCaseV0::VoidV0(v) => VariantJson {
                            name: v.name.to_utf8_string_lossy(),
                            types: None,
                            value: None,
                        },
                        ScSpecUdtUnionCaseV0::TupleV0(t) => VariantJson {
                            name: t.name.to_utf8_string_lossy(),
                            types: Some(t.type_.iter().map(|ty| format_type(ty)).collect()),
                            value: None,
                        },
                    }).collect(),
                });
            }
            ScSpecEntry::UdtEnumV0(e) => {
                enums.push(EnumJson {
                    name: e.name.to_utf8_string_lossy(),
                    variants: e.cases.iter().map(|c| VariantJson {
                        name: c.name.to_utf8_string_lossy(),
                        types: None,
                        value: Some(c.value),
                    }).collect(),
                });
            }
            ScSpecEntry::UdtErrorEnumV0(e) => {
                errors.push(EnumJson {
                    name: e.name.to_utf8_string_lossy(),
                    variants: e.cases.iter().map(|c| VariantJson {
                        name: c.name.to_utf8_string_lossy(),
                        types: None,
                        value: Some(c.value),
                    }).collect(),
                });
            }
            ScSpecEntry::EventV0(e) => {
                events.push(StructJson {
                    name: e.name.to_utf8_string_lossy(),
                    fields: e.params.iter().map(|p| FieldJson {
                        name: p.name.to_utf8_string_lossy(),
                        r#type: format_type(&p.type_),
                    }).collect(),
                });
            }
        }
    }

    let output = ContractJson { wasm_size, functions, structs, enums, errors, events };
    serde_json::to_string_pretty(&output).context("failed to serialize")
}

fn imports_to_json(
    imports: &[soroban_decompiler::wasm_imports::ResolvedImport],
) -> Result<String> {
    let resolved = imports.iter().filter(|i| i.semantic_name.is_some()).count();
    let total = imports.len();

    let items: Vec<ImportJson> = imports.iter().map(|i| ImportJson {
        module: &i.module,
        field: &i.field,
        semantic_module: i.semantic_module.as_deref(),
        semantic_name: i.semantic_name.as_deref(),
        args: &i.args,
        return_type: i.return_type.as_deref(),
    }).collect();

    let output = ImportsJson { total, resolved, unresolved: total - resolved, imports: items };
    serde_json::to_string_pretty(&output).context("failed to serialize")
}

fn analyses_to_json(
    analyses: &[soroban_decompiler::wasm_analysis::FunctionAnalysis],
) -> Result<String> {
    let items: Vec<AnalysisJson> = analyses.iter().map(|a| {
        AnalysisJson {
            export_name: &a.export_name,
            dispatcher_traced: a.export_func_id != a.impl_func_id,
            host_calls: a.host_calls.iter().map(|h| HostCallJson {
                module: &h.semantic_module,
                name: &h.semantic_name,
                raw_module: &h.raw_module,
                raw_field: &h.raw_field,
            }).collect(),
            local_call_count: a.local_call_count,
            has_branches: a.has_branches,
            has_loops: a.has_loops,
            instruction_count: a.instruction_count,
        }
    }).collect();

    serde_json::to_string_pretty(&items).context("failed to serialize")
}

fn format_type(t: &ScSpecTypeDef) -> String {
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
        ScSpecTypeDef::Option(o) => {
            format!("Option<{}>", format_type(&o.value_type))
        }
        ScSpecTypeDef::Result(r) => {
            format!(
                "Result<{}, {}>",
                format_type(&r.ok_type),
                format_type(&r.error_type),
            )
        }
        ScSpecTypeDef::Vec(v) => {
            format!("Vec<{}>", format_type(&v.element_type))
        }
        ScSpecTypeDef::Map(m) => {
            format!(
                "Map<{}, {}>",
                format_type(&m.key_type),
                format_type(&m.value_type),
            )
        }
        ScSpecTypeDef::Tuple(t) => {
            let types: Vec<String> = t.value_types.iter().map(|ty| format_type(ty)).collect();
            format!("({})", types.join(", "))
        }
        ScSpecTypeDef::BytesN(b) => format!("BytesN<{}>", b.n),
        ScSpecTypeDef::Udt(u) => u.name.to_utf8_string_lossy(),
    }
}

// -- JSON types --

#[derive(Serialize)]
struct ContractJson {
    wasm_size: usize,
    functions: Vec<FnJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    structs: Vec<StructJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    enums: Vec<EnumJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<EnumJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    events: Vec<StructJson>,
}

#[derive(Serialize)]
struct FnJson {
    name: String,
    inputs: Vec<FieldJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
}

#[derive(Serialize)]
struct FieldJson {
    name: String,
    r#type: String,
}

#[derive(Serialize)]
struct StructJson {
    name: String,
    fields: Vec<FieldJson>,
}

#[derive(Serialize)]
struct EnumJson {
    name: String,
    variants: Vec<VariantJson>,
}

#[derive(Serialize)]
struct VariantJson {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<u32>,
}

#[derive(Serialize)]
struct ImportsJson<'a> {
    total: usize,
    resolved: usize,
    unresolved: usize,
    imports: Vec<ImportJson<'a>>,
}

#[derive(Serialize)]
struct ImportJson<'a> {
    module: &'a str,
    field: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_module: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_name: Option<&'a str>,
    args: &'a Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    return_type: Option<&'a str>,
}

#[derive(Serialize)]
struct AnalysisJson<'a> {
    export_name: &'a str,
    dispatcher_traced: bool,
    host_calls: Vec<HostCallJson<'a>>,
    local_call_count: usize,
    has_branches: bool,
    has_loops: bool,
    instruction_count: usize,
}

#[derive(Serialize)]
struct HostCallJson<'a> {
    module: &'a str,
    name: &'a str,
    raw_module: &'a str,
    raw_field: &'a str,
}
