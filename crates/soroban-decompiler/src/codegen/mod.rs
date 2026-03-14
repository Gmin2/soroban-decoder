//! Rust source code generation from the decompiled IR.
//!
//! This is the final stage of the decompilation pipeline. It takes contract
//! specification entries (for type definitions) and optionally an analyzed
//! WASM module (for function bodies), produces a Rust token stream using
//! `quote`, and formats it with `prettyplease`.
//!
//! The generated code includes:
//!
//! - `#![no_std]` and `use soroban_sdk::{...}` imports
//! - `#[contracttype]` struct and enum definitions
//! - `#[contracterror]` error enum definitions
//! - `#[soroban_sdk::contractevent]` event struct definitions
//! - `#[contract]` struct declaration
//! - `#[contractimpl]` block with decompiled function bodies
//!
//! When no WASM analysis is provided (signatures-only mode), function bodies
//! contain `todo!("body decompilation pending")` placeholders.
//!
//! # Submodules
//!
//! - [`types`] -- type definition generators (structs, enums, events)
//! - [`emit`] -- statement and expression token emission
//! - [`imports`] -- SDK type and macro import collection

mod types;
mod emit;
mod imports;

use anyhow::Result;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use stellar_xdr::curr as stellar_xdr;
use stellar_xdr::{
    ScSpecEntry, ScSpecUdtUnionCaseV0,
};

use crate::pattern_recognizer;
use crate::wasm_analysis::AnalyzedModule;

/// Generate formatted Rust source code from contract spec entries.
///
/// When `analysis` is provided, attempts to decompile function bodies using
/// pattern recognition. Falls back to `todo!()` for unrecognized patterns.
pub fn generate_rust(
    entries: &[ScSpecEntry],
    analysis: Option<&AnalyzedModule>,
) -> Result<String> {
    let tokens = generate_tokens(entries, analysis);
    let file = syn::parse2(tokens)
        .map_err(|e| anyhow::anyhow!("generated code failed to parse: {e}"))?;
    let formatted = prettyplease::unparse(&file);
    let mut formatted = formatted.replace("& env", "&env");

    let error_enums: Vec<String> = entries.iter().filter_map(|e| {
        if let ScSpecEntry::UdtErrorEnumV0(err) = e {
            Some(err.name.to_utf8_string_lossy())
        } else {
            None
        }
    }).collect();
    if !error_enums.is_empty() {
        formatted = formatted.replace("soroban_sdk::Error", &error_enums[0]);
    }

    for entry in entries {
        if let ScSpecEntry::UdtErrorEnumV0(err) = entry {
            let enum_name = err.name.to_utf8_string_lossy();
            for case in err.cases.iter() {
                let placeholder = format!("__contract_error_{}", case.value);
                let replacement = format!(
                    "{}::{}",
                    enum_name,
                    case.name.to_utf8_string_lossy(),
                );
                formatted = formatted.replace(&placeholder, &replacement);
            }
        }
    }

    Ok(formatted)
}

fn generate_tokens(entries: &[ScSpecEntry], analysis: Option<&AnalyzedModule>) -> TokenStream {
    let mut sdk_types = std::collections::BTreeSet::new();
    let mut has_functions = false;
    let mut has_types = false;
    let mut has_errors = false;

    for entry in entries {
        match entry {
            ScSpecEntry::FunctionV0(f) => {
                has_functions = true;
                for input in f.inputs.iter() {
                    imports::collect_sdk_types(&input.type_, &mut sdk_types);
                }
                if let Some(t) = f.outputs.to_option() {
                    imports::collect_sdk_types(&t, &mut sdk_types);
                }
            }
            ScSpecEntry::UdtStructV0(s) => {
                has_types = true;
                for f in s.fields.iter() {
                    imports::collect_sdk_types(&f.type_, &mut sdk_types);
                }
            }
            ScSpecEntry::UdtUnionV0(u) => {
                has_types = true;
                for c in u.cases.iter() {
                    if let ScSpecUdtUnionCaseV0::TupleV0(t) = c {
                        for ty in t.type_.iter() {
                            imports::collect_sdk_types(ty, &mut sdk_types);
                        }
                    }
                }
            }
            ScSpecEntry::UdtEnumV0(_) => { has_types = true; }
            ScSpecEntry::UdtErrorEnumV0(_) => { has_errors = true; }
            ScSpecEntry::EventV0(e) => {
                for p in e.params.iter() {
                    imports::collect_sdk_types(&p.type_, &mut sdk_types);
                }
            }
        }
    }

    let mut use_parts: Vec<TokenStream> = vec![
        quote! { contract },
        quote! { contractimpl },
    ];
    if has_functions {
        use_parts.push(quote! { Env });
    }
    if has_types {
        use_parts.push(quote! { contracttype });
    }
    if has_errors {
        use_parts.push(quote! { contracterror });
    }
    for ty_name in &sdk_types {
        let ident = format_ident!("{}", ty_name);
        use_parts.push(quote! { #ident });
    }

    let mut is_account_contract = false;
    let mut referenced_udts: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let contract_type_names: std::collections::HashSet<String> = entries.iter().filter_map(|e| {
        match e {
            ScSpecEntry::UdtStructV0(s) => Some(s.name.to_utf8_string_lossy()),
            ScSpecEntry::UdtUnionV0(u) => Some(u.name.to_utf8_string_lossy()),
            ScSpecEntry::UdtEnumV0(e) => Some(e.name.to_utf8_string_lossy()),
            ScSpecEntry::UdtErrorEnumV0(e) => Some(e.name.to_utf8_string_lossy()),
            _ => None,
        }
    }).collect();

    for entry in entries {
        if let ScSpecEntry::FunctionV0(f) = entry {
            let fn_name = f.name.to_utf8_string_lossy();
            if fn_name == "__check_auth" {
                is_account_contract = true;
            }
            for input in f.inputs.iter() {
                imports::collect_udt_refs(&input.type_, &mut referenced_udts);
            }
            if let Some(t) = f.outputs.to_option() {
                imports::collect_udt_refs(&t, &mut referenced_udts);
            }
        }
    }

    let mut extra_use_stmts: Vec<TokenStream> = Vec::new();
    for udt_name in &referenced_udts {
        if !contract_type_names.contains(udt_name.as_str()) {
            match udt_name.as_str() {
                "Context" => {
                    extra_use_stmts.push(quote! { use soroban_sdk::auth::Context; });
                }
                _ => {}
            }
        }
    }
    if is_account_contract {
        extra_use_stmts.push(quote! { use soroban_sdk::auth::CustomAccountInterface; });
    }

    let mut type_defs = Vec::new();
    let mut fns = Vec::new();
    let mut body_irs = Vec::new();

    for entry in entries {
        match entry {
            ScSpecEntry::FunctionV0(f) => {
                let body_ir = analysis.and_then(|a| pattern_recognizer::recognize(a, f, entries));
                fns.push(emit::gen_function(f, body_ir.as_ref()));
                if let Some(ir) = body_ir {
                    body_irs.push(ir);
                }
            }
            ScSpecEntry::UdtStructV0(s) => type_defs.push(types::gen_struct(s)),
            ScSpecEntry::UdtUnionV0(u) => type_defs.push(types::gen_union(u)),
            ScSpecEntry::UdtEnumV0(e) => type_defs.push(types::gen_enum(e)),
            ScSpecEntry::UdtErrorEnumV0(e) => type_defs.push(types::gen_error_enum(e)),
            ScSpecEntry::EventV0(e) => type_defs.push(types::gen_event(e)),
        }
    }

    let mut extra_imports = std::collections::BTreeSet::new();
    for ir in &body_irs {
        for stmt in &ir.body {
            imports::collect_ir_imports_stmt(stmt, &mut extra_imports);
        }
    }
    for imp in &extra_imports {
        if !sdk_types.contains(imp) {
            let ident = format_ident!("{}", imp);
            use_parts.push(quote! { #ident });
        }
    }

    quote! {
        #![no_std]

        use soroban_sdk::{#(#use_parts),*};
        #(#extra_use_stmts)*

        #(#type_defs)*

        #[contract]
        pub struct Contract;

        #[contractimpl]
        impl Contract {
            #(#fns)*
        }
    }
}
