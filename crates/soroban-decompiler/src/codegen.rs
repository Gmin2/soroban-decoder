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

use anyhow::Result;
use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use stellar_xdr::curr as stellar_xdr;
use stellar_xdr::{
    ScSpecEntry, ScSpecEventParamLocationV0, ScSpecEventV0, ScSpecFunctionV0, ScSpecTypeDef,
    ScSpecUdtEnumV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructV0, ScSpecUdtUnionCaseV0,
    ScSpecUdtUnionV0,
};

use crate::ir;
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
    Ok(prettyplease::unparse(&file))
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
                    collect_sdk_types(&input.type_, &mut sdk_types);
                }
                if let Some(t) = f.outputs.to_option() {
                    collect_sdk_types(&t, &mut sdk_types);
                }
            }
            ScSpecEntry::UdtStructV0(s) => {
                has_types = true;
                for f in s.fields.iter() {
                    collect_sdk_types(&f.type_, &mut sdk_types);
                }
            }
            ScSpecEntry::UdtUnionV0(u) => {
                has_types = true;
                for c in u.cases.iter() {
                    if let ScSpecUdtUnionCaseV0::TupleV0(t) = c {
                        for ty in t.type_.iter() {
                            collect_sdk_types(ty, &mut sdk_types);
                        }
                    }
                }
            }
            ScSpecEntry::UdtEnumV0(_) => { has_types = true; }
            ScSpecEntry::UdtErrorEnumV0(_) => { has_errors = true; }
            ScSpecEntry::EventV0(e) => {
                for p in e.params.iter() {
                    collect_sdk_types(&p.type_, &mut sdk_types);
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

    let mut type_defs = Vec::new();
    let mut fns = Vec::new();

    for entry in entries {
        match entry {
            ScSpecEntry::FunctionV0(f) => {
                let body_ir = analysis.and_then(|a| pattern_recognizer::recognize(a, f, entries));
                fns.push(gen_function(f, body_ir.as_ref()));
            }
            ScSpecEntry::UdtStructV0(s) => type_defs.push(gen_struct(s)),
            ScSpecEntry::UdtUnionV0(u) => type_defs.push(gen_union(u)),
            ScSpecEntry::UdtEnumV0(e) => type_defs.push(gen_enum(e)),
            ScSpecEntry::UdtErrorEnumV0(e) => type_defs.push(gen_error_enum(e)),
            ScSpecEntry::EventV0(e) => type_defs.push(gen_event(e)),
        }
    }

    quote! {
        #![no_std]

        use soroban_sdk::{#(#use_parts),*};

        #(#type_defs)*

        #[contract]
        pub struct Contract;

        #[contractimpl]
        impl Contract {
            #(#fns)*
        }
    }
}

fn gen_struct(spec: &ScSpecUdtStructV0) -> TokenStream {
    let ident = format_ident!("{}", spec.name.to_utf8_string_lossy());

    if spec.lib.len() > 0 {
        let lib_ident = format_ident!("{}", spec.lib.to_utf8_string_lossy());
        return quote! { type #ident = ::#lib_ident::#ident; };
    }

    let is_tuple = spec
        .fields
        .iter()
        .all(|f| f.name.to_utf8_string_lossy().parse::<usize>().is_ok());

    if is_tuple {
        let fields = spec.fields.iter().map(|f| {
            let f_type = gen_type_ident(&f.type_);
            quote! { pub #f_type }
        });
        quote! {
            #[contracttype]
            #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
            pub struct #ident(#(#fields),*);
        }
    } else {
        let fields = spec.fields.iter().map(|f| {
            let f_ident = format_ident!("{}", f.name.to_utf8_string_lossy());
            let f_type = gen_type_ident(&f.type_);
            quote! { pub #f_ident: #f_type }
        });
        quote! {
            #[contracttype]
            #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
            pub struct #ident { #(#fields,)* }
        }
    }
}

fn gen_union(spec: &ScSpecUdtUnionV0) -> TokenStream {
    let ident = format_ident!("{}", spec.name.to_utf8_string_lossy());

    if spec.lib.len() > 0 {
        let lib_ident = format_ident!("{}", spec.lib.to_utf8_string_lossy());
        return quote! { pub type #ident = ::#lib_ident::#ident; };
    }

    let variants = spec.cases.iter().map(|c| match c {
        ScSpecUdtUnionCaseV0::VoidV0(v) => {
            let v_ident = format_ident!("{}", v.name.to_utf8_string_lossy());
            quote! { #v_ident }
        }
        ScSpecUdtUnionCaseV0::TupleV0(t) => {
            let v_ident = format_ident!("{}", t.name.to_utf8_string_lossy());
            let v_types = t.type_.iter().map(|ty| gen_type_ident(ty));
            quote! { #v_ident(#(#v_types),*) }
        }
    });

    quote! {
        #[contracttype]
        #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
        pub enum #ident { #(#variants,)* }
    }
}

fn gen_enum(spec: &ScSpecUdtEnumV0) -> TokenStream {
    let ident = format_ident!("{}", spec.name.to_utf8_string_lossy());

    if spec.lib.len() > 0 {
        let lib_ident = format_ident!("{}", spec.lib.to_utf8_string_lossy());
        return quote! { pub type #ident = ::#lib_ident::#ident; };
    }

    let variants = spec.cases.iter().map(|c| {
        let v_ident = format_ident!("{}", c.name.to_utf8_string_lossy());
        let v_value = Literal::u32_unsuffixed(c.value);
        quote! { #v_ident = #v_value }
    });

    quote! {
        #[contracttype]
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
        pub enum #ident { #(#variants,)* }
    }
}

fn gen_error_enum(spec: &ScSpecUdtErrorEnumV0) -> TokenStream {
    let ident = format_ident!("{}", spec.name.to_utf8_string_lossy());

    if spec.lib.len() > 0 {
        let lib_ident = format_ident!("{}", spec.lib.to_utf8_string_lossy());
        return quote! { pub type #ident = ::#lib_ident::#ident; };
    }

    let variants = spec.cases.iter().map(|c| {
        let v_ident = format_ident!("{}", c.name.to_utf8_string_lossy());
        let v_value = Literal::u32_unsuffixed(c.value);
        quote! { #v_ident = #v_value }
    });

    quote! {
        #[contracterror]
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
        pub enum #ident { #(#variants,)* }
    }
}

fn gen_event(spec: &ScSpecEventV0) -> TokenStream {
    let ident = format_ident!("{}", spec.name.to_utf8_string_lossy());

    if spec.lib.len() > 0 {
        let lib_ident = format_ident!("{}", spec.lib.to_utf8_string_lossy());
        return quote! { type #ident = ::#lib_ident::#ident; };
    }

    let fields = spec.params.iter().map(|p| {
        let p_ident = format_ident!("{}", p.name.to_utf8_string_lossy());
        let p_type = gen_type_ident(&p.type_);
        match p.location {
            ScSpecEventParamLocationV0::TopicList => quote! {
                #[topic]
                pub #p_ident: #p_type
            },
            ScSpecEventParamLocationV0::Data => quote! {
                pub #p_ident: #p_type
            },
        }
    });

    quote! {
        #[soroban_sdk::contractevent]
        #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
        pub struct #ident { #(#fields,)* }
    }
}

fn gen_function(spec: &ScSpecFunctionV0, body_ir: Option<&ir::FunctionIR>) -> TokenStream {
    let fn_ident = format_ident!("{}", spec.name.to_utf8_string_lossy());

    let fn_inputs = spec.inputs.iter().map(|input| {
        let name = format_ident!("{}", input.name.to_utf8_string_lossy());
        let type_ident = gen_type_ident(&input.type_);
        quote! { #name: #type_ident }
    });

    let fn_output = spec
        .outputs
        .to_option()
        .map(|t| gen_type_ident(&t))
        .map(|t| quote! { -> #t });

    let is_void = spec.outputs.to_option()
        .map_or(true, |t| matches!(t, ScSpecTypeDef::Void));

    let body = match body_ir {
        Some(func_ir) => {
            let stmts: Vec<TokenStream> = func_ir.body.iter().map(gen_statement).collect();
            let ends_with_return = func_ir.body.last()
                .map_or(false, |s| matches!(s, ir::Statement::Return(_)));
            if ends_with_return || is_void {
                quote! { #(#stmts)* }
            } else {
                quote! { #(#stmts)* todo!("remaining logic") }
            }
        }
        None => quote! { todo!("body decompilation pending") },
    };

    quote! {
        pub fn #fn_ident(env: Env, #(#fn_inputs),*) #fn_output {
            #body
        }
    }
}

/// Convert an IR statement to a TokenStream.
fn gen_statement(stmt: &ir::Statement) -> TokenStream {
    match stmt {
        ir::Statement::Let { name, mutable, value } => {
            // Sanitize: replace dots and brackets with underscores for valid identifiers
            let safe_name = name.replace('.', "_").replace('[', "_").replace(']', "");
            let ident = format_ident!("{}", safe_name);
            let val = gen_expr(value);
            if *mutable {
                quote! { let mut #ident = #val; }
            } else {
                quote! { let #ident = #val; }
            }
        }
        ir::Statement::Assign { target, value } => {
            let t = gen_expr(target);
            let v = gen_expr(value);
            quote! { #t = #v; }
        }
        ir::Statement::Expr(expr) => {
            let e = gen_expr(expr);
            quote! { #e; }
        }
        ir::Statement::Return(Some(expr)) => {
            let e = gen_expr(expr);
            quote! { return #e; }
        }
        ir::Statement::Return(None) => {
            quote! { return; }
        }
        ir::Statement::If { condition, then_body, else_body } => {
            let cond = gen_expr(condition);
            let then_stmts: Vec<TokenStream> = then_body.iter().map(gen_statement).collect();
            if else_body.is_empty() {
                quote! { if #cond { #(#then_stmts)* } }
            } else {
                let else_stmts: Vec<TokenStream> = else_body.iter().map(gen_statement).collect();
                quote! { if #cond { #(#then_stmts)* } else { #(#else_stmts)* } }
            }
        }
        ir::Statement::While { condition, body } => {
            let cond = gen_expr(condition);
            let stmts: Vec<TokenStream> = body.iter().map(gen_statement).collect();
            quote! { while #cond { #(#stmts)* } }
        }
        ir::Statement::Loop { body } => {
            let stmts: Vec<TokenStream> = body.iter().map(gen_statement).collect();
            quote! { loop { #(#stmts)* } }
        }
    }
}

/// Convert an IR expression to a TokenStream.
fn gen_expr(expr: &ir::Expr) -> TokenStream {
    match expr {
        ir::Expr::Literal(lit) => match lit {
            ir::Literal::I32(v) => {
                let l = Literal::i32_unsuffixed(*v);
                quote! { #l }
            }
            ir::Literal::I64(v) => {
                let l = Literal::i64_unsuffixed(*v);
                quote! { #l }
            }
            ir::Literal::F32(v) => {
                let l = Literal::f32_unsuffixed(*v);
                quote! { #l }
            }
            ir::Literal::F64(v) => {
                let l = Literal::f64_unsuffixed(*v);
                quote! { #l }
            }
            ir::Literal::Bool(v) => {
                if *v { quote! { true } } else { quote! { false } }
            }
            ir::Literal::Str(s) => {
                let l = Literal::string(s);
                quote! { #l }
            }
        }
        ir::Expr::Var(name) => {
            // Handle references like "&key" by splitting
            let (is_ref, base) = if let Some(stripped) = name.strip_prefix('&') {
                (true, stripped)
            } else {
                (false, name.as_str())
            };
            // Handle dotted names (e.g. "state.count") as field access chains
            let parts: Vec<&str> = base.split('.').collect();
            let first = format_ident!("{}", parts[0]);
            let mut tokens = quote! { #first };
            for part in &parts[1..] {
                let field = format_ident!("{}", part);
                tokens = quote! { #tokens.#field };
            }
            if is_ref {
                quote! { &#tokens }
            } else {
                tokens
            }
        }
        ir::Expr::HostCall { module, name, args } => {
            let mod_ident = format_ident!("{}", module);
            let fn_ident = format_ident!("{}", name);
            let arg_tokens: Vec<TokenStream> = args.iter().map(gen_expr).collect();
            quote! { #mod_ident::#fn_ident(#(#arg_tokens),*) }
        }
        ir::Expr::MethodChain { receiver, calls } => {
            let mut tokens = gen_expr(receiver);
            for call in calls {
                let method = format_ident!("{}", call.name);
                let args: Vec<TokenStream> = call.args.iter().map(gen_expr).collect();
                tokens = quote! { #tokens.#method(#(#args),*) };
            }
            tokens
        }
        ir::Expr::BinOp { left, op, right } => {
            let l = gen_expr(left);
            let r = gen_expr(right);
            let op_tok = match op {
                ir::BinOp::Add => quote! { + },
                ir::BinOp::Sub => quote! { - },
                ir::BinOp::Mul => quote! { * },
                ir::BinOp::Div => quote! { / },
                ir::BinOp::Rem => quote! { % },
                ir::BinOp::BitAnd => quote! { & },
                ir::BinOp::BitOr => quote! { | },
                ir::BinOp::BitXor => quote! { ^ },
                ir::BinOp::Shl => quote! { << },
                ir::BinOp::Shr => quote! { >> },
                ir::BinOp::Eq => quote! { == },
                ir::BinOp::Ne => quote! { != },
                ir::BinOp::Lt => quote! { < },
                ir::BinOp::Le => quote! { <= },
                ir::BinOp::Gt => quote! { > },
                ir::BinOp::Ge => quote! { >= },
            };
            quote! { (#l #op_tok #r) }
        }
        ir::Expr::UnOp { op, operand } => {
            let e = gen_expr(operand);
            match op {
                ir::UnOp::Neg => quote! { (-#e) },
                ir::UnOp::Not => quote! { (!#e) },
            }
        }
        ir::Expr::MacroCall { name, args } => {
            let macro_name = format_ident!("{}", name);
            let arg_tokens: Vec<TokenStream> = args.iter().map(gen_expr).collect();
            quote! { #macro_name!(#(#arg_tokens),*) }
        }
        ir::Expr::StructLiteral { name, fields } => {
            let struct_ident = format_ident!("{}", name);
            let field_tokens: Vec<TokenStream> = fields.iter().map(|(fname, fval)| {
                let f_ident = format_ident!("{}", fname);
                let val = gen_expr(fval);
                quote! { #f_ident: #val }
            }).collect();
            quote! { #struct_ident { #(#field_tokens,)* } }
        }
        ir::Expr::EnumVariant { enum_name, variant_name, fields } => {
            let enum_ident = format_ident!("{}", enum_name);
            let variant_ident = format_ident!("{}", variant_name);
            if fields.is_empty() {
                quote! { #enum_ident::#variant_ident }
            } else {
                let arg_tokens: Vec<TokenStream> = fields.iter().map(gen_expr).collect();
                quote! { #enum_ident::#variant_ident(#(#arg_tokens),*) }
            }
        }
        ir::Expr::Raw(text) => {
            // Emit as a raw identifier token that prettyplease will preserve
            quote! { { todo!(#text) } }
        }
    }
}

/// Maps an [`ScSpecTypeDef`] to its corresponding Rust type as a [`TokenStream`].
fn gen_type_ident(spec: &ScSpecTypeDef) -> TokenStream {
    match spec {
        ScSpecTypeDef::Val => quote! { soroban_sdk::Val },
        ScSpecTypeDef::U64 => quote! { u64 },
        ScSpecTypeDef::I64 => quote! { i64 },
        ScSpecTypeDef::U32 => quote! { u32 },
        ScSpecTypeDef::I32 => quote! { i32 },
        ScSpecTypeDef::U128 => quote! { u128 },
        ScSpecTypeDef::I128 => quote! { i128 },
        ScSpecTypeDef::Bool => quote! { bool },
        ScSpecTypeDef::Symbol => quote! { Symbol },
        ScSpecTypeDef::Error => quote! { soroban_sdk::Error },
        ScSpecTypeDef::Bytes => quote! { Bytes },
        ScSpecTypeDef::Address => quote! { Address },
        ScSpecTypeDef::MuxedAddress => quote! { MuxedAddress },
        ScSpecTypeDef::String => quote! { String },
        ScSpecTypeDef::Option(o) => {
            let value_ident = gen_type_ident(&o.value_type);
            quote! { Option<#value_ident> }
        }
        ScSpecTypeDef::Result(r) => {
            let ok_ident = gen_type_ident(&r.ok_type);
            let error_ident = gen_type_ident(&r.error_type);
            quote! { Result<#ok_ident, #error_ident> }
        }
        ScSpecTypeDef::Vec(v) => {
            let element_ident = gen_type_ident(&v.element_type);
            quote! { Vec<#element_ident> }
        }
        ScSpecTypeDef::Map(m) => {
            let key_ident = gen_type_ident(&m.key_type);
            let value_ident = gen_type_ident(&m.value_type);
            quote! { Map<#key_ident, #value_ident> }
        }
        ScSpecTypeDef::Tuple(t) => {
            let type_idents = t.value_types.iter().map(|ty| gen_type_ident(ty));
            quote! { (#(#type_idents,)*) }
        }
        ScSpecTypeDef::BytesN(b) => {
            let n = Literal::u32_unsuffixed(b.n);
            quote! { BytesN<#n> }
        }
        ScSpecTypeDef::Udt(u) => {
            let ident = format_ident!("{}", u.name.to_utf8_string_lossy());
            quote! { #ident }
        }
        ScSpecTypeDef::Void => quote! { () },
        ScSpecTypeDef::Timepoint => quote! { Timepoint },
        ScSpecTypeDef::Duration => quote! { Duration },
        ScSpecTypeDef::U256 => quote! { U256 },
        ScSpecTypeDef::I256 => quote! { I256 },
    }
}

/// Walks an [`ScSpecTypeDef`] tree and inserts any SDK type names that require an import.
fn collect_sdk_types(
    spec: &ScSpecTypeDef,
    types: &mut std::collections::BTreeSet<String>,
) {
    match spec {
        ScSpecTypeDef::Symbol => { types.insert("Symbol".into()); }
        ScSpecTypeDef::Bytes => { types.insert("Bytes".into()); }
        ScSpecTypeDef::Address => { types.insert("Address".into()); }
        ScSpecTypeDef::MuxedAddress => { types.insert("MuxedAddress".into()); }
        ScSpecTypeDef::String => { types.insert("String".into()); }
        ScSpecTypeDef::Timepoint => { types.insert("Timepoint".into()); }
        ScSpecTypeDef::Duration => { types.insert("Duration".into()); }
        ScSpecTypeDef::U256 => { types.insert("U256".into()); }
        ScSpecTypeDef::I256 => { types.insert("I256".into()); }
        ScSpecTypeDef::BytesN(_) => { types.insert("BytesN".into()); }
        ScSpecTypeDef::Vec(v) => {
            types.insert("Vec".into());
            collect_sdk_types(&v.element_type, types);
        }
        ScSpecTypeDef::Map(m) => {
            types.insert("Map".into());
            collect_sdk_types(&m.key_type, types);
            collect_sdk_types(&m.value_type, types);
        }
        ScSpecTypeDef::Option(o) => {
            collect_sdk_types(&o.value_type, types);
        }
        ScSpecTypeDef::Result(r) => {
            collect_sdk_types(&r.ok_type, types);
            collect_sdk_types(&r.error_type, types);
        }
        ScSpecTypeDef::Tuple(t) => {
            for ty in t.value_types.iter() {
                collect_sdk_types(ty, types);
            }
        }
        _ => {}
    }
}
