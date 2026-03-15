//! Statement and expression code emission.
//!
//! Converts IR statements and expressions into Rust token streams using
//! `quote`. Also handles function body generation with proper tail
//! expression handling, `Ok`/`Err` wrapping for `Result` types, and
//! undeclared local variable declarations.

use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use stellar_xdr::curr::{ScSpecFunctionV0, ScSpecTypeDef};

use crate::ir;
use super::types::gen_type_ident;

pub(super) fn gen_function(spec: &ScSpecFunctionV0, body_ir: Option<&ir::FunctionIR>) -> TokenStream {
    gen_function_inner(spec, body_ir, false)
}

/// Generate a trait impl function (`fn` instead of `pub fn`, with `#[allow(non_snake_case)]`).
pub(super) fn gen_trait_function(spec: &ScSpecFunctionV0, body_ir: Option<&ir::FunctionIR>) -> TokenStream {
    gen_function_inner(spec, body_ir, true)
}

fn gen_function_inner(spec: &ScSpecFunctionV0, body_ir: Option<&ir::FunctionIR>, is_trait_fn: bool) -> TokenStream {
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

    let is_result = spec.outputs.to_option()
        .map_or(false, |t| matches!(t, ScSpecTypeDef::Result(_)));

    let body = match body_ir {
        Some(func_ir) => {
            let ends_with_return = func_ir.body.last()
                .map_or(false, |s| matches!(s, ir::Statement::Return(Some(_))));
            let ends_with_complete_if = is_result && matches!(
                func_ir.body.last(),
                Some(ir::Statement::If { then_body, else_body, .. })
                if !else_body.is_empty()
                    && then_body.last().map_or(false, |s| matches!(s, ir::Statement::Return(Some(_))))
                    && else_body.last().map_or(false, |s| matches!(s, ir::Statement::Return(Some(_))))
            );
            if ends_with_complete_if && !is_void {
                let init_stmts: Vec<TokenStream> = func_ir.body[..func_ir.body.len() - 1]
                    .iter().map(gen_statement).collect();
                let last_if = gen_result_if_statement(func_ir.body.last().unwrap());
                quote! { #(#init_stmts)* #last_if }
            } else if ends_with_return && !is_void {
                let init_stmts: Vec<TokenStream> = func_ir.body[..func_ir.body.len() - 1]
                    .iter().map(gen_statement).collect();
                let tail_expr = match func_ir.body.last().unwrap() {
                    ir::Statement::Return(Some(e)) => gen_expr(e),
                    _ => unreachable!(),
                };
                if is_result {
                    let is_error_return = match func_ir.body.last() {
                        Some(ir::Statement::Return(Some(ir::Expr::Var(v)))) =>
                            v.starts_with("__contract_error_"),
                        _ => false,
                    };
                    if is_error_return {
                        quote! { #(#init_stmts)* Err(#tail_expr) }
                    } else {
                        quote! { #(#init_stmts)* Ok(#tail_expr) }
                    }
                } else {
                    quote! { #(#init_stmts)* #tail_expr }
                }
            } else if ends_with_return || is_void {
                let body_stmts = if is_void {
                    let mut s = func_ir.body.clone();
                    if matches!(s.last(),
                        Some(ir::Statement::Return(Some(ir::Expr::Literal(ir::Literal::Unit))))
                        | Some(ir::Statement::Return(None))
                    ) {
                        s.pop();
                    }
                    s
                } else {
                    func_ir.body.clone()
                };
                let stmts: Vec<TokenStream> = body_stmts.iter().map(gen_statement).collect();
                quote! { #(#stmts)* }
            } else if !is_void {
                let last_let_name = func_ir.body.iter().rev().find_map(|s| {
                    if let ir::Statement::Let { name, .. } = s { Some(name.clone()) } else { None }
                });
                if let Some(name) = last_let_name {
                    let stmts: Vec<TokenStream> = func_ir.body.iter().map(gen_statement).collect();
                    let safe_name = name.replace('.', "_").replace('[', "_").replace(']', "");
                    let ident = format_ident!("{}", safe_name);
                    if is_result {
                        quote! { #(#stmts)* Ok(#ident) }
                    } else {
                        quote! { #(#stmts)* #ident }
                    }
                } else {
                    let stmts: Vec<TokenStream> = func_ir.body.iter().map(gen_statement).collect();
                    if is_result {
                        quote! { #(#stmts)* Ok(Default::default()) }
                    } else {
                        quote! { #(#stmts)* Default::default() }
                    }
                }
            } else {
                let stmts: Vec<TokenStream> = func_ir.body.iter().map(gen_statement).collect();
                quote! { #(#stmts)* }
            }
        }
        None => {
            if is_void {
                quote! { /* body could not be decompiled */ }
            } else if is_result {
                quote! { Ok(Default::default()) /* body could not be decompiled */ }
            } else {
                quote! { Default::default() /* body could not be decompiled */ }
            }
        },
    };

    // Collect undeclared `local_N` references and emit declarations.
    let local_decls = if let Some(func_ir) = body_ir {
        let param_names: std::collections::HashSet<String> = spec.inputs.iter()
            .map(|i| i.name.to_utf8_string_lossy())
            .collect();
        let mut locals = std::collections::BTreeSet::new();
        for stmt in &func_ir.body {
            collect_local_refs_stmt(stmt, &mut locals);
        }
        locals.remove("env");
        for p in &param_names { locals.remove(p.as_str()); }
        let mut declared = std::collections::HashSet::new();
        for stmt in &func_ir.body {
            if let ir::Statement::Let { name, .. } = stmt {
                declared.insert(name.replace('.', "_").replace('[', "_").replace(']', ""));
            }
        }
        for d in &declared { locals.remove(d.as_str()); }
        let decls: Vec<TokenStream> = locals.into_iter().map(|name| {
            let ident = format_ident!("{}", name);
            quote! { let #ident = Default::default(); /* unresolved WASM local */ }
        }).collect();
        quote! { #(#decls)* }
    } else {
        quote! {}
    };

    if is_trait_fn {
        quote! {
            #[allow(non_snake_case)]
            fn #fn_ident(env: Env, #(#fn_inputs),*) #fn_output {
                #local_decls
                #body
            }
        }
    } else {
        quote! {
            pub fn #fn_ident(env: Env, #(#fn_inputs),*) #fn_output {
                #local_decls
                #body
            }
        }
    }
}

/// Collect `local_N` variable references from an IR statement.
fn collect_local_refs_stmt(stmt: &ir::Statement, locals: &mut std::collections::BTreeSet<String>) {
    match stmt {
        ir::Statement::Let { value, .. } => collect_local_refs_expr(value, locals),
        ir::Statement::Assign { target, value } => {
            collect_local_refs_expr(target, locals);
            collect_local_refs_expr(value, locals);
        }
        ir::Statement::Expr(e) => collect_local_refs_expr(e, locals),
        ir::Statement::Return(Some(e)) => collect_local_refs_expr(e, locals),
        ir::Statement::Return(None) => {}
        ir::Statement::If { condition, then_body, else_body } => {
            collect_local_refs_expr(condition, locals);
            for s in then_body { collect_local_refs_stmt(s, locals); }
            for s in else_body { collect_local_refs_stmt(s, locals); }
        }
        ir::Statement::While { condition, body } => {
            collect_local_refs_expr(condition, locals);
            for s in body { collect_local_refs_stmt(s, locals); }
        }
        ir::Statement::Loop { body } => {
            for s in body { collect_local_refs_stmt(s, locals); }
        }
        ir::Statement::ForEach { collection, body, .. } => {
            collect_local_refs_expr(collection, locals);
            for s in body { collect_local_refs_stmt(s, locals); }
        }
        ir::Statement::ForRange { bound, body, .. } => {
            collect_local_refs_expr(bound, locals);
            for s in body { collect_local_refs_stmt(s, locals); }
        }
    }
}

/// Collect `local_N` variable references from an IR expression.
fn collect_local_refs_expr(expr: &ir::Expr, locals: &mut std::collections::BTreeSet<String>) {
    match expr {
        ir::Expr::Var(name) => {
            let base = name.strip_prefix('&').unwrap_or(name);
            let root = base.split('.').next().unwrap_or(base);
            if root.starts_with("local_") {
                locals.insert(root.to_string());
            }
        }
        ir::Expr::BinOp { left, right, .. } => {
            collect_local_refs_expr(left, locals);
            collect_local_refs_expr(right, locals);
        }
        ir::Expr::UnOp { operand, .. } => collect_local_refs_expr(operand, locals),
        ir::Expr::MethodChain { receiver, calls } => {
            collect_local_refs_expr(receiver, locals);
            for c in calls { for a in &c.args { collect_local_refs_expr(a, locals); } }
        }
        ir::Expr::MacroCall { args, .. } => {
            for a in args { collect_local_refs_expr(a, locals); }
        }
        ir::Expr::HostCall { args, .. } => {
            for a in args { collect_local_refs_expr(a, locals); }
        }
        ir::Expr::StructLiteral { fields, .. } => {
            for (_, v) in fields { collect_local_refs_expr(v, locals); }
        }
        ir::Expr::EnumVariant { fields, .. } => {
            for f in fields { collect_local_refs_expr(f, locals); }
        }
        ir::Expr::Ref(inner) => collect_local_refs_expr(inner, locals),
        ir::Expr::Literal(_) | ir::Expr::Raw(_) => {}
    }
}

/// Generate a Result-returning If statement where each branch's final Return
/// gets wrapped in Ok() or Err() based on whether the value is a contract error.
fn gen_result_if_statement(stmt: &ir::Statement) -> TokenStream {
    if let ir::Statement::If { condition, then_body, else_body } = stmt {
        let cond = gen_expr(condition);

        let gen_branch = |body: &[ir::Statement]| -> Vec<TokenStream> {
            let n = body.len();
            if n == 0 { return vec![]; }
            let mut stmts: Vec<TokenStream> = body[..n - 1].iter().map(gen_statement).collect();
            if let Some(ir::Statement::Return(Some(e))) = body.last() {
                let expr = gen_expr(e);
                let is_error = matches!(e, ir::Expr::Var(v) if v.starts_with("__contract_error_"));
                if is_error {
                    stmts.push(quote! { Err(#expr) });
                } else {
                    stmts.push(quote! { Ok(#expr) });
                }
            }
            stmts
        };

        let then_stmts = gen_branch(then_body);
        let else_stmts = gen_branch(else_body);

        if else_stmts.is_empty() {
            quote! { if #cond { #(#then_stmts)* } }
        } else {
            quote! { if #cond { #(#then_stmts)* } else { #(#else_stmts)* } }
        }
    } else {
        gen_statement(stmt)
    }
}

/// Convert an IR statement to a TokenStream.
pub(super) fn gen_statement(stmt: &ir::Statement) -> TokenStream {
    match stmt {
        ir::Statement::Let { name, mutable, value } => {
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
        ir::Statement::ForEach { var_name, collection, body } => {
            let var_ident = format_ident!("{}", var_name);
            let coll = gen_expr(collection);
            let stmts: Vec<TokenStream> = body.iter().map(gen_statement).collect();
            quote! { for #var_ident in #coll.iter() { #(#stmts)* } }
        }
        ir::Statement::ForRange { var_name, bound, body } => {
            let var_ident = format_ident!("{}", var_name);
            let bound_expr = gen_expr(bound);
            let stmts: Vec<TokenStream> = body.iter().map(gen_statement).collect();
            quote! { for #var_ident in 0..#bound_expr { #(#stmts)* } }
        }
    }
}

/// Convert an IR expression to a TokenStream.
pub(super) fn gen_expr(expr: &ir::Expr) -> TokenStream {
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
            ir::Literal::Unit => {
                quote! { () }
            }
        }
        ir::Expr::Var(name) => {
            let (is_ref, base) = if let Some(stripped) = name.strip_prefix('&') {
                (true, stripped)
            } else {
                (false, name.as_str())
            };
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
            let arg_tokens: Vec<TokenStream> = args.iter().map(gen_expr).collect();
            // Free function call (extracted helper): empty module
            if module.is_empty() {
                let fn_ident = format_ident!("{}", name);
                return quote! { #fn_ident(#(#arg_tokens),*) };
            }
            // Support path-style modules like "token::Client"
            if module.contains("::") {
                let path: TokenStream = module.parse().unwrap_or_else(|_| {
                    let ident = format_ident!("{}", module.replace("::", "_"));
                    quote! { #ident }
                });
                let fn_ident = format_ident!("{}", name);
                quote! { #path::#fn_ident(#(#arg_tokens),*) }
            } else {
                let mod_ident = format_ident!("{}", module);
                let fn_ident = format_ident!("{}", name);
                quote! { #mod_ident::#fn_ident(#(#arg_tokens),*) }
            }
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
                ir::BinOp::AddAssign => quote! { += },
            };
            if matches!(op, ir::BinOp::AddAssign) {
                // Compound assignment: no parens, emit as statement-like expression
                quote! { #l #op_tok #r }
            } else if matches!(op,
                ir::BinOp::Eq | ir::BinOp::Ne | ir::BinOp::Lt
                | ir::BinOp::Le | ir::BinOp::Gt | ir::BinOp::Ge
            ) {
                // Comparison operators: no outer parens needed.
                // Rust's `if a < b` doesn't need `if (a < b)`.
                quote! { #l #op_tok #r }
            } else {
                quote! { (#l #op_tok #r) }
            }
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
            if name == "vec" {
                quote! { #macro_name![#(#arg_tokens),*] }
            } else {
                quote! { #macro_name!(#(#arg_tokens),*) }
            }
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
        ir::Expr::Ref(inner) => {
            let e = gen_expr(inner);
            quote! { &#e }
        }
        ir::Expr::Raw(text) => {
            // If the Raw text starts with "&[" or other meaningful
            // content, render it literally. Only fall back to
            // Default::default() for placeholder comments.
            if text.starts_with("&[") || text.starts_with("b\"") {
                let ts: proc_macro2::TokenStream = text.parse().unwrap_or_else(|_| {
                    quote! { Default::default() }
                });
                ts
            } else {
                quote! { Default::default() }
            }
        }
    }
}
