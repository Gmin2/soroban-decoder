//! Extract repeated storage accessor/writer patterns as free helper functions.
//!
//! When the same storage key is read or written in 2+ (readers) or 3+ (writers)
//! exported functions, this module extracts the operation into a standalone
//! `fn get_X(e: &Env) -> i128` or `fn put_X(e: &Env, amount: i128)` helper,
//! replacing the inline storage access with a call to the helper. This mirrors
//! the common Soroban pattern of defining `get_reserve_a`, `put_reserve_a`, etc.
//!
//! The extraction runs as a post-processing step in [`super::generate_tokens`]
//! after all [`crate::ir::FunctionIR`] bodies have been produced by pattern
//! recognition.

use std::collections::HashMap;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::ir::{Expr, FunctionIR, Literal, MethodCall, Statement};

/// A storage accessor fingerprint: (tier, enum_name, variant_name).
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct AccessorKey {
    tier: String,
    enum_name: String,
    variant_name: String,
}

/// Extracted helper function to emit.
pub struct HelperFunction {
    pub name: String,
    pub body_stmt: Statement,
    pub is_writer: bool,
}

/// Scan all function bodies for repeated storage accessors/writers.
/// Replace repeated patterns with helper function calls.
/// Returns the helper functions to emit.
pub fn extract_helpers(functions: &mut [FunctionIR]) -> Vec<HelperFunction> {
    // Pass 1: count accessor/writer fingerprints across all functions
    let mut reader_counts: HashMap<AccessorKey, usize> = HashMap::new();
    let mut writer_counts: HashMap<AccessorKey, usize> = HashMap::new();

    for func in functions.iter() {
        count_in_stmts(&func.body, &mut reader_counts, &mut writer_counts);
    }

    // Filter to fingerprints appearing 2+ times
    let reader_helpers: HashMap<AccessorKey, String> = reader_counts.into_iter()
        .filter(|(_, count)| *count >= 2)
        .map(|(key, _)| {
            let name = format!("get_{}", to_snake(&key.variant_name));
            (key, name)
        })
        .collect();

    // Only extract writers when they appear 3+ times (conservative).
    // At 2 occurrences, writers are often part of increment/constructor
    // patterns that are better left inline.
    let writer_helpers: HashMap<AccessorKey, String> = writer_counts.into_iter()
        .filter(|(_, count)| *count >= 3)
        .map(|(key, _)| {
            let name = format!("put_{}", to_snake(&key.variant_name));
            (key, name)
        })
        .collect();

    if reader_helpers.is_empty() && writer_helpers.is_empty() {
        return vec![];
    }

    // Build helper function definitions
    let mut helpers = Vec::new();
    for (key, name) in &reader_helpers {
        helpers.push(build_reader_helper(key, name));
    }
    for (key, name) in &writer_helpers {
        helpers.push(build_writer_helper(key, name));
    }

    // Pass 2: rewrite all function bodies
    for func in functions.iter_mut() {
        func.body = rewrite_stmts(
            std::mem::take(&mut func.body),
            &reader_helpers,
            &writer_helpers,
        );
    }

    helpers
}

/// Count storage accessor/writer patterns in a statement list.
fn count_in_stmts(
    stmts: &[Statement],
    readers: &mut HashMap<AccessorKey, usize>,
    writers: &mut HashMap<AccessorKey, usize>,
) {
    for stmt in stmts {
        if let Some(key) = try_match_reader(stmt) {
            *readers.entry(key).or_insert(0) += 1;
        }
        if let Some(key) = try_match_writer(stmt) {
            *writers.entry(key).or_insert(0) += 1;
        }
        // Recurse into nested blocks
        match stmt {
            Statement::If { then_body, else_body, .. } => {
                count_in_stmts(then_body, readers, writers);
                count_in_stmts(else_body, readers, writers);
            }
            Statement::While { body, .. }
            | Statement::Loop { body }
            | Statement::ForEach { body, .. }
            | Statement::ForRange { body, .. } => {
                count_in_stmts(body, readers, writers);
            }
            _ => {}
        }
    }
}

/// Match: `let X = env.storage().TIER().get(&EnumVariant).unwrap_or(0)`
fn try_match_reader(stmt: &Statement) -> Option<AccessorKey> {
    if let Statement::Let { value: Expr::MethodChain { receiver, calls }, .. } = stmt {
        if !matches!(receiver.as_ref(), Expr::Var(n) if n == "env") {
            return None;
        }
        if calls.len() < 4 { return None; }
        if calls[0].name != "storage" { return None; }
        let tier = &calls[1].name;
        if calls[2].name != "get" { return None; }
        if calls[3].name != "unwrap_or" { return None; }

        // Key must be &EnumVariant with no fields
        let key_expr = calls[2].args.first()?;
        if let Some((enum_name, variant_name)) = extract_enum_key(key_expr) {
            return Some(AccessorKey {
                tier: tier.clone(),
                enum_name,
                variant_name,
            });
        }
    }
    None
}

/// Match: `env.storage().TIER().set(&EnumVariant, &value)`
fn try_match_writer(stmt: &Statement) -> Option<AccessorKey> {
    if let Statement::Expr(Expr::MethodChain { receiver, calls }) = stmt {
        if !matches!(receiver.as_ref(), Expr::Var(n) if n == "env") {
            return None;
        }
        if calls.len() < 3 { return None; }
        if calls[0].name != "storage" { return None; }
        let tier = &calls[1].name;
        if calls[2].name != "set" { return None; }
        if calls[2].args.len() < 2 { return None; }

        let key_expr = &calls[2].args[0];
        if let Some((enum_name, variant_name)) = extract_enum_key(key_expr) {
            return Some(AccessorKey {
                tier: tier.clone(),
                enum_name,
                variant_name,
            });
        }
    }
    None
}

/// Extract (enum_name, variant_name) from &EnumVariant { fields: [] }
fn extract_enum_key(expr: &Expr) -> Option<(String, String)> {
    match expr {
        Expr::Ref(inner) => extract_enum_key(inner),
        Expr::EnumVariant { enum_name, variant_name, fields } if fields.is_empty() => {
            Some((enum_name.clone(), variant_name.clone()))
        }
        _ => None,
    }
}

/// Build a reader helper: `fn get_X(e: &Env) -> i128 { e.storage().T().get(&K).unwrap_or(0) }`
fn build_reader_helper(key: &AccessorKey, name: &str) -> HelperFunction {
    let body_stmt = Statement::Return(Some(Expr::MethodChain {
        receiver: Box::new(Expr::Var("e".into())),
        calls: vec![
            MethodCall { name: "storage".into(), args: vec![] },
            MethodCall { name: key.tier.clone(), args: vec![] },
            MethodCall { name: "get".into(), args: vec![Expr::Ref(Box::new(
                Expr::EnumVariant {
                    enum_name: key.enum_name.clone(),
                    variant_name: key.variant_name.clone(),
                    fields: vec![],
                }
            ))] },
            MethodCall { name: "unwrap_or".into(), args: vec![Expr::Literal(Literal::I64(0))] },
        ],
    }));
    HelperFunction { name: name.into(), body_stmt, is_writer: false }
}

/// Build a writer helper: `fn put_X(e: &Env, amount: i128) { e.storage().T().set(&K, &amount) }`
fn build_writer_helper(key: &AccessorKey, name: &str) -> HelperFunction {
    let body_stmt = Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("e".into())),
        calls: vec![
            MethodCall { name: "storage".into(), args: vec![] },
            MethodCall { name: key.tier.clone(), args: vec![] },
            MethodCall { name: "set".into(), args: vec![
                Expr::Ref(Box::new(Expr::EnumVariant {
                    enum_name: key.enum_name.clone(),
                    variant_name: key.variant_name.clone(),
                    fields: vec![],
                })),
                Expr::Ref(Box::new(Expr::Var("amount".into()))),
            ] },
        ],
    });
    HelperFunction { name: name.into(), body_stmt, is_writer: true }
}

/// Rewrite statements: replace matched patterns with helper calls.
fn rewrite_stmts(
    stmts: Vec<Statement>,
    readers: &HashMap<AccessorKey, String>,
    writers: &HashMap<AccessorKey, String>,
) -> Vec<Statement> {
    stmts.into_iter().map(|stmt| {
        // Try reader replacement
        if let Some(key) = try_match_reader(&stmt) {
            if let Some(helper_name) = readers.get(&key) {
                if let Statement::Let { name, mutable, .. } = stmt {
                    return Statement::Let {
                        name,
                        mutable,
                        value: Expr::HostCall {
                            module: String::new(),
                            name: helper_name.clone(),
                            args: vec![Expr::Var("&env".into())],
                        },
                    };
                }
            }
        }
        // Try writer replacement
        if let Some(key) = try_match_writer(&stmt) {
            if let Some(helper_name) = writers.get(&key) {
                if let Statement::Expr(Expr::MethodChain { calls, .. }) = &stmt {
                    let val_arg = calls.iter()
                        .find(|c| c.name == "set")
                        .and_then(|c| c.args.get(1))
                        .cloned()
                        .unwrap_or(Expr::Literal(Literal::I64(0)));
                    return Statement::Expr(Expr::HostCall {
                        module: String::new(),
                        name: helper_name.clone(),
                        args: vec![Expr::Var("&env".into()), val_arg],
                    });
                }
            }
        }
        // Recurse into nested blocks
        match stmt {
            Statement::If { condition, then_body, else_body } => Statement::If {
                condition,
                then_body: rewrite_stmts(then_body, readers, writers),
                else_body: rewrite_stmts(else_body, readers, writers),
            },
            Statement::While { condition, body } => Statement::While {
                condition,
                body: rewrite_stmts(body, readers, writers),
            },
            Statement::Loop { body } => Statement::Loop {
                body: rewrite_stmts(body, readers, writers),
            },
            other => other,
        }
    }).collect()
}

/// Generate a helper function as a TokenStream.
pub fn gen_helper_tokens(helper: &HelperFunction) -> TokenStream {
    let fn_name = format_ident!("{}", helper.name);
    let body = super::emit::gen_statement(&helper.body_stmt);
    if helper.is_writer {
        quote! {
            fn #fn_name(e: &Env, amount: i128) {
                #body
            }
        }
    } else {
        quote! {
            fn #fn_name(e: &Env) -> i128 {
                #body
            }
        }
    }
}

/// Convert PascalCase to snake_case.
fn to_snake(s: &str) -> String {
    let mut result = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(ch.to_ascii_lowercase());
    }
    result
}
