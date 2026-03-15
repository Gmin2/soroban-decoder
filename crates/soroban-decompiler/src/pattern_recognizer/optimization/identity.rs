//! Identity elimination, single-use inlining, and client call splitting.
//!
//! This module contains three related optimization passes that clean up
//! redundant variable bindings produced by the WASM decompilation pipeline:
//!
//! - **Identity elimination**: Removes `let x = y;` copy bindings and rewrites
//!   all references of `x` to `y`, including transitive chains (`a = b = c`).
//! - **Single-use inlining**: When a binding is used exactly once as a method
//!   receiver in the next statement, inlines the value directly to produce
//!   fluent method chains.
//! - **Client splitting**: Splits `contract_client::new(&env, &addr).method()`
//!   into a separate `let client = ...` binding followed by `client.method()`,
//!   matching idiomatic Soroban patterns.

use std::collections::HashMap;

use crate::ir::{Expr, Statement};

use super::rename_stmt_vars;

/// Remove `let x = y;` bindings where the value is just a variable reference.
///
/// Rewrites all subsequent references of `x` to `y` and drops the binding.
/// This eliminates patterns like `let swap_spec = item;` that arise from
/// WASM local copies. Recurses into nested blocks.
pub fn eliminate_identity_bindings(stmts: Vec<Statement>) -> Vec<Statement> {
    eliminate_identity_bindings_inner(stmts, &HashMap::new())
}

fn eliminate_identity_bindings_inner(
    stmts: Vec<Statement>,
    inherited_renames: &HashMap<String, String>,
) -> Vec<Statement> {
    let mut renames = inherited_renames.clone();

    // First pass: find identity bindings at this level.
    for stmt in &stmts {
        if let Statement::Let { name, value, .. } = stmt {
            if let Expr::Var(ref var_name) = value {
                let bare = var_name.strip_prefix('&').unwrap_or(var_name);
                renames.insert(name.clone(), bare.to_string());
            }
        }
    }

    // Resolve transitive renames: if a->b and b->c, then a->c.
    let mut resolved: HashMap<String, String> = HashMap::new();
    for (from, to) in &renames {
        let mut target = to.clone();
        let mut seen = std::collections::HashSet::new();
        seen.insert(from.clone());
        while let Some(next) = renames.get(&target) {
            if seen.contains(next) {
                break;
            }
            seen.insert(target.clone());
            target = next.clone();
        }
        resolved.insert(from.clone(), target);
    }

    // Second pass: remove identity bindings, rewrite references, and recurse.
    // Always recurse into nested blocks even if no renames at this level.
    stmts.into_iter()
        .filter(|stmt| {
            if !resolved.is_empty() {
                if let Statement::Let { name, value, .. } = stmt {
                    if let Expr::Var(_) = value {
                        return !resolved.contains_key(name);
                    }
                }
            }
            true
        })
        .map(|stmt| {
            let renamed = if resolved.is_empty() { stmt } else { rename_stmt_vars(stmt, &resolved) };
            // Recurse into nested blocks.
            match renamed {
                Statement::If { condition, then_body, else_body } => Statement::If {
                    condition,
                    then_body: eliminate_identity_bindings_inner(then_body, &resolved),
                    else_body: eliminate_identity_bindings_inner(else_body, &resolved),
                },
                Statement::While { condition, body } => Statement::While {
                    condition,
                    body: eliminate_identity_bindings_inner(body, &resolved),
                },
                Statement::Loop { body } => Statement::Loop {
                    body: eliminate_identity_bindings_inner(body, &resolved),
                },
                Statement::ForEach { var_name, collection, body } => Statement::ForEach {
                    var_name,
                    collection,
                    body: eliminate_identity_bindings_inner(body, &resolved),
                },
                Statement::ForRange { var_name, bound, body } => Statement::ForRange {
                    var_name,
                    bound,
                    body: eliminate_identity_bindings_inner(body, &resolved),
                },
                other => other,
            }
        })
        .collect()
}

/// Inline single-use bindings where a `let x = expr; x.method(args)` can be
/// collapsed to `expr.method(args)`. This handles patterns like:
///   let contract_addr = env.current_contract_address();
///   contract_addr.require_auth();
/// → env.current_contract_address().require_auth();
pub fn inline_single_use_bindings(stmts: Vec<Statement>) -> Vec<Statement> {
    let mut result = Vec::with_capacity(stmts.len());
    let mut i = 0;
    while i < stmts.len() {
        if i + 1 < stmts.len() {
            if let Statement::Let { name, value, mutable: false } = &stmts[i] {
                // Check if next stmt is a bare return/expr of this variable
                // (let x = expr; x) → just expr
                if is_bare_var_use(&stmts[i + 1], name) {
                    let rest = &stmts[i + 2..];
                    if !refs_name_in_stmts(rest, name) {
                        // Replace the bare var with the value directly
                        result.push(substitute_var_in_stmt(&stmts[i + 1], name, value));
                        i += 2;
                        continue;
                    }
                }
                // Check if `name` is used exactly once as a method receiver in the next stmt.
                // Skip "client" bindings — they were deliberately split by split_client_calls.
                if name == "client" {
                    // Don't inline client bindings back
                } else if let Some(inlined) = try_inline_receiver(&stmts[i + 1], name, value) {
                    let rest = &stmts[i + 2..];
                    if !refs_name_in_stmts(rest, name) {
                        result.push(inlined);
                        i += 2;
                        continue;
                    }
                }
            }
        }
        // Recurse into nested blocks
        result.push(match stmts[i].clone() {
            Statement::If { condition, then_body, else_body } => Statement::If {
                condition,
                then_body: inline_single_use_bindings(then_body),
                else_body: inline_single_use_bindings(else_body),
            },
            other => other,
        });
        i += 1;
    }
    result
}

/// Check if a statement is just a bare use of a variable (return x, or expr x).
fn is_bare_var_use(stmt: &Statement, name: &str) -> bool {
    match stmt {
        Statement::Expr(Expr::Var(n)) => n == name,
        Statement::Return(Some(Expr::Var(n))) => n == name,
        _ => false,
    }
}

/// Substitute a variable with a value in a statement.
fn substitute_var_in_stmt(stmt: &Statement, name: &str, value: &Expr) -> Statement {
    match stmt {
        Statement::Expr(Expr::Var(n)) if n == name => Statement::Expr(value.clone()),
        Statement::Return(Some(Expr::Var(n))) if n == name => Statement::Return(Some(value.clone())),
        other => other.clone(),
    }
}

/// Try to inline a value as the receiver in a method chain statement.
fn try_inline_receiver(stmt: &Statement, name: &str, value: &Expr) -> Option<Statement> {
    match stmt {
        // x.method(args) → value.method(args)
        Statement::Expr(Expr::MethodChain { receiver, calls }) => {
            if matches!(receiver.as_ref(), Expr::Var(n) if n == name) {
                return Some(Statement::Expr(Expr::MethodChain {
                    receiver: Box::new(value.clone()),
                    calls: calls.clone(),
                }));
            }
            None
        }
        // let y = x.method(args) → let y = value.method(args)
        Statement::Let { name: let_name, mutable, value: Expr::MethodChain { receiver, calls } } => {
            if matches!(receiver.as_ref(), Expr::Var(n) if n == name) {
                return Some(Statement::Let {
                    name: let_name.clone(),
                    mutable: *mutable,
                    value: Expr::MethodChain {
                        receiver: Box::new(value.clone()),
                        calls: calls.clone(),
                    },
                });
            }
            None
        }
        _ => None,
    }
}

/// Split chained client constructor calls into two statements:
///   `contract_client::new(&env, &addr).method(&args)`
/// →
///   `let client = contract_client::new(&env, &addr);`
///   `client.method(&args)`
/// This matches the idiomatic Soroban pattern of binding the client first.
pub fn split_client_calls(stmts: Vec<Statement>) -> Vec<Statement> {
    let mut result = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        match &stmt {
            // Match: let X = HostCall(module::new).method(args)  or bare expr
            Statement::Let { name, mutable, value } => {
                if let Some((client_expr, method_call)) = try_split_client_chain(value) {
                    // Emit: let client = module::new(&env, &addr);
                    result.push(Statement::Let {
                        name: "client".into(),
                        mutable: false,
                        value: client_expr,
                    });
                    // Emit: let X = client.method(&args);
                    result.push(Statement::Let {
                        name: name.clone(),
                        mutable: *mutable,
                        value: Expr::MethodChain {
                            receiver: Box::new(Expr::Var("client".into())),
                            calls: vec![method_call],
                        },
                    });
                    continue;
                }
            }
            Statement::Expr(value) => {
                if let Some((client_expr, method_call)) = try_split_client_chain(value) {
                    result.push(Statement::Let {
                        name: "client".into(),
                        mutable: false,
                        value: client_expr,
                    });
                    result.push(Statement::Expr(Expr::MethodChain {
                        receiver: Box::new(Expr::Var("client".into())),
                        calls: vec![method_call],
                    }));
                    continue;
                }
            }
            _ => {}
        }
        // Recurse into nested blocks
        result.push(match stmt {
            Statement::If { condition, then_body, else_body } => Statement::If {
                condition,
                then_body: split_client_calls(then_body),
                else_body: split_client_calls(else_body),
            },
            other => other,
        });
    }
    result
}

/// Try to split a HostCall.method() chain into (HostCall, method).
/// Only matches contract_client::new patterns (non-token clients).
fn try_split_client_chain(expr: &Expr) -> Option<(Expr, crate::ir::MethodCall)> {
    if let Expr::MethodChain { receiver, calls } = expr {
        if calls.len() == 1 {
            if let Expr::HostCall { module, name, .. } = receiver.as_ref() {
                // Only split contract_client (not token::Client which is better chained)
                if module == "contract_client" && name == "new" {
                    return Some((*receiver.clone(), calls[0].clone()));
                }
            }
        }
    }
    None
}

/// Check if a name appears in any expression across multiple statements.
fn refs_name_in_stmts(stmts: &[Statement], name: &str) -> bool {
    stmts.iter().any(|s| refs_name_in_stmt(s, name))
}

fn refs_name_in_stmt(stmt: &Statement, name: &str) -> bool {
    match stmt {
        Statement::Let { value, .. } => refs_name_in_expr(value, name),
        Statement::Expr(e) => refs_name_in_expr(e, name),
        Statement::Return(Some(e)) => refs_name_in_expr(e, name),
        Statement::If { condition, then_body, else_body } => {
            refs_name_in_expr(condition, name)
                || refs_name_in_stmts(then_body, name)
                || refs_name_in_stmts(else_body, name)
        }
        _ => false,
    }
}

fn refs_name_in_expr(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::Var(n) => n == name,
        Expr::BinOp { left, right, .. } => refs_name_in_expr(left, name) || refs_name_in_expr(right, name),
        Expr::UnOp { operand, .. } => refs_name_in_expr(operand, name),
        Expr::Ref(inner) => refs_name_in_expr(inner, name),
        Expr::MethodChain { receiver, calls } => {
            refs_name_in_expr(receiver, name)
                || calls.iter().any(|c| c.args.iter().any(|a| refs_name_in_expr(a, name)))
        }
        Expr::HostCall { args, .. } | Expr::MacroCall { args, .. } => {
            args.iter().any(|a| refs_name_in_expr(a, name))
        }
        _ => false,
    }
}
