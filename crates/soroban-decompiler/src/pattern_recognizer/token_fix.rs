//! Token address void fix.
//!
//! When `token::Client::new(&env, &())` appears (the address resolved to void
//! because the struct field was untracked), this module substitutes the address
//! with a preceding storage-loaded struct's `.token` field.

use crate::ir::{Expr, Literal, Statement};

/// Fix void token addresses in token::Client::new(&env, &()) calls.
///
/// When the token address resolves to () (from untracked struct field access),
/// look for a preceding storage-loaded struct variable that has a "token" field
/// and substitute `var.token`.
pub(super) fn fix_void_token_addresses(stmts: Vec<Statement>) -> Vec<Statement> {
    // Find the name of a storage-loaded struct variable.
    let mut storage_var: Option<String> = None;
    for stmt in &stmts {
        if let Statement::Let { name, value, .. } = stmt {
            // Pattern: let val = env.storage().*.get(&key).unwrap_or_default()
            if let Expr::MethodChain { calls, .. } = value {
                let has_get = calls.iter().any(|c| c.name == "get");
                let has_unwrap = calls.iter().any(|c| c.name.starts_with("unwrap"));
                if has_get && has_unwrap {
                    storage_var = Some(name.clone());
                }
            }
        }
    }

    let Some(var_name) = storage_var else {
        return stmts;
    };

    // Replace &() with &var.token in token::Client::new calls
    stmts.into_iter().map(|stmt| {
        fix_void_token_in_stmt(stmt, &var_name)
    }).collect()
}

fn fix_void_token_in_stmt(stmt: Statement, var_name: &str) -> Statement {
    match stmt {
        Statement::Let { name, mutable, value } => Statement::Let {
            name, mutable, value: fix_void_token_in_expr(value, var_name),
        },
        Statement::Expr(e) => Statement::Expr(fix_void_token_in_expr(e, var_name)),
        Statement::If { condition, then_body, else_body } => Statement::If {
            condition,
            then_body: then_body.into_iter().map(|s| fix_void_token_in_stmt(s, var_name)).collect(),
            else_body: else_body.into_iter().map(|s| fix_void_token_in_stmt(s, var_name)).collect(),
        },
        other => other,
    }
}

fn fix_void_token_in_expr(expr: Expr, var_name: &str) -> Expr {
    match expr {
        // Match: token::Client::new(&env, &())
        Expr::MethodChain { receiver, calls } => {
            let new_receiver = if let Expr::HostCall { module, name, args } = receiver.as_ref() {
                if module == "token::Client" && name == "new" {
                    // Check if second arg is &() (void)
                    let is_void_addr = args.get(1).map_or(false, |a| matches!(a,
                        Expr::Ref(inner) if matches!(inner.as_ref(), Expr::Literal(Literal::Unit))
                    ));
                    if is_void_addr {
                        let mut new_args = args.clone();
                        new_args[1] = Expr::Ref(Box::new(
                            Expr::Var(format!("{}.token", var_name)),
                        ));
                        Some(Box::new(Expr::HostCall {
                            module: module.clone(),
                            name: name.clone(),
                            args: new_args,
                        }))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };
            Expr::MethodChain {
                receiver: new_receiver.unwrap_or(receiver),
                calls,
            }
        }
        other => other,
    }
}
