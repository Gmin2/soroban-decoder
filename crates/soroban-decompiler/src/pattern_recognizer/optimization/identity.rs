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
