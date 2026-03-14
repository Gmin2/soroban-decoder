use crate::ir::{Expr, Statement};

use super::expr_has_side_effects;

/// Remove `Let` bindings whose names are never referenced by subsequent statements.
///
/// A binding is "dead" if its name never appears in any expression in the
/// remaining statements (including nested if/else/loop bodies) or the return.
/// Side-effectful statements (Expr, Assign, Return, method calls in Let values)
/// are always kept.
pub fn eliminate_dead_vars(stmts: Vec<Statement>) -> Vec<Statement> {
    // Collect all variable names referenced across ALL statements.
    let mut referenced = std::collections::HashSet::new();
    for stmt in &stmts {
        collect_stmt_refs(stmt, &mut referenced);
    }

    eliminate_dead_vars_with_refs(stmts, &referenced)
}

/// Inner recursive DCE that uses pre-collected references.
fn eliminate_dead_vars_with_refs(
    stmts: Vec<Statement>,
    referenced: &std::collections::HashSet<String>,
) -> Vec<Statement> {
    stmts.into_iter().filter_map(|stmt| {
        match stmt {
            Statement::Let { name, value, mutable } => {
                // Sanitize name the same way codegen does for matching
                let check_name = name.replace('.', "_").replace('[', "_").replace(']', "");
                if referenced.contains(&name) || referenced.contains(&check_name) {
                    return Some(Statement::Let { name, value, mutable });
                }
                // Also check dotted field access: "state.count" is referenced
                // when "state" appears as a receiver in field access chains.
                if name.contains('.') {
                    let base = name.split('.').next().unwrap_or(&name);
                    if referenced.contains(base) {
                        return Some(Statement::Let { name, value, mutable });
                    }
                }
                // Keep if the value has side effects
                if expr_has_side_effects(&value) {
                    Some(Statement::Let { name, value, mutable })
                } else {
                    None
                }
            }
            // Recurse into nested blocks.
            Statement::If { condition, then_body, else_body } => {
                let then_clean = eliminate_dead_vars_with_refs(then_body, referenced);
                let else_clean = eliminate_dead_vars_with_refs(else_body, referenced);
                // Drop empty if blocks.
                if then_clean.is_empty() && else_clean.is_empty() {
                    None
                } else {
                    Some(Statement::If {
                        condition,
                        then_body: then_clean,
                        else_body: else_clean,
                    })
                }
            }
            Statement::While { condition, body } => {
                Some(Statement::While {
                    condition,
                    body: eliminate_dead_vars_with_refs(body, referenced),
                })
            }
            Statement::Loop { body } => {
                Some(Statement::Loop {
                    body: eliminate_dead_vars_with_refs(body, referenced),
                })
            }
            Statement::ForEach { var_name, collection, body } => {
                Some(Statement::ForEach {
                    var_name,
                    collection,
                    body: eliminate_dead_vars_with_refs(body, referenced),
                })
            }
            Statement::ForRange { var_name, bound, body } => {
                Some(Statement::ForRange {
                    var_name,
                    bound,
                    body: eliminate_dead_vars_with_refs(body, referenced),
                })
            }
            other => Some(other),
        }
    }).collect()
}

/// Collect all variable names referenced in a statement's expressions.
pub(super) fn collect_stmt_refs(stmt: &Statement, refs: &mut std::collections::HashSet<String>) {
    match stmt {
        Statement::Let { value, .. } => collect_expr_refs(value, refs),
        Statement::Assign { target, value } => {
            collect_expr_refs(target, refs);
            collect_expr_refs(value, refs);
        }
        Statement::Expr(e) => collect_expr_refs(e, refs),
        Statement::Return(Some(e)) => collect_expr_refs(e, refs),
        Statement::Return(None) => {}
        Statement::If { condition, then_body, else_body } => {
            collect_expr_refs(condition, refs);
            for s in then_body { collect_stmt_refs(s, refs); }
            for s in else_body { collect_stmt_refs(s, refs); }
        }
        Statement::While { condition, body } => {
            collect_expr_refs(condition, refs);
            for s in body { collect_stmt_refs(s, refs); }
        }
        Statement::Loop { body } => {
            for s in body { collect_stmt_refs(s, refs); }
        }
        Statement::ForEach { collection, body, .. } => {
            collect_expr_refs(collection, refs);
            for s in body { collect_stmt_refs(s, refs); }
        }
        Statement::ForRange { bound, body, .. } => {
            collect_expr_refs(bound, refs);
            for s in body { collect_stmt_refs(s, refs); }
        }
    }
}

/// Collect all variable names referenced in an expression.
fn collect_expr_refs(expr: &Expr, refs: &mut std::collections::HashSet<String>) {
    match expr {
        Expr::Var(name) => {
            let bare = name.strip_prefix('&').unwrap_or(name);
            refs.insert(bare.to_string());
            // For dotted names like "state.count", also mark the base
            if bare.contains('.') {
                if let Some(base) = bare.split('.').next() {
                    refs.insert(base.to_string());
                }
            }
        }
        Expr::BinOp { left, right, .. } => {
            collect_expr_refs(left, refs);
            collect_expr_refs(right, refs);
        }
        Expr::UnOp { operand, .. } => collect_expr_refs(operand, refs),
        Expr::MethodChain { receiver, calls } => {
            collect_expr_refs(receiver, refs);
            for call in calls {
                for arg in &call.args { collect_expr_refs(arg, refs); }
            }
        }
        Expr::HostCall { args, .. } => {
            for arg in args { collect_expr_refs(arg, refs); }
        }
        Expr::MacroCall { args, .. } => {
            for arg in args { collect_expr_refs(arg, refs); }
        }
        Expr::StructLiteral { fields, .. } => {
            for (_, val) in fields { collect_expr_refs(val, refs); }
        }
        Expr::EnumVariant { fields, .. } => {
            for f in fields { collect_expr_refs(f, refs); }
        }
        Expr::Ref(inner) => collect_expr_refs(inner, refs),
        Expr::Literal(_) | Expr::Raw(_) => {}
    }
}
