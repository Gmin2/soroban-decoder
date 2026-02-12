/// IR optimization passes.
///
/// Common subexpression elimination, dead variable elimination,
/// and variable renaming utilities.

use std::collections::HashMap;

use crate::ir::{Expr, MethodCall, Statement};

/// Remove duplicate Let bindings that produce the same expression value.
///
/// When `let sym_1 = Symbol::new(&env, "Counter")` duplicates an earlier
/// `let sym = Symbol::new(&env, "Counter")`, remove `sym_1` and rewrite
/// all references to `sym_1` as `sym`.
pub(super) fn eliminate_common_subexprs(stmts: Vec<Statement>) -> Vec<Statement> {
    // Map from expression (via PartialEq) to the first binding name.
    let mut seen: Vec<(Expr, String)> = Vec::new();
    // Map from duplicate name → original name.
    let mut renames: HashMap<String, String> = HashMap::new();

    // First pass: identify duplicates.
    for stmt in &stmts {
        if let Statement::Let { name, value, .. } = stmt {
            // Only CSE side-effect-free expressions
            if !expr_has_side_effects(value) {
                // Apply existing renames to the value for comparison
                let normalized = rename_expr_vars(value, &renames);
                if let Some((_, first_name)) = seen.iter().find(|(expr, _)| *expr == normalized) {
                    renames.insert(name.clone(), first_name.clone());
                } else {
                    seen.push((normalized, name.clone()));
                }
            }
        }
    }

    if renames.is_empty() {
        return stmts;
    }

    // Second pass: remove duplicate bindings and rewrite references.
    stmts.into_iter()
        .filter(|stmt| {
            if let Statement::Let { name, .. } = stmt {
                !renames.contains_key(name)
            } else {
                true
            }
        })
        .map(|stmt| rename_stmt_vars(stmt, &renames))
        .collect()
}

/// Rewrite variable references in a statement according to the rename map.
fn rename_stmt_vars(stmt: Statement, renames: &HashMap<String, String>) -> Statement {
    match stmt {
        Statement::Let { name, mutable, value } => Statement::Let {
            name,
            mutable,
            value: rename_expr_vars(&value, renames),
        },
        Statement::Assign { target, value } => Statement::Assign {
            target: rename_expr_vars(&target, renames),
            value: rename_expr_vars(&value, renames),
        },
        Statement::Expr(e) => Statement::Expr(rename_expr_vars(&e, renames)),
        Statement::Return(Some(e)) => Statement::Return(Some(rename_expr_vars(&e, renames))),
        Statement::Return(None) => Statement::Return(None),
        Statement::If { condition, then_body, else_body } => Statement::If {
            condition: rename_expr_vars(&condition, renames),
            then_body: then_body.into_iter().map(|s| rename_stmt_vars(s, renames)).collect(),
            else_body: else_body.into_iter().map(|s| rename_stmt_vars(s, renames)).collect(),
        },
        Statement::While { condition, body } => Statement::While {
            condition: rename_expr_vars(&condition, renames),
            body: body.into_iter().map(|s| rename_stmt_vars(s, renames)).collect(),
        },
        Statement::Loop { body } => Statement::Loop {
            body: body.into_iter().map(|s| rename_stmt_vars(s, renames)).collect(),
        },
    }
}

/// Rewrite variable references in an expression according to the rename map.
fn rename_expr_vars(expr: &Expr, renames: &HashMap<String, String>) -> Expr {
    match expr {
        Expr::Var(name) => {
            let (prefix, bare) = if let Some(stripped) = name.strip_prefix('&') {
                ("&", stripped)
            } else {
                ("", name.as_str())
            };
            if let Some(new_name) = renames.get(bare) {
                Expr::Var(format!("{}{}", prefix, new_name))
            } else {
                expr.clone()
            }
        }
        Expr::BinOp { left, op, right } => Expr::BinOp {
            left: Box::new(rename_expr_vars(left, renames)),
            op: *op,
            right: Box::new(rename_expr_vars(right, renames)),
        },
        Expr::UnOp { op, operand } => Expr::UnOp {
            op: *op,
            operand: Box::new(rename_expr_vars(operand, renames)),
        },
        Expr::MethodChain { receiver, calls } => Expr::MethodChain {
            receiver: Box::new(rename_expr_vars(receiver, renames)),
            calls: calls.iter().map(|c| MethodCall {
                name: c.name.clone(),
                args: c.args.iter().map(|a| rename_expr_vars(a, renames)).collect(),
            }).collect(),
        },
        Expr::HostCall { module, name, args } => Expr::HostCall {
            module: module.clone(),
            name: name.clone(),
            args: args.iter().map(|a| rename_expr_vars(a, renames)).collect(),
        },
        Expr::MacroCall { name, args } => Expr::MacroCall {
            name: name.clone(),
            args: args.iter().map(|a| rename_expr_vars(a, renames)).collect(),
        },
        Expr::StructLiteral { name, fields } => Expr::StructLiteral {
            name: name.clone(),
            fields: fields.iter().map(|(k, v)| (k.clone(), rename_expr_vars(v, renames))).collect(),
        },
        Expr::EnumVariant { enum_name, variant_name, fields } => Expr::EnumVariant {
            enum_name: enum_name.clone(),
            variant_name: variant_name.clone(),
            fields: fields.iter().map(|f| rename_expr_vars(f, renames)).collect(),
        },
        Expr::Literal(_) | Expr::Raw(_) => expr.clone(),
    }
}

// ---------------------------------------------------------------------------
// Dead variable elimination
// ---------------------------------------------------------------------------

/// Remove `Let` bindings whose names are never referenced by subsequent statements.
///
/// A binding is "dead" if its name never appears in any expression in the
/// remaining statements (including nested if/else/loop bodies) or the return.
/// Side-effectful statements (Expr, Assign, Return, method calls in Let values)
/// are always kept.
pub(super) fn eliminate_dead_vars(stmts: Vec<Statement>) -> Vec<Statement> {
    // Collect all variable names referenced across ALL statements.
    let mut referenced = std::collections::HashSet::new();
    for stmt in &stmts {
        collect_stmt_refs(stmt, &mut referenced);
    }

    // Filter: keep a Let binding only if its name is referenced elsewhere,
    // OR if its value has side effects (method chains, host calls).
    stmts.into_iter().filter(|stmt| {
        match stmt {
            Statement::Let { name, value, .. } => {
                // Sanitize name the same way codegen does for matching
                let check_name = name.replace('.', "_").replace('[', "_").replace(']', "");
                if referenced.contains(name) || referenced.contains(&check_name) {
                    return true;
                }
                // Also check dotted field access: "state.count" is referenced
                // when "state" appears as a receiver in field access chains.
                if name.contains('.') {
                    let base = name.split('.').next().unwrap_or(name);
                    if referenced.contains(base) {
                        return true;
                    }
                }
                // Keep if the value has side effects
                expr_has_side_effects(value)
            }
            _ => true, // Keep all non-Let statements
        }
    }).collect()
}

/// Collect all variable names referenced in a statement's expressions.
fn collect_stmt_refs(stmt: &Statement, refs: &mut std::collections::HashSet<String>) {
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
        Expr::Literal(_) | Expr::Raw(_) => {}
    }
}

/// Check if an expression has observable side effects (should not be eliminated).
fn expr_has_side_effects(expr: &Expr) -> bool {
    match expr {
        Expr::MethodChain { calls, .. } => {
            // Read-only method chains can be safely eliminated.
            // Check if the last method in the chain is a known read-only operation.
            if let Some(last) = calls.last() {
                let read_only = matches!(last.name.as_str(),
                    "has" | "get" | "sequence" | "timestamp"
                    | "current_contract_address" | "ledger"
                    | "storage" | "persistent" | "instance" | "temporary"
                );
                !read_only
            } else {
                true
            }
        }
        Expr::HostCall { name, .. } => {
            // Constructor helpers like Map::new, Vec::new are side-effect free
            !matches!(name.as_str(), "new" | "from_str")
        }
        _ => false,
    }
}
