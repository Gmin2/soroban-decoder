//! Struct field mutation pattern reconstruction.
//!
//! When a Soroban contract modifies fields of a stored struct, the WASM
//! compiler destructs the struct into individual fields, applies modifications,
//! and reconstructs a new struct literal. The decompiled output shows this as
//! `let state_1 = MyStruct { f1: val.f1 + X, f2: val.f2 };` which is
//! semantically correct but unidiomatic. This pass detects the get/modify/set
//! pattern and rewrites it as `state.f1 += X;` field mutations on a mutable
//! binding, matching how developers write struct updates.

use crate::ir::{BinOp, Expr, Statement};

/// Reconstruct struct field mutation from struct literal construction.
///
/// Transforms:
///   let val = env.storage().get(&key).unwrap_or(0);
///   let state_1 = StructName { f1: val.f1 + X, f2: Y };
///   env.storage().set(&key, &state_1);
///   return (val.f1 + X);
/// Into:
///   let mut state = env.storage().get(&key).unwrap_or(0);
///   state.f1 += X;
///   state.f2 = Y;
///   env.storage().set(&key, &state);
///   return state.f1;
pub fn reconstruct_struct_mutation(stmts: Vec<Statement>) -> Vec<Statement> {
    let mut result = Vec::with_capacity(stmts.len());
    let mut i = 0;

    while i < stmts.len() {
        if let Some((src_var, struct_idx, struct_var, fields)) =
            find_struct_mutation_pair(&stmts, i)
        {
            // Check: at least one field must be MODIFIED (not all identity copies).
            // If all fields are identity copies, it's a return pattern (get_state),
            // not a mutation pattern.
            let has_mutation = fields.iter().any(|(_, kind)| !matches!(kind, FieldKind::Identity));
            if !has_mutation {
                result.push(stmts[i].clone());
                i += 1;
                continue;
            }

            // Emit: let mut state = storage_get_chain;
            if let Statement::Let { value, .. } = &stmts[i] {
                result.push(Statement::Let {
                    name: "state".into(),
                    mutable: true,
                    value: value.clone(),
                });
            }

            // Emit intermediate statements between get and struct
            for j in (i + 1)..struct_idx {
                result.push(rename_in_stmt(stmts[j].clone(), &src_var, "state"));
            }

            // Emit field mutations
            for (field_name, kind) in &fields {
                match kind {
                    FieldKind::Identity => {
                        // state.field = state.field — skip (no-op)
                    }
                    FieldKind::AddAssign(addend) => {
                        // state.field += addend;
                        result.push(Statement::Expr(Expr::BinOp {
                            op: BinOp::AddAssign,
                            left: Box::new(Expr::Var(format!("state.{}", field_name))),
                            right: Box::new(addend.clone()),
                        }));
                    }
                    FieldKind::Assign(value) => {
                        // state.field = value;
                        result.push(Statement::Assign {
                            target: Expr::Var(format!("state.{}", field_name)),
                            value: value.clone(),
                        });
                    }
                }
            }

            // Emit remaining statements after the struct literal,
            // replacing struct_var references with "state" and
            // (src_var.field + expr) patterns with state.field
            for j in (struct_idx + 1)..stmts.len() {
                let mut s = rename_in_stmt(stmts[j].clone(), &struct_var, "state");
                s = rewrite_field_exprs(s, &src_var, &fields);
                result.push(s);
            }
            return result;
        }

        result.push(stmts[i].clone());
        i += 1;
    }

    result
}

/// Classification of how a struct field is derived from the source variable.
#[derive(Debug)]
enum FieldKind {
    /// Field is `src_var.field_name` — identity copy
    Identity,
    /// Field is `src_var.field_name + expr` — add-assign
    AddAssign(Expr),
    /// Field is some other expression — direct assignment
    Assign(Expr),
}

/// Find a storage-get followed by a struct literal using the get's result.
/// Returns (src_var_name, struct_stmt_index, struct_var_name, fields_analysis).
fn find_struct_mutation_pair(
    stmts: &[Statement],
    get_idx: usize,
) -> Option<(String, usize, String, Vec<(String, FieldKind)>)> {
    // Statement at get_idx must be a storage get
    let src_var = match &stmts[get_idx] {
        Statement::Let { name, value: Expr::MethodChain { calls, .. }, .. } => {
            let has_get = calls.iter().any(|c| c.name == "get");
            let has_unwrap = calls.iter().any(|c| c.name == "unwrap_or");
            if has_get && has_unwrap { name.clone() } else { return None; }
        }
        _ => return None,
    };

    // Look for a struct literal in subsequent statements
    for j in (get_idx + 1)..stmts.len().min(get_idx + 4) {
        if let Statement::Let { name: struct_var, value: Expr::StructLiteral { fields, .. }, .. } = &stmts[j] {
            // Analyze each field
            let mut field_analysis = Vec::new();
            let mut uses_src = false;

            for (field_name, field_value) in fields {
                let kind = classify_field(field_value, &src_var, field_name);
                if matches!(kind, FieldKind::Identity | FieldKind::AddAssign(_)) {
                    uses_src = true;
                }
                field_analysis.push((field_name.clone(), kind));
            }

            if uses_src && !field_analysis.is_empty() {
                // Verify the struct is used in a subsequent storage set
                let struct_is_stored = stmts[j + 1..].iter().any(|s| {
                    refs_var(s, struct_var)
                });
                if struct_is_stored {
                    return Some((src_var, j, struct_var.clone(), field_analysis));
                }
            }
        }
    }

    None
}

/// Classify how a struct field value relates to the source variable.
fn classify_field(value: &Expr, src_var: &str, field_name: &str) -> FieldKind {
    let expected_ref = format!("{}.{}", src_var, field_name);

    match value {
        // Identity: field = src_var.field_name
        Expr::Var(name) if *name == expected_ref => FieldKind::Identity,
        // AddAssign: field = src_var.field_name + expr
        Expr::BinOp { op: BinOp::Add, left, right } => {
            if matches!(left.as_ref(), Expr::Var(n) if *n == expected_ref) {
                FieldKind::AddAssign(*right.clone())
            } else if matches!(right.as_ref(), Expr::Var(n) if *n == expected_ref) {
                FieldKind::AddAssign(*left.clone())
            } else {
                FieldKind::Assign(value.clone())
            }
        }
        // Anything else: direct assignment
        _ => FieldKind::Assign(value.clone()),
    }
}

/// Check if a statement references a variable name.
fn refs_var(stmt: &Statement, var_name: &str) -> bool {
    match stmt {
        Statement::Let { value, .. } => expr_refs_var(value, var_name),
        Statement::Expr(e) => expr_refs_var(e, var_name),
        Statement::Return(Some(e)) => expr_refs_var(e, var_name),
        Statement::Assign { target, value } => expr_refs_var(target, var_name) || expr_refs_var(value, var_name),
        Statement::If { condition, then_body, else_body } => {
            expr_refs_var(condition, var_name)
                || then_body.iter().any(|s| refs_var(s, var_name))
                || else_body.iter().any(|s| refs_var(s, var_name))
        }
        _ => false,
    }
}

fn expr_refs_var(expr: &Expr, var_name: &str) -> bool {
    match expr {
        Expr::Var(n) => n == var_name || n.starts_with(&format!("{}.", var_name)),
        Expr::BinOp { left, right, .. } => expr_refs_var(left, var_name) || expr_refs_var(right, var_name),
        Expr::UnOp { operand, .. } => expr_refs_var(operand, var_name),
        Expr::Ref(inner) => expr_refs_var(inner, var_name),
        Expr::MethodChain { receiver, calls } => {
            expr_refs_var(receiver, var_name) || calls.iter().any(|c| c.args.iter().any(|a| expr_refs_var(a, var_name)))
        }
        Expr::HostCall { args, .. } | Expr::MacroCall { args, .. } => args.iter().any(|a| expr_refs_var(a, var_name)),
        Expr::StructLiteral { fields, .. } => fields.iter().any(|(_, v)| expr_refs_var(v, var_name)),
        _ => false,
    }
}

/// Rename variable references in a statement.
fn rename_in_stmt(stmt: Statement, old: &str, new: &str) -> Statement {
    match stmt {
        Statement::Let { name, mutable, value } => Statement::Let {
            name: if name == old { new.into() } else { name },
            mutable,
            value: rename_in_expr(value, old, new),
        },
        Statement::Expr(e) => Statement::Expr(rename_in_expr(e, old, new)),
        Statement::Return(Some(e)) => Statement::Return(Some(rename_in_expr(e, old, new))),
        Statement::Assign { target, value } => Statement::Assign {
            target: rename_in_expr(target, old, new),
            value: rename_in_expr(value, old, new),
        },
        Statement::If { condition, then_body, else_body } => Statement::If {
            condition: rename_in_expr(condition, old, new),
            then_body: then_body.into_iter().map(|s| rename_in_stmt(s, old, new)).collect(),
            else_body: else_body.into_iter().map(|s| rename_in_stmt(s, old, new)).collect(),
        },
        other => other,
    }
}

fn rename_in_expr(expr: Expr, old: &str, new: &str) -> Expr {
    match expr {
        Expr::Var(ref name) => {
            if name == old {
                Expr::Var(new.into())
            } else if name.starts_with(&format!("{}.", old)) {
                Expr::Var(name.replacen(old, new, 1))
            } else {
                expr
            }
        }
        Expr::BinOp { op, left, right } => Expr::BinOp {
            op,
            left: Box::new(rename_in_expr(*left, old, new)),
            right: Box::new(rename_in_expr(*right, old, new)),
        },
        Expr::UnOp { op, operand } => Expr::UnOp {
            op,
            operand: Box::new(rename_in_expr(*operand, old, new)),
        },
        Expr::Ref(inner) => Expr::Ref(Box::new(rename_in_expr(*inner, old, new))),
        Expr::MethodChain { receiver, calls } => Expr::MethodChain {
            receiver: Box::new(rename_in_expr(*receiver, old, new)),
            calls: calls.into_iter().map(|c| crate::ir::MethodCall {
                name: c.name,
                args: c.args.into_iter().map(|a| rename_in_expr(a, old, new)).collect(),
            }).collect(),
        },
        Expr::HostCall { module, name, args } => Expr::HostCall {
            module, name,
            args: args.into_iter().map(|a| rename_in_expr(a, old, new)).collect(),
        },
        Expr::StructLiteral { name, fields } => Expr::StructLiteral {
            name,
            fields: fields.into_iter().map(|(f, v)| (f, rename_in_expr(v, old, new))).collect(),
        },
        other => other,
    }
}

/// Rewrite `(src_var.field + addend)` patterns to `state.field` in statements.
fn rewrite_field_exprs(
    stmt: Statement,
    src_var: &str,
    fields: &[(String, FieldKind)],
) -> Statement {
    match stmt {
        Statement::Return(Some(e)) => Statement::Return(Some(rewrite_field_expr(e, src_var, fields))),
        Statement::Expr(e) => Statement::Expr(rewrite_field_expr(e, src_var, fields)),
        Statement::Let { name, mutable, value } => Statement::Let {
            name, mutable,
            value: rewrite_field_expr(value, src_var, fields),
        },
        other => other,
    }
}

/// Replace `(src_var.field + addend)` with `state.field` when the field was add-assigned.
fn rewrite_field_expr(expr: Expr, src_var: &str, fields: &[(String, FieldKind)]) -> Expr {
    match &expr {
        Expr::BinOp { op: BinOp::Add, left, .. } => {
            // Check if left is src_var.field and this field was add-assigned
            if let Expr::Var(name) = left.as_ref() {
                if name.starts_with(&format!("{}.", src_var)) {
                    let field_name = &name[src_var.len() + 1..];
                    for (fname, kind) in fields {
                        if fname == field_name && matches!(kind, FieldKind::AddAssign(_)) {
                            return Expr::Var(format!("state.{}", field_name));
                        }
                    }
                }
            }
        }
        Expr::Var(name) if name.starts_with(&format!("{}.", src_var)) => {
            return Expr::Var(name.replacen(src_var, "state", 1));
        }
        _ => {}
    }
    // Recurse
    match expr {
        Expr::BinOp { op, left, right } => Expr::BinOp {
            op,
            left: Box::new(rewrite_field_expr(*left, src_var, fields)),
            right: Box::new(rewrite_field_expr(*right, src_var, fields)),
        },
        Expr::Ref(inner) => Expr::Ref(Box::new(rewrite_field_expr(*inner, src_var, fields))),
        Expr::MethodChain { receiver, calls } => Expr::MethodChain {
            receiver: Box::new(rewrite_field_expr(*receiver, src_var, fields)),
            calls: calls.into_iter().map(|c| crate::ir::MethodCall {
                name: c.name,
                args: c.args.into_iter().map(|a| rewrite_field_expr(a, src_var, fields)).collect(),
            }).collect(),
        },
        other => other,
    }
}
