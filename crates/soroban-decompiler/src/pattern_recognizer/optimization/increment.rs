//! Storage increment pattern reconstruction.
//!
//! Recognizes the common Soroban pattern of reading a counter from storage,
//! adding a value, and writing it back. The raw decompiled form uses separate
//! `get`, arithmetic, and `set` statements; this pass collapses them into an
//! idiomatic `let mut count = ...; count += X; storage.set(&key, &count);`
//! sequence that matches how developers actually write counter logic.

use crate::ir::{BinOp, Expr, Literal, MethodCall, Statement};

/// Recognize the storage increment pattern:
///   let val = env.storage().*.get(&key).unwrap_or(0);
///   env.storage().*.set(&key, &(val + X));
/// Transform to:
///   let mut count = env.storage().*.get(&key).unwrap_or(0);
///   count += X;
///   env.storage().*.set(&key, &count);
/// And replace `(val + X)` in subsequent expressions with `count`.
pub fn reconstruct_increment_pattern(stmts: Vec<Statement>) -> Vec<Statement> {
    let mut result = Vec::with_capacity(stmts.len());
    let mut i = 0;

    while i < stmts.len() {
        if let Some((var_name, set_idx, addend)) = find_increment_pair(&stmts, i) {
            // Emit: let mut count = ...get(&key).unwrap_or(0);
            if let Statement::Let { value, .. } = &stmts[i] {
                result.push(Statement::Let {
                    name: "count".into(),
                    mutable: true,
                    value: value.clone(),
                });
            }

            // Emit: count += X;
            result.push(Statement::Expr(Expr::BinOp {
                op: BinOp::AddAssign,
                left: Box::new(Expr::Var("count".into())),
                right: Box::new(addend.clone()),
            }));

            // Emit intermediate statements between get and set
            for j in (i + 1)..set_idx {
                result.push(rewrite_var_refs(stmts[j].clone(), &var_name, "count"));
            }

            // If the set is a top-level method chain, replace its value arg.
            // If the set is inside an if block, rewrite the entire block.
            if let Statement::Expr(Expr::MethodChain { receiver, calls }) = &stmts[set_idx] {
                let mut new_calls = calls.clone();
                if let Some(set_call) = new_calls.iter_mut().find(|c| c.name == "set") {
                    if set_call.args.len() >= 2 {
                        set_call.args[1] = Expr::Ref(Box::new(Expr::Var("count".into())));
                    }
                }
                result.push(Statement::Expr(Expr::MethodChain {
                    receiver: receiver.clone(),
                    calls: new_calls,
                }));
            } else {
                // Set is nested inside an if/else — rewrite the whole statement
                result.push(rewrite_add_expr(stmts[set_idx].clone(), &var_name, &addend));
            }

            // Emit remaining statements, replacing (val + X) with count
            for j in (set_idx + 1)..stmts.len() {
                result.push(rewrite_add_expr(stmts[j].clone(), &var_name, &addend));
            }
            return result;
        }

        result.push(stmts[i].clone());
        i += 1;
    }

    result
}

/// Find a get/set pair that forms an increment pattern.
/// Returns (var_name, set_index, addend_expr) if found.
fn find_increment_pair(
    stmts: &[Statement],
    get_idx: usize,
) -> Option<(String, usize, Expr)> {
    let var_name = match &stmts[get_idx] {
        Statement::Let { name, value: Expr::MethodChain { calls, .. }, .. } => {
            // Must have .get(&key).unwrap_or(0)
            let _get_call = calls.iter().find(|c| c.name == "get")?;
            let unwrap_call = calls.iter().find(|c| c.name == "unwrap_or")?;
            match unwrap_call.args.first() {
                Some(Expr::Literal(Literal::I64(0))) | Some(Expr::Literal(Literal::I32(0))) => {}
                _ => return None,
            }
            name.clone()
        }
        _ => return None,
    };

    // Find the set statement that uses (var_name + X) as value.
    // Search at the top level AND inside if blocks.
    for j in (get_idx + 1)..stmts.len() {
        if let Some(addend) = find_set_with_addend(&stmts[j], &var_name) {
            return Some((var_name, j, addend));
        }
    }

    None
}

/// Search a statement (and nested if blocks) for a storage set with (var + X).
fn find_set_with_addend(stmt: &Statement, var_name: &str) -> Option<Expr> {
    match stmt {
        Statement::Expr(Expr::MethodChain { calls, .. }) => {
            if let Some(set_call) = calls.iter().find(|c| c.name == "set") {
                if set_call.args.len() >= 2 {
                    return extract_var_plus(&set_call.args[1], var_name);
                }
            }
            None
        }
        Statement::If { then_body, else_body, .. } => {
            for s in then_body {
                if let Some(addend) = find_set_with_addend(s, var_name) {
                    return Some(addend);
                }
            }
            for s in else_body {
                if let Some(addend) = find_set_with_addend(s, var_name) {
                    return Some(addend);
                }
            }
            None
        }
        _ => None,
    }
}

/// Extract the addend from &(var + X), returning X.
fn extract_var_plus(expr: &Expr, var_name: &str) -> Option<Expr> {
    match expr {
        Expr::Ref(inner) => extract_var_plus(inner, var_name),
        Expr::BinOp { op: BinOp::Add, left, right } => {
            if matches!(left.as_ref(), Expr::Var(n) if n == var_name) {
                Some(*right.clone())
            } else if matches!(right.as_ref(), Expr::Var(n) if n == var_name) {
                Some(*left.clone())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Replace references to old_name with new_name in a statement.
fn rewrite_var_refs(stmt: Statement, old_name: &str, new_name: &str) -> Statement {
    match stmt {
        Statement::Let { name, mutable, value } => Statement::Let {
            name, mutable,
            value: rewrite_expr_refs(value, old_name, new_name),
        },
        Statement::Expr(e) => Statement::Expr(rewrite_expr_refs(e, old_name, new_name)),
        Statement::Return(Some(e)) => Statement::Return(Some(rewrite_expr_refs(e, old_name, new_name))),
        other => other,
    }
}

/// Replace (var + addend) with count in a statement.
fn rewrite_add_expr(stmt: Statement, var_name: &str, addend: &Expr) -> Statement {
    match stmt {
        Statement::Return(Some(e)) => Statement::Return(Some(replace_add(e, var_name, addend))),
        Statement::Expr(e) => Statement::Expr(replace_add(e, var_name, addend)),
        Statement::Let { name, mutable, value } => Statement::Let {
            name, mutable,
            value: replace_add(value, var_name, addend),
        },
        Statement::If { condition, then_body, else_body } => Statement::If {
            condition: replace_add(condition, var_name, addend),
            then_body: then_body.into_iter().map(|s| rewrite_add_expr(s, var_name, addend)).collect(),
            else_body: else_body.into_iter().map(|s| rewrite_add_expr(s, var_name, addend)).collect(),
        },
        other => other,
    }
}

/// Replace (var + addend) with count, and bare var with count.
fn replace_add(expr: Expr, var_name: &str, addend: &Expr) -> Expr {
    match &expr {
        Expr::BinOp { op: BinOp::Add, left, right } => {
            // Check if this is (var + addend) or (addend + var)
            if matches!(left.as_ref(), Expr::Var(n) if n == var_name) && exprs_equal(right, addend) {
                return Expr::Var("count".into());
            }
            if matches!(right.as_ref(), Expr::Var(n) if n == var_name) && exprs_equal(left, addend) {
                return Expr::Var("count".into());
            }
        }
        Expr::Var(n) if n == var_name => return Expr::Var("count".into()),
        Expr::Ref(inner) => return Expr::Ref(Box::new(replace_add(*inner.clone(), var_name, addend))),
        _ => {}
    }
    // Recurse into sub-expressions
    match expr {
        Expr::BinOp { op, left, right } => Expr::BinOp {
            op,
            left: Box::new(replace_add(*left, var_name, addend)),
            right: Box::new(replace_add(*right, var_name, addend)),
        },
        Expr::MethodChain { receiver, calls } => Expr::MethodChain {
            receiver: Box::new(replace_add(*receiver, var_name, addend)),
            calls: calls.into_iter().map(|c| MethodCall {
                name: c.name,
                args: c.args.into_iter().map(|a| replace_add(a, var_name, addend)).collect(),
            }).collect(),
        },
        other => other,
    }
}

/// Simple structural equality check for expressions.
fn exprs_equal(a: &Expr, b: &Expr) -> bool {
    format!("{:?}", a) == format!("{:?}", b)
}

fn rewrite_expr_refs(expr: Expr, old_name: &str, new_name: &str) -> Expr {
    match expr {
        Expr::Var(ref n) if n == old_name => Expr::Var(new_name.into()),
        Expr::BinOp { op, left, right } => Expr::BinOp {
            op,
            left: Box::new(rewrite_expr_refs(*left, old_name, new_name)),
            right: Box::new(rewrite_expr_refs(*right, old_name, new_name)),
        },
        Expr::Ref(inner) => Expr::Ref(Box::new(rewrite_expr_refs(*inner, old_name, new_name))),
        Expr::MethodChain { receiver, calls } => Expr::MethodChain {
            receiver: Box::new(rewrite_expr_refs(*receiver, old_name, new_name)),
            calls: calls.into_iter().map(|c| MethodCall {
                name: c.name,
                args: c.args.into_iter().map(|a| rewrite_expr_refs(a, old_name, new_name)).collect(),
            }).collect(),
        },
        other => other,
    }
}
