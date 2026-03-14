use crate::ir::{Expr, Statement};

/// Fold `if` statements with constant boolean conditions.
///
/// - `if (1) { body }` -> inline body (1 = true)
/// - `if (0) { body } else { else_body }` -> inline else_body (0 = false)
/// - Recurse into nested statements.
pub fn fold_constant_guards(stmts: Vec<Statement>) -> Vec<Statement> {
    let mut result = Vec::new();
    for stmt in stmts {
        match stmt {
            Statement::If { condition, then_body, else_body } => {
                // Recurse into both branches first.
                let then_folded = fold_constant_guards(then_body);
                let else_folded = fold_constant_guards(else_body);

                if is_truthy_literal(&condition) {
                    // Condition is always true: inline then-body.
                    result.extend(then_folded);
                } else if is_falsy_literal(&condition) {
                    // Condition is always false: inline else-body (or drop).
                    result.extend(else_folded);
                } else if is_type_tag_check(&condition) {
                    // Soroban type tag validation guard: inline then-body.
                    // These are compiler-inserted checks like `(x & 255) == 77`
                    // that validate Val encoding tags. Since we've already
                    // typed the parameters, these are redundant.
                    result.extend(then_folded);
                } else if is_artifact_constant_comparison(&condition) {
                    // WASM compilation artifact: br_if continuation with a
                    // condition that compares two raw constants (frame offsets,
                    // loop counters). These always evaluate to a fixed value
                    // but the constants are simulation artifacts, not logical
                    // values. Inline the body since the continuation is the
                    // real execution path.
                    result.extend(then_folded);
                } else if is_non_boolean_condition(&condition) && else_folded.is_empty() {
                    // Non-boolean if-condition like `if (val + 1)` or
                    // `if (some_var)` -- WASM br_if artifact. In Rust, `if`
                    // requires bool, so a non-boolean condition is always a
                    // compilation artifact. Inline the body.
                    // Only do this when there's no else branch to be safe.
                    result.extend(then_folded);
                } else {
                    result.push(Statement::If {
                        condition,
                        then_body: then_folded,
                        else_body: else_folded,
                    });
                }
            }
            Statement::While { condition, body } => {
                result.push(Statement::While {
                    condition,
                    body: fold_constant_guards(body),
                });
            }
            Statement::Loop { body } => {
                result.push(Statement::Loop {
                    body: fold_constant_guards(body),
                });
            }
            Statement::ForEach { var_name, collection, body } => {
                result.push(Statement::ForEach {
                    var_name,
                    collection,
                    body: fold_constant_guards(body),
                });
            }
            Statement::ForRange { var_name, bound, body } => {
                result.push(Statement::ForRange {
                    var_name,
                    bound,
                    body: fold_constant_guards(body),
                });
            }
            other => result.push(other),
        }
    }
    result
}

/// Check if an expression is a truthy literal (nonzero integer, true, or unit).
///
/// Unit `()` is treated as truthy because it typically represents an
/// unresolvable br_if continuation -- the body always executes.
fn is_truthy_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Literal(crate::ir::Literal::I32(n)) => *n != 0,
        Expr::Literal(crate::ir::Literal::I64(n)) => *n != 0,
        Expr::Literal(crate::ir::Literal::Bool(b)) => *b,
        Expr::Literal(crate::ir::Literal::Unit) => true,
        _ => false,
    }
}

/// Check if an expression is a falsy literal (zero or false).
fn is_falsy_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Literal(crate::ir::Literal::I32(0)) => true,
        Expr::Literal(crate::ir::Literal::I64(0)) => true,
        Expr::Literal(crate::ir::Literal::Bool(false)) => true,
        _ => false,
    }
}

/// Detect Soroban type tag validation patterns.
///
/// The WASM compiler inserts checks like `(x & 255) == 77` (Address tag),
/// `(x & 255) == 75` (Vec tag), `(x & 255) == 0` (U32 tag), etc.
/// These validate the Val encoding type but are redundant when parameters
/// are already typed in the decompiled output.
fn is_type_tag_check(expr: &Expr) -> bool {
    // Pattern: (x & 255) == TAG  or  (x & 255) != TAG
    // Also: Not((x & 255) != TAG) which is equivalent to (x & 255) == TAG
    if let Expr::BinOp { left, op, right } = expr {
        if matches!(op, crate::ir::BinOp::Eq | crate::ir::BinOp::Ne) {
            return is_val_tag_mask(left) || is_val_tag_mask(right);
        }
    }
    // Unwrap Not wrapper: Not(type_tag_check) is still a type tag check
    if let Expr::UnOp { op: crate::ir::UnOp::Not, operand } = expr {
        return is_type_tag_check(operand);
    }
    false
}

/// Check if an expression is `(x & 255)` -- the Soroban Val type tag mask.
fn is_val_tag_mask(expr: &Expr) -> bool {
    if let Expr::BinOp { op: crate::ir::BinOp::BitAnd, right, .. } = expr {
        matches!(right.as_ref(),
            Expr::Literal(crate::ir::Literal::I32(255))
            | Expr::Literal(crate::ir::Literal::I64(255))
        )
    } else {
        false
    }
}

/// Detect comparisons between two raw constant literals.
///
/// These arise from br_if continuations where the WASM simulator resolved
/// frame pointer offsets or loop counters to constants. At runtime the
/// values would be dynamic, so the guard is always a compilation artifact
/// that should be inlined.
fn is_artifact_constant_comparison(expr: &Expr) -> bool {
    if let Expr::BinOp { left, op, right } = expr {
        if matches!(op,
            crate::ir::BinOp::Eq | crate::ir::BinOp::Ne
            | crate::ir::BinOp::Lt | crate::ir::BinOp::Le
            | crate::ir::BinOp::Gt | crate::ir::BinOp::Ge
        ) {
            return is_raw_constant(left) && is_raw_constant(right);
        }
    }
    false
}

/// Check if an expression is a raw integer constant (I32 or I64 literal).
fn is_raw_constant(expr: &Expr) -> bool {
    matches!(expr,
        Expr::Literal(crate::ir::Literal::I32(_))
        | Expr::Literal(crate::ir::Literal::I64(_))
    )
}

/// Detect non-boolean if-conditions that are WASM br_if artifacts.
///
/// In Rust, `if` requires a `bool`. An if-condition like `if (val + 1)` or
/// `if (some_var)` without any comparison operator is always a WASM br_if
/// continuation artifact where the condition was used as a truthiness test.
/// These should be inlined (the body always executes).
///
/// Returns true only for expressions that are clearly non-boolean:
/// arithmetic ops, plain variables (not boolean-named), method calls, etc.
/// Returns false for comparisons (Eq/Ne/Lt/etc.), boolean Not, and literals
/// (those are handled by other checks).
fn is_non_boolean_condition(expr: &Expr) -> bool {
    match expr {
        // Arithmetic: val + 1, x * y, etc. -- never boolean in Rust
        Expr::BinOp { op, .. } => matches!(op,
            crate::ir::BinOp::Add | crate::ir::BinOp::Sub
            | crate::ir::BinOp::Mul | crate::ir::BinOp::Div
            | crate::ir::BinOp::Rem
            | crate::ir::BinOp::BitAnd | crate::ir::BinOp::BitOr
            | crate::ir::BinOp::BitXor
            | crate::ir::BinOp::Shl | crate::ir::BinOp::Shr
        ),
        // A plain variable used as condition -- WASM i32 truthiness test
        Expr::Var(_) => true,
        // Method call result used as condition
        Expr::MethodChain { .. } => true,
        // Literals and comparisons handled elsewhere
        _ => false,
    }
}
