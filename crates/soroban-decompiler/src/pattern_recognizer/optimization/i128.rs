//! i128 arithmetic collapse pass.
//!
//! WASM has no native i128 type, so the Rust compiler decomposes every i128
//! operation into sequences of i64 multiplies, adds, shifts, and masks
//! (carry-chain arithmetic). The decompiler faithfully reconstructs these as
//! deeply nested `BinOp` trees, which are unreadable. This pass simplifies
//! them through three stages: algebraic identity simplification, depth-based
//! collapse of remaining deep expressions to `/* i128 expr */` placeholders,
//! and elimination of i128 overflow check guards.

use crate::ir::{Expr, MethodCall, Statement};

use super::collect_expr_var_names;

/// Collapse i128 carry-chain arithmetic that the WASM compiler expands from
/// simple i128 operations.
///
/// WASM has no native i128 type, so the Rust compiler expands every i128
/// operation into sequences of i64 multiplies, adds, shifts, and masks.
/// The decompiler faithfully reconstructs these as deeply nested `BinOp`
/// trees. This pass simplifies them by:
///
/// 1. Algebraic identities: `(0 - (0 - x))` -> `x`, `0 * x` -> `0`, etc.
/// 2. Sign-extension removal: `(((x >> 63) << 64) | x)` -> `x`
/// 3. Depth-based collapse: expressions deeper than a threshold that
///    involve only arithmetic on the same base variable(s) and i128
///    constants are collapsed to `/* i128 expr on (vars) */`.
pub fn collapse_i128_patterns(stmts: Vec<Statement>) -> Vec<Statement> {
    // First pass: simplify all expressions algebraically.
    let simplified: Vec<Statement> = stmts.into_iter()
        .map(|s| simplify_stmt_exprs(s))
        .collect();

    // Second pass: collapse remaining deep i128 expressions.
    let collapsed: Vec<Statement> = simplified.into_iter()
        .map(|s| collapse_deep_i128_stmt(s))
        .collect();

    // Third pass: eliminate i128 overflow check guards.
    // Soroban i128 arithmetic traps on overflow, so overflow check guards
    // are always-true dead code. Flatten `if (overflow_check) { body }` to `body`.
    eliminate_overflow_guards(collapsed)
}

/// Eliminate i128 overflow check guard patterns.
///
/// Detects `if` statements where the condition is an i128 signed overflow
/// check (involving `>> 63` sign-bit extraction, XOR, AND, and `>= 0`).
/// These are always true in Soroban (overflow traps), so the if-body is
/// inlined and the guard removed.
fn eliminate_overflow_guards(stmts: Vec<Statement>) -> Vec<Statement> {
    let mut result = Vec::new();
    for stmt in stmts {
        match stmt {
            Statement::If { ref condition, ref then_body, ref else_body } => {
                if is_overflow_check(condition) && else_body.is_empty() {
                    // Flatten: inline the then-body directly.
                    result.extend(eliminate_overflow_guards(then_body.clone()));
                } else {
                    // Recurse into both branches.
                    result.push(Statement::If {
                        condition: condition.clone(),
                        then_body: eliminate_overflow_guards(then_body.clone()),
                        else_body: eliminate_overflow_guards(else_body.clone()),
                    });
                }
            }
            Statement::While { condition, body } => {
                result.push(Statement::While {
                    condition,
                    body: eliminate_overflow_guards(body),
                });
            }
            Statement::Loop { body } => {
                result.push(Statement::Loop {
                    body: eliminate_overflow_guards(body),
                });
            }
            Statement::ForEach { var_name, collection, body } => {
                result.push(Statement::ForEach {
                    var_name,
                    collection,
                    body: eliminate_overflow_guards(body),
                });
            }
            Statement::ForRange { var_name, bound, body } => {
                result.push(Statement::ForRange {
                    var_name,
                    bound,
                    body: eliminate_overflow_guards(body),
                });
            }
            other => result.push(other),
        }
    }
    result
}

/// Check if an expression is an i128 signed overflow check pattern.
///
/// The pattern is:
///   `((a >> 63) ^ (b >> 63)) & ((a >> 63) ^ (result_hi)) >= 0`
///
/// Key indicators:
/// - Contains `>> 63` shifts (sign bit extraction)
/// - Contains XOR (`^`) operations
/// - Top-level comparison is `>= 0`
/// - Expression depth > 3
fn is_overflow_check(expr: &Expr) -> bool {
    // Pattern: `expr >= 0`
    if let Expr::BinOp { left, op: crate::ir::BinOp::Ge, right } = expr {
        if is_literal_zero(right) && count_shr63(left) >= 2 && has_xor(left) {
            return true;
        }
    }
    // Pattern: `(expr) >= 0` with extra nesting
    if let Expr::BinOp { left, op: crate::ir::BinOp::Ge, right } = expr {
        if is_literal_zero(right) {
            if let Expr::BinOp { op: crate::ir::BinOp::BitAnd, left: inner_l, right: inner_r } = left.as_ref() {
                if count_shr63(inner_l) >= 1 && count_shr63(inner_r) >= 1 {
                    return true;
                }
            }
        }
    }
    false
}

/// Count occurrences of `>> 63` shifts in an expression tree.
fn count_shr63(expr: &Expr) -> usize {
    match expr {
        Expr::BinOp { left, op: crate::ir::BinOp::Shr, right } => {
            let is_63 = matches!(right.as_ref(), Expr::Literal(crate::ir::Literal::I64(63)));
            let count = count_shr63(left) + count_shr63(right);
            if is_63 { count + 1 } else { count }
        }
        Expr::BinOp { left, right, .. } => count_shr63(left) + count_shr63(right),
        Expr::UnOp { operand, .. } => count_shr63(operand),
        _ => 0,
    }
}

/// Check if an expression tree contains XOR operations.
fn has_xor(expr: &Expr) -> bool {
    match expr {
        Expr::BinOp { op: crate::ir::BinOp::BitXor, .. } => true,
        Expr::BinOp { left, right, .. } => has_xor(left) || has_xor(right),
        Expr::UnOp { operand, .. } => has_xor(operand),
        _ => false,
    }
}

/// Apply algebraic simplification to all expressions in a statement.
fn simplify_stmt_exprs(stmt: Statement) -> Statement {
    match stmt {
        Statement::Let { name, mutable, value } => Statement::Let {
            name,
            mutable,
            value: simplify_expr(&value),
        },
        Statement::Assign { target, value } => Statement::Assign {
            target: simplify_expr(&target),
            value: simplify_expr(&value),
        },
        Statement::Expr(e) => Statement::Expr(simplify_expr(&e)),
        Statement::Return(Some(e)) => Statement::Return(Some(simplify_expr(&e))),
        Statement::Return(None) => Statement::Return(None),
        Statement::If { condition, then_body, else_body } => Statement::If {
            condition: simplify_expr(&condition),
            then_body: then_body.into_iter().map(simplify_stmt_exprs).collect(),
            else_body: else_body.into_iter().map(simplify_stmt_exprs).collect(),
        },
        Statement::While { condition, body } => Statement::While {
            condition: simplify_expr(&condition),
            body: body.into_iter().map(simplify_stmt_exprs).collect(),
        },
        Statement::Loop { body } => Statement::Loop {
            body: body.into_iter().map(simplify_stmt_exprs).collect(),
        },
        Statement::ForEach { var_name, collection, body } => Statement::ForEach {
            var_name,
            collection: simplify_expr(&collection),
            body: body.into_iter().map(simplify_stmt_exprs).collect(),
        },
        Statement::ForRange { var_name, bound, body } => Statement::ForRange {
            var_name,
            bound: simplify_expr(&bound),
            body: body.into_iter().map(simplify_stmt_exprs).collect(),
        },
    }
}

/// Recursively simplify an expression using algebraic identities.
///
/// Applies rules bottom-up (children first, then the node itself) and
/// iterates until a fixed point is reached.
fn simplify_expr(expr: &Expr) -> Expr {
    // First, recursively simplify children.
    let simplified = match expr {
        Expr::BinOp { left, op, right } => {
            let l = simplify_expr(left);
            let r = simplify_expr(right);
            Expr::BinOp {
                left: Box::new(l),
                op: *op,
                right: Box::new(r),
            }
        }
        Expr::UnOp { op, operand } => {
            let inner = simplify_expr(operand);
            Expr::UnOp {
                op: *op,
                operand: Box::new(inner),
            }
        }
        Expr::MethodChain { receiver, calls } => Expr::MethodChain {
            receiver: Box::new(simplify_expr(receiver)),
            calls: calls.iter().map(|c| MethodCall {
                name: c.name.clone(),
                args: c.args.iter().map(|a| simplify_expr(a)).collect(),
            }).collect(),
        },
        Expr::HostCall { module, name, args } => Expr::HostCall {
            module: module.clone(),
            name: name.clone(),
            args: args.iter().map(|a| simplify_expr(a)).collect(),
        },
        Expr::MacroCall { name, args } => Expr::MacroCall {
            name: name.clone(),
            args: args.iter().map(|a| simplify_expr(a)).collect(),
        },
        Expr::StructLiteral { name, fields } => Expr::StructLiteral {
            name: name.clone(),
            fields: fields.iter().map(|(k, v)| (k.clone(), simplify_expr(v))).collect(),
        },
        Expr::EnumVariant { enum_name, variant_name, fields } => Expr::EnumVariant {
            enum_name: enum_name.clone(),
            variant_name: variant_name.clone(),
            fields: fields.iter().map(|f| simplify_expr(f)).collect(),
        },
        Expr::Ref(inner) => Expr::Ref(Box::new(simplify_expr(inner))),
        Expr::Literal(_) | Expr::Var(_) | Expr::Raw(_) => expr.clone(),
    };

    // Now apply algebraic simplification rules to this node.
    apply_algebraic_rules(&simplified)
}

/// Apply algebraic simplification rules to a single expression node.
///
/// Returns a simplified expression if any rule fires, otherwise the
/// original expression unchanged.
fn apply_algebraic_rules(expr: &Expr) -> Expr {
    use crate::ir::BinOp as Op;

    match expr {
        Expr::BinOp { left, op, right } => {
            let l = left.as_ref();
            let r = right.as_ref();

            // Rule: (0 - (0 - x)) => x  (double negation via subtraction)
            if *op == Op::Sub && is_literal_zero(l) {
                if let Expr::BinOp { left: inner_l, op: Op::Sub, right: inner_r } = r {
                    if is_literal_zero(inner_l) {
                        return apply_algebraic_rules(inner_r);
                    }
                }
            }

            // Rule: 0 * x => 0, x * 0 => 0
            if *op == Op::Mul {
                if is_literal_zero(l) || is_literal_zero(r) {
                    return Expr::Literal(crate::ir::Literal::I64(0));
                }
            }

            // Rule: x + 0 => x, 0 + x => x
            if *op == Op::Add {
                if is_literal_zero(r) {
                    return l.clone();
                }
                if is_literal_zero(l) {
                    return r.clone();
                }
            }

            // Rule: x - 0 => x
            if *op == Op::Sub && is_literal_zero(r) {
                return l.clone();
            }

            // Rule: x | 0 => x, 0 | x => x
            if *op == Op::BitOr {
                if is_literal_zero(r) {
                    return l.clone();
                }
                if is_literal_zero(l) {
                    return r.clone();
                }
            }

            // Rule: x & 0 => 0, 0 & x => 0
            if *op == Op::BitAnd {
                if is_literal_zero(l) || is_literal_zero(r) {
                    return Expr::Literal(crate::ir::Literal::I64(0));
                }
            }

            // Rule: 0 << x => 0, x << 0 => x
            if *op == Op::Shl {
                if is_literal_zero(l) {
                    return Expr::Literal(crate::ir::Literal::I64(0));
                }
                if is_literal_zero(r) {
                    return l.clone();
                }
            }

            // Rule: 0 >> x => 0, x >> 0 => x
            if *op == Op::Shr {
                if is_literal_zero(l) {
                    return Expr::Literal(crate::ir::Literal::I64(0));
                }
                if is_literal_zero(r) {
                    return l.clone();
                }
            }

            // Rule: x * 1 => x, 1 * x => x
            if *op == Op::Mul {
                if is_literal_one(r) {
                    return l.clone();
                }
                if is_literal_one(l) {
                    return r.clone();
                }
            }

            // Rule: (x != 0) in boolean context used as i128 carry => simplify
            // (0 != 0) => false => 0
            if *op == Op::Ne && is_literal_zero(l) && is_literal_zero(r) {
                return Expr::Literal(crate::ir::Literal::I64(0));
            }

            // Rule: (0 < 0) => false => 0
            if *op == Op::Lt && is_literal_zero(l) && is_literal_zero(r) {
                return Expr::Literal(crate::ir::Literal::I64(0));
            }

            // Sign-extension pattern: (((x >> 63) << 64) | x) => x
            // Also catches the << 32 variant used in i128 hi-part construction.
            if *op == Op::BitOr {
                if let Some(base) = match_sign_extension(l, r) {
                    return base;
                }
                if let Some(base) = match_sign_extension(r, l) {
                    return base;
                }
            }

            // Conservative constant folding: only fold comparisons where BOTH
            // sides are zero. Arbitrary constants (like frame offsets 0, 16)
            // may be simulation artifacts that don't represent logical values.
            // Folding them would incorrectly remove real code.
            if is_literal_zero(l) && is_literal_zero(r) {
                match op {
                    Op::Eq => return bool_literal(true),   // 0 == 0
                    Op::Le => return bool_literal(true),   // 0 <= 0
                    Op::Ge => return bool_literal(true),   // 0 >= 0
                    // Ne, Lt, Gt for 0,0 already handled above
                    _ => {}
                }
            }

            expr.clone()
        }

        // Rule: -(-x) => x  (double negation via UnOp)
        Expr::UnOp { op: crate::ir::UnOp::Neg, operand } => {
            if let Expr::UnOp { op: crate::ir::UnOp::Neg, operand: inner } = operand.as_ref() {
                return inner.as_ref().clone();
            }
            expr.clone()
        }

        // Rules for logical NOT
        Expr::UnOp { op: crate::ir::UnOp::Not, operand } => {
            // Double negation: !(!(x)) => x
            if let Expr::UnOp { op: crate::ir::UnOp::Not, operand: inner } = operand.as_ref() {
                return inner.as_ref().clone();
            }
            // De Morgan for comparisons: !(a != b) => (a == b), etc.
            if let Expr::BinOp { left, op, right } = operand.as_ref() {
                let flipped = match op {
                    Op::Ne => Some(Op::Eq),
                    Op::Eq => Some(Op::Ne),
                    Op::Lt => Some(Op::Ge),
                    Op::Ge => Some(Op::Lt),
                    Op::Gt => Some(Op::Le),
                    Op::Le => Some(Op::Gt),
                    _ => None,
                };
                if let Some(new_op) = flipped {
                    return Expr::BinOp {
                        left: left.clone(),
                        op: new_op,
                        right: right.clone(),
                    };
                }
            }
            // !0 => 1 (true), !nonzero_literal => 0 (false)
            if is_literal_zero(operand) {
                return Expr::Literal(crate::ir::Literal::I32(1));
            }
            if is_nonzero_literal(operand) {
                return Expr::Literal(crate::ir::Literal::I32(0));
            }
            expr.clone()
        }

        _ => expr.clone(),
    }
}

/// Check if an expression is a literal zero (i32 or i64).
fn is_literal_zero(expr: &Expr) -> bool {
    matches!(expr,
        Expr::Literal(crate::ir::Literal::I32(0))
        | Expr::Literal(crate::ir::Literal::I64(0))
    )
}

/// Check if an expression is a literal one (i32 or i64).
fn is_literal_one(expr: &Expr) -> bool {
    matches!(expr,
        Expr::Literal(crate::ir::Literal::I32(1))
        | Expr::Literal(crate::ir::Literal::I64(1))
    )
}

/// Check if an expression is a nonzero literal (i32 or i64).
fn is_nonzero_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Literal(crate::ir::Literal::I32(n)) => *n != 0,
        Expr::Literal(crate::ir::Literal::I64(n)) => *n != 0,
        _ => false,
    }
}

/// Create a boolean result literal (1 for true, 0 for false).
fn bool_literal(val: bool) -> Expr {
    Expr::Literal(crate::ir::Literal::I32(if val { 1 } else { 0 }))
}

/// Try to match the sign-extension pattern: ((x >> 63) << N) is the
/// shift-half, and `base` is the or-half. If shift-half's inner `x` equals
/// `base`, this is sign-extension and we return `base`.
///
/// Matches: `((x >> 63) << 64) | x` and `((x >> 63) << 32) | x`.
fn match_sign_extension(shift_half: &Expr, base: &Expr) -> Option<Expr> {
    // shift_half should be (something << 64) or (something << 32)
    if let Expr::BinOp { left: shl_inner, op: crate::ir::BinOp::Shl, right: shl_amount } = shift_half {
        let shift_amt = match shl_amount.as_ref() {
            Expr::Literal(crate::ir::Literal::I64(n)) => Some(*n),
            Expr::Literal(crate::ir::Literal::I32(n)) => Some(*n as i64),
            _ => None,
        };
        if matches!(shift_amt, Some(32) | Some(64)) {
            // shl_inner should be (x >> 63)
            if let Expr::BinOp { left: shr_inner, op: crate::ir::BinOp::Shr, right: shr_amount } = shl_inner.as_ref() {
                let shr_amt = match shr_amount.as_ref() {
                    Expr::Literal(crate::ir::Literal::I64(63)) => true,
                    Expr::Literal(crate::ir::Literal::I32(63)) => true,
                    _ => false,
                };
                if shr_amt && *shr_inner.as_ref() == *base {
                    return Some(base.clone());
                }
            }
        }
    }
    None
}

/// Collapse deeply nested i128 arithmetic expressions that survived
/// algebraic simplification.
///
/// After the algebraic pass, some expressions may still be deeply nested
/// carry-chain artifacts. This pass detects expressions deeper than a
/// threshold and replaces them with a descriptive `Raw` placeholder
/// showing which variables are involved.
fn collapse_deep_i128_stmt(stmt: Statement) -> Statement {
    match stmt {
        Statement::Let { name, mutable, value } => Statement::Let {
            name,
            mutable,
            value: collapse_deep_i128_expr(&value),
        },
        Statement::Assign { target, value } => Statement::Assign {
            target: collapse_deep_i128_expr(&target),
            value: collapse_deep_i128_expr(&value),
        },
        Statement::Expr(e) => Statement::Expr(collapse_deep_i128_expr(&e)),
        Statement::Return(Some(e)) => Statement::Return(Some(collapse_deep_i128_expr(&e))),
        Statement::Return(None) => Statement::Return(None),
        Statement::If { condition, then_body, else_body } => Statement::If {
            condition: collapse_deep_i128_expr(&condition),
            then_body: then_body.into_iter().map(collapse_deep_i128_stmt).collect(),
            else_body: else_body.into_iter().map(collapse_deep_i128_stmt).collect(),
        },
        Statement::While { condition, body } => Statement::While {
            condition: collapse_deep_i128_expr(&condition),
            body: body.into_iter().map(collapse_deep_i128_stmt).collect(),
        },
        Statement::Loop { body } => Statement::Loop {
            body: body.into_iter().map(collapse_deep_i128_stmt).collect(),
        },
        Statement::ForEach { var_name, collection, body } => Statement::ForEach {
            var_name,
            collection: collapse_deep_i128_expr(&collection),
            body: body.into_iter().map(collapse_deep_i128_stmt).collect(),
        },
        Statement::ForRange { var_name, bound, body } => Statement::ForRange {
            var_name,
            bound: collapse_deep_i128_expr(&bound),
            body: body.into_iter().map(collapse_deep_i128_stmt).collect(),
        },
    }
}

/// Collapse a deeply nested expression if it looks like i128 arithmetic.
///
/// An expression is considered i128 carry-chain noise if:
/// - Its depth exceeds 8 levels of nested BinOps
/// - It contains i128-characteristic constants (4294967295 = 0xFFFFFFFF,
///   4294966296 = 0xFFFFF998, shifts by 32/63/64)
///
/// Such expressions are replaced with a compact `/* i128 expr */`
/// representation showing the base variables involved.
fn collapse_deep_i128_expr(expr: &Expr) -> Expr {
    // Only collapse BinOp trees -- other expression types pass through
    // but their children may be collapsed.
    match expr {
        Expr::BinOp { .. } => {
            let depth = expr_depth(expr);
            if depth > 8 && has_i128_constants(expr) {
                // Collect the variable names used in this expression.
                let mut vars = std::collections::BTreeSet::new();
                collect_expr_var_names(expr, &mut vars);
                let var_list = if vars.is_empty() {
                    String::new()
                } else {
                    format!(" on {}", vars.into_iter().collect::<Vec<_>>().join(", "))
                };
                Expr::Raw(format!("/* i128 arithmetic{var_list} */"))
            } else {
                // Recursively try to collapse sub-expressions.
                match expr {
                    Expr::BinOp { left, op, right } => Expr::BinOp {
                        left: Box::new(collapse_deep_i128_expr(left)),
                        op: *op,
                        right: Box::new(collapse_deep_i128_expr(right)),
                    },
                    _ => unreachable!(),
                }
            }
        }
        Expr::MethodChain { receiver, calls } => Expr::MethodChain {
            receiver: Box::new(collapse_deep_i128_expr(receiver)),
            calls: calls.iter().map(|c| MethodCall {
                name: c.name.clone(),
                args: c.args.iter().map(|a| collapse_deep_i128_expr(a)).collect(),
            }).collect(),
        },
        Expr::HostCall { module, name, args } => Expr::HostCall {
            module: module.clone(),
            name: name.clone(),
            args: args.iter().map(|a| collapse_deep_i128_expr(a)).collect(),
        },
        Expr::MacroCall { name, args } => Expr::MacroCall {
            name: name.clone(),
            args: args.iter().map(|a| collapse_deep_i128_expr(a)).collect(),
        },
        Expr::StructLiteral { name, fields } => Expr::StructLiteral {
            name: name.clone(),
            fields: fields.iter().map(|(k, v)| (k.clone(), collapse_deep_i128_expr(v))).collect(),
        },
        Expr::EnumVariant { enum_name, variant_name, fields } => Expr::EnumVariant {
            enum_name: enum_name.clone(),
            variant_name: variant_name.clone(),
            fields: fields.iter().map(|f| collapse_deep_i128_expr(f)).collect(),
        },
        Expr::Ref(inner) => Expr::Ref(Box::new(collapse_deep_i128_expr(inner))),
        Expr::UnOp { op, operand } => Expr::UnOp {
            op: *op,
            operand: Box::new(collapse_deep_i128_expr(operand)),
        },
        Expr::Literal(_) | Expr::Var(_) | Expr::Raw(_) => expr.clone(),
    }
}

/// Compute the nesting depth of an expression tree.
fn expr_depth(expr: &Expr) -> usize {
    match expr {
        Expr::BinOp { left, right, .. } => {
            1 + expr_depth(left).max(expr_depth(right))
        }
        Expr::UnOp { operand, .. } => 1 + expr_depth(operand),
        Expr::Ref(inner) => expr_depth(inner),
        _ => 0,
    }
}

/// Check if an expression contains constants characteristic of i128
/// carry-chain arithmetic (0xFFFFFFFF, 0xFFFFF998, shifts by 32/63/64).
fn has_i128_constants(expr: &Expr) -> bool {
    match expr {
        Expr::Literal(crate::ir::Literal::I64(v)) => {
            // Common i128 expansion constants
            matches!(*v,
                4294967295     // 0xFFFF_FFFF (u32::MAX)
                | 4294966296   // 0xFFFFF998
                | 4294966299   // 0xFFFFF99B
                | 32 | 63 | 64
            )
        }
        Expr::Literal(crate::ir::Literal::I32(v)) => {
            matches!(*v, 32 | 63 | 64)
        }
        Expr::BinOp { left, op, right } => {
            // A shift by 32 or 63 is a strong i128 signal
            if matches!(op, crate::ir::BinOp::Shl | crate::ir::BinOp::Shr) {
                if let Expr::Literal(crate::ir::Literal::I64(n)) = right.as_ref() {
                    if matches!(*n, 32 | 63 | 64) {
                        return true;
                    }
                }
                if let Expr::Literal(crate::ir::Literal::I32(n)) = right.as_ref() {
                    if matches!(*n, 32 | 63 | 64) {
                        return true;
                    }
                }
            }
            has_i128_constants(left) || has_i128_constants(right)
        }
        Expr::UnOp { operand, .. } => has_i128_constants(operand),
        Expr::Ref(inner) => has_i128_constants(inner),
        _ => false,
    }
}
