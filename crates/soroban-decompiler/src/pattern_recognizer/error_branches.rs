//! Error branch reconstruction for Result-returning functions.
//!
//! Detects the WASM default-then-override pattern where
//! `local = Error; if (ok) { ...; local = Ok; } return local;`
//! was flattened during simulation. Moves the Return into the if-then body
//! and adds an `Err(...)` return to the else branch.

use stellar_xdr::curr::ScSpecEntry;

use crate::ir::{Expr, Statement};

/// Reconstruct error branches in Result-returning functions.
///
/// Detects the WASM default-then-override pattern where `local = Error; if (ok) { ...; local = Ok; } return local;`
/// was flattened to `If { cond, then: [side_effects], else: [] }; Return(val)` because the error
/// value was lost during simulation. Moves the Return into the if-then body and adds an Err return
/// to the else branch.
pub(super) fn reconstruct_error_branches(stmts: Vec<Statement>, all_entries: &[ScSpecEntry]) -> Vec<Statement> {
    // Find the first error enum variant value for the Err branch.
    let first_error_val = all_entries.iter().find_map(|e| {
        if let ScSpecEntry::UdtErrorEnumV0(err) = e {
            err.cases.first().map(|c| c.value)
        } else {
            None
        }
    });
    let error_val = match first_error_val {
        Some(v) => v,
        None => return stmts, // No error enum defined, nothing to do
    };

    let n = stmts.len();
    if n < 2 {
        return stmts;
    }

    // Look for the pattern: If { cond, then: [has side effects], else: [] } followed by Return(val)
    let last_idx = n - 1;
    let penult_idx = n - 2;

    let is_pattern = matches!(
        (&stmts[penult_idx], &stmts[last_idx]),
        (
            Statement::If { else_body, .. },
            Statement::Return(Some(_))
        ) if else_body.is_empty()
    );

    if !is_pattern {
        return stmts;
    }

    // Check that the if-then body has side effects (storage write, event publish, etc.)
    // to distinguish from read-only guards that shouldn't get error branches.
    let has_side_effects = if let Statement::If { then_body, .. } = &stmts[penult_idx] {
        then_body.iter().any(|s| matches!(s, Statement::Expr(_)))
    } else {
        false
    };

    if !has_side_effects {
        return stmts;
    }

    // Reconstruct: move Return into if-then, add Err return to else
    let mut result: Vec<Statement> = stmts[..penult_idx].to_vec();
    let return_stmt = stmts[last_idx].clone();

    if let Statement::If { condition, then_body, .. } = &stmts[penult_idx] {
        let mut new_then = then_body.clone();
        new_then.push(return_stmt);

        let error_placeholder = format!("__contract_error_{}", error_val);
        let else_body = vec![
            Statement::Return(Some(Expr::Var(error_placeholder))),
        ];

        result.push(Statement::If {
            condition: condition.clone(),
            then_body: new_then,
            else_body,
        });
    }

    result
}
