use std::collections::HashMap;

use crate::ir::{Expr, Statement};

use super::{expr_has_side_effects, rename_expr_vars, rename_stmt_vars};

/// Remove duplicate Let bindings that produce the same expression value.
///
/// When `let sym_1 = Symbol::new(&env, "Counter")` duplicates an earlier
/// `let sym = Symbol::new(&env, "Counter")`, remove `sym_1` and rewrite
/// all references to `sym_1` as `sym`.
pub fn eliminate_common_subexprs(stmts: Vec<Statement>) -> Vec<Statement> {
    // Map from expression (via PartialEq) to the first binding name.
    let mut seen: Vec<(Expr, String)> = Vec::new();
    // Map from duplicate name -> original name.
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
