use crate::ir::Statement;

use super::super::optimization::dce::collect_stmt_refs;

/// Flatten `if` blocks when their inner `Let` bindings are referenced by
/// subsequent statements.
///
/// WASM br_if patterns often produce:
/// ```text
/// let exists = has(...);
/// if (exists == 1) { let val = get(...); }
/// set(&key, &(val + 1));  // val is used OUTSIDE the if!
/// ```
///
/// This pass detects such cases and inlines the if-body to make the
/// code semantically valid.
pub fn hoist_scoped_bindings(stmts: Vec<Statement>) -> Vec<Statement> {
    if stmts.len() < 2 {
        return stmts;
    }

    // Collect all names referenced across ALL statements for future-reference checks.
    let mut all_referenced = std::collections::HashSet::new();
    for stmt in &stmts {
        collect_stmt_refs(stmt, &mut all_referenced);
    }

    let mut result = Vec::new();
    for stmt in stmts {
        match stmt {
            Statement::If { condition, then_body, else_body } => {
                // Recurse into nested blocks first.
                let then_hoisted = hoist_scoped_bindings(then_body);
                let else_hoisted = hoist_scoped_bindings(else_body);

                // Check if any Let binding inside the then-body defines a name
                // that is referenced by statements OUTSIDE this if block.
                let should_flatten = has_externally_referenced_bindings(
                    &then_hoisted, &all_referenced,
                ) || has_externally_referenced_bindings(
                    &else_hoisted, &all_referenced,
                );

                if should_flatten {
                    // Inline both branches.
                    result.extend(then_hoisted);
                    result.extend(else_hoisted);
                } else {
                    result.push(Statement::If {
                        condition,
                        then_body: then_hoisted,
                        else_body: else_hoisted,
                    });
                }
            }
            Statement::While { condition, body } => {
                result.push(Statement::While {
                    condition,
                    body: hoist_scoped_bindings(body),
                });
            }
            Statement::Loop { body } => {
                result.push(Statement::Loop {
                    body: hoist_scoped_bindings(body),
                });
            }
            Statement::ForEach { var_name, collection, body } => {
                result.push(Statement::ForEach {
                    var_name,
                    collection,
                    body: hoist_scoped_bindings(body),
                });
            }
            Statement::ForRange { var_name, bound, body } => {
                result.push(Statement::ForRange {
                    var_name,
                    bound,
                    body: hoist_scoped_bindings(body),
                });
            }
            other => result.push(other),
        }
    }

    result
}

/// Check if any Let binding in a statement list defines a name that appears
/// in the given reference set (which includes names from sibling/subsequent
/// statements).
fn has_externally_referenced_bindings(
    stmts: &[Statement],
    external_refs: &std::collections::HashSet<String>,
) -> bool {
    for stmt in stmts {
        if let Statement::Let { name, .. } = stmt {
            let check_name = name.replace('.', "_").replace('[', "_").replace(']', "");
            if external_refs.contains(name) || external_refs.contains(&check_name) {
                // Also check: the name must be referenced by OTHER statements,
                // not just by itself. We verify this by checking if the name
                // appears in the external_refs which was collected from ALL stmts.
                return true;
            }
        }
        // Recurse into nested if/loop blocks.
        match stmt {
            Statement::If { then_body, else_body, .. } => {
                if has_externally_referenced_bindings(then_body, external_refs) {
                    return true;
                }
                if has_externally_referenced_bindings(else_body, external_refs) {
                    return true;
                }
            }
            Statement::While { body, .. }
            | Statement::Loop { body }
            | Statement::ForEach { body, .. }
            | Statement::ForRange { body, .. } => {
                if has_externally_referenced_bindings(body, external_refs) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}
