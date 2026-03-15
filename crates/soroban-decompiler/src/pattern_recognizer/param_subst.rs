//! Parameter pass-through substitution.
//!
//! When the original contract passes a struct parameter straight through
//! (e.g. `ClaimableBalance { time_bound, ... }`), the WASM compiler unpacks
//! and repacks it through memory, which our simulation may reconstruct
//! incorrectly. This pass detects the pattern and substitutes the parameter
//! reference.

use stellar_xdr::curr::{ScSpecEntry, ScSpecFunctionV0, ScSpecTypeDef};

use crate::ir::{Expr, Statement};

/// Substitute struct literal fields with function parameters when the types match.
///
/// When the original code does `ClaimableBalance { time_bound, ... }` passing
/// a parameter directly, the WASM unpacks and repacks it through memory.
/// Our simulation may reconstruct the fields incorrectly. This pass detects
/// the pattern and substitutes the parameter reference.
pub(super) fn substitute_param_pass_through(
    stmts: Vec<Statement>,
    spec: &ScSpecFunctionV0,
    all_entries: &[ScSpecEntry],
) -> Vec<Statement> {
    // Build a map of param_name -> type_name for UDT (struct/enum) params.
    let param_types: Vec<(String, String)> = spec.inputs.iter().filter_map(|input| {
        if let ScSpecTypeDef::Udt(udt) = &input.type_ {
            Some((input.name.to_utf8_string_lossy(), udt.name.to_utf8_string_lossy()))
        } else {
            None
        }
    }).collect();

    if param_types.is_empty() {
        return stmts;
    }

    // Collect struct type names defined in the spec.
    let struct_names: std::collections::HashSet<String> = all_entries.iter().filter_map(|e| {
        if let ScSpecEntry::UdtStructV0(s) = e {
            Some(s.name.to_utf8_string_lossy())
        } else {
            None
        }
    }).collect();

    stmts.into_iter().map(|stmt| {
        substitute_pass_through_stmt(stmt, &param_types, &struct_names)
    }).collect()
}

fn substitute_pass_through_stmt(
    stmt: Statement,
    param_types: &[(String, String)],
    struct_names: &std::collections::HashSet<String>,
) -> Statement {
    match stmt {
        // When a Let binding creates a struct literal, check if any field
        // references a reconstructed struct that could be a parameter.
        Statement::Let { name, mutable, value } => Statement::Let {
            name,
            mutable,
            value: substitute_pass_through_expr(value, param_types, struct_names),
        },
        Statement::Expr(e) => Statement::Expr(
            substitute_pass_through_expr(e, param_types, struct_names),
        ),
        Statement::If { condition, then_body, else_body } => Statement::If {
            condition,
            then_body: then_body.into_iter()
                .map(|s| substitute_pass_through_stmt(s, param_types, struct_names))
                .collect(),
            else_body: else_body.into_iter()
                .map(|s| substitute_pass_through_stmt(s, param_types, struct_names))
                .collect(),
        },
        other => other,
    }
}

fn substitute_pass_through_expr(
    expr: Expr,
    param_types: &[(String, String)],
    struct_names: &std::collections::HashSet<String>,
) -> Expr {
    match expr {
        Expr::StructLiteral { name, fields } => {
            // For each field: if the field's type matches a struct AND there's
            // a function parameter of that struct type with a matching name,
            // replace the field value with the parameter reference.
            let new_fields: Vec<(String, Expr)> = fields.into_iter().map(|(field_name, field_val)| {
                // Check if this field references a reconstructed struct
                // that could be replaced by a parameter.
                if let Expr::Var(ref var_name) = field_val {
                    // The var might be "time_bound_1" referencing a Let binding
                    // that builds a struct. Check if there's a param with the
                    // base name and matching struct type.
                    let base = var_name.trim_end_matches(|c: char| c == '_' || c.is_ascii_digit());
                    for (param_name, param_type) in param_types {
                        if (base == param_name || &field_name == param_name)
                            && struct_names.contains(param_type)
                        {
                            return (field_name, Expr::Var(param_name.clone()));
                        }
                    }
                }
                // Also handle the case where the field value is clearly wrong
                // (a variable of a completely different type is used for a
                // struct-typed field). Check by field name matching a param.
                for (param_name, param_type) in param_types {
                    if &field_name == param_name && struct_names.contains(param_type) {
                        // Field name matches a parameter name and the param
                        // is a struct type -> use the parameter.
                        return (field_name, Expr::Var(param_name.clone()));
                    }
                }
                (field_name, substitute_pass_through_expr(field_val, param_types, struct_names))
            }).collect();
            Expr::StructLiteral { name, fields: new_fields }
        }
        other => other,
    }
}
