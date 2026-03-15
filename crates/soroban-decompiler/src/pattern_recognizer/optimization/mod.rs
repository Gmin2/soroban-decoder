//! IR optimization passes applied after pattern recognition to clean up decompiled output.
//!
//! Each pass transforms the IR statement list in a specific way while preserving
//! program semantics. The passes are designed to be composed in a fixed order:
//!
//! 1. **CSE** (`cse.rs`) — Eliminate duplicate bindings that compute the same value.
//! 2. **Identity elimination** (`identity.rs`) — Remove `let x = y;` copy bindings.
//! 3. **Single-use inlining** (`identity.rs`) — Inline bindings used exactly once as a receiver.
//! 4. **Client splitting** (`identity.rs`) — Split chained `contract_client::new().method()` calls.
//! 5. **Constant guard folding** (`guards.rs`) — Fold `if` with constant/artifact conditions.
//! 6. **Comparison normalization** (`guards.rs`) — Rewrite `x < N+1` to `x <= N`.
//! 7. **i128 collapse** (`i128.rs`) — Simplify carry-chain arithmetic from WASM i128 expansion.
//! 8. **Scoped binding hoisting** (`hoisting.rs`) — Flatten `if` blocks whose bindings escape scope.
//! 9. **DCE** (`dce.rs`) — Eliminate unreferenced bindings and dead read-only chains.
//! 10. **Increment reconstruction** (`increment.rs`) — Recognize `get/add/set` as `count += X`.
//! 11. **Struct mutation reconstruction** (`struct_mutation.rs`) — Recognize struct rebuild as field mutation.

mod cse;
mod dce;
mod guards;
mod hoisting;
mod i128;
mod identity;
mod increment;
mod struct_mutation;

pub use cse::eliminate_common_subexprs;
pub use dce::eliminate_dead_vars;
pub use guards::{fold_constant_guards, normalize_comparisons};
pub use hoisting::hoist_scoped_bindings;
pub use i128::collapse_i128_patterns;
pub use identity::{eliminate_identity_bindings, inline_single_use_bindings, split_client_calls};
pub use increment::reconstruct_increment_pattern;
pub use struct_mutation::reconstruct_struct_mutation;

use std::collections::HashMap;

use crate::ir::{Expr, MethodCall, Statement};

/// Rewrite variable references in a statement according to the rename map.
///
/// Recursively walks all sub-statements and expressions, replacing any `Var`
/// whose bare name (without leading `&` or dotted suffix) appears in `renames`
/// with the corresponding target name. Used by CSE and identity elimination.
pub(super) fn rename_stmt_vars(stmt: Statement, renames: &HashMap<String, String>) -> Statement {
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
        Statement::ForEach { var_name, collection, body } => Statement::ForEach {
            var_name,
            collection: rename_expr_vars(&collection, renames),
            body: body.into_iter().map(|s| rename_stmt_vars(s, renames)).collect(),
        },
        Statement::ForRange { var_name, bound, body } => Statement::ForRange {
            var_name,
            bound: rename_expr_vars(&bound, renames),
            body: body.into_iter().map(|s| rename_stmt_vars(s, renames)).collect(),
        },
    }
}

/// Rewrite variable references in an expression according to the rename map.
///
/// Handles `&`-prefixed references and dotted paths (e.g., `state.count` is
/// renamed when `state` maps to a new name). Returns a new expression with
/// all matching variable references replaced.
pub(super) fn rename_expr_vars(expr: &Expr, renames: &HashMap<String, String>) -> Expr {
    match expr {
        Expr::Var(name) => {
            let (prefix, bare) = if let Some(stripped) = name.strip_prefix('&') {
                ("&", stripped)
            } else {
                ("", name.as_str())
            };
            if let Some(new_name) = renames.get(bare) {
                Expr::Var(format!("{}{}", prefix, new_name))
            } else if let Some(dot_pos) = bare.find('.') {
                // Handle dotted paths: "state.count" -> "val.count" when "state" -> "val"
                let base = &bare[..dot_pos];
                let suffix = &bare[dot_pos..]; // includes the dot
                if let Some(new_base) = renames.get(base) {
                    Expr::Var(format!("{}{}{}", prefix, new_base, suffix))
                } else {
                    expr.clone()
                }
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
        Expr::Ref(inner) => Expr::Ref(Box::new(rename_expr_vars(inner, renames))),
        Expr::Literal(_) | Expr::Raw(_) => expr.clone(),
    }
}

/// Check if an expression has observable side effects (should not be eliminated).
///
/// Side-effectful expressions must be preserved even when their result is unused.
/// Method chains ending in read-only operations (`has`, `get`, `len`, etc.) are
/// considered safe to eliminate. Note that `new` is intentionally treated as
/// side-effectful since `Vec::new` and `Map::new` are constructors whose
/// bindings must be kept.
pub(super) fn expr_has_side_effects(expr: &Expr) -> bool {
    match expr {
        Expr::MethodChain { calls, .. } => {
            // Read-only method chains can be safely eliminated.
            // Check if the last method in the chain is a known read-only operation.
            if let Some(last) = calls.last() {
                let read_only = matches!(last.name.as_str(),
                    "has" | "get" | "sequence" | "timestamp"
                    | "current_contract_address" | "ledger"
                    | "storage" | "persistent" | "instance" | "temporary"
                    | "len" | "cmp" | "keys" | "values"
                    | "unwrap_or_default" | "unwrap"
                    // Note: "new" is intentionally NOT here -- Vec::new, Map::new
                    // are side-effectful constructors whose bindings must be kept.
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
        Expr::Ref(inner) => expr_has_side_effects(inner),
        _ => false,
    }
}

/// Collect all variable names referenced within an expression into a set.
///
/// Strips `&` prefixes to get the bare name. Used by the i128 collapse pass
/// to identify which variables participate in a carry-chain expression.
pub(super) fn collect_expr_var_names(expr: &Expr, names: &mut std::collections::BTreeSet<String>) {
    match expr {
        Expr::Var(name) => {
            let bare = name.strip_prefix('&').unwrap_or(name);
            names.insert(bare.to_string());
        }
        Expr::BinOp { left, right, .. } => {
            collect_expr_var_names(left, names);
            collect_expr_var_names(right, names);
        }
        Expr::UnOp { operand, .. } => collect_expr_var_names(operand, names),
        Expr::Ref(inner) => collect_expr_var_names(inner, names),
        Expr::MethodChain { receiver, calls } => {
            collect_expr_var_names(receiver, names);
            for call in calls {
                for arg in &call.args { collect_expr_var_names(arg, names); }
            }
        }
        Expr::HostCall { args, .. } | Expr::MacroCall { args, .. } => {
            for arg in args { collect_expr_var_names(arg, names); }
        }
        Expr::StructLiteral { fields, .. } => {
            for (_, val) in fields { collect_expr_var_names(val, names); }
        }
        Expr::EnumVariant { fields, .. } => {
            for f in fields { collect_expr_var_names(f, names); }
        }
        Expr::Literal(_) | Expr::Raw(_) => {}
    }
}
