//! Storage key resolution and tuple key synthesis.
//!
//! Resolves unresolved storage keys (e.g. `Default::default()` or `local_N`)
//! to `DataKey::Variant` enum variants, and synthesizes `DataKey::Name(param)`
//! tuple keys from `Symbol::new` + `vec!` storage key patterns.

use std::collections::HashMap;

use stellar_xdr::curr::ScSpecEntry;

use crate::ir::{Expr, Literal, MethodCall, Statement};

/// Resolve unresolved storage keys to enum variants.
///
/// When `env.storage().set(&local_N, &val)` or `env.storage().set(&Default::default(), &val)`
/// appears, try to match the key against the contract's DataKey enum.
/// Detection: scan for storage set/get calls with Var("local_*") or
/// Raw("Default::default()") keys, and replace with the appropriate
/// DataKey::Variant based on the position/usage pattern.
pub(super) fn resolve_storage_keys(
    stmts: Vec<Statement>,
    all_entries: &[ScSpecEntry],
) -> Vec<Statement> {
    // Find enum types that look like storage keys (variants without tuple data,
    // matching the pattern "DataKey", "Key", etc.)
    let key_enum = all_entries.iter().find_map(|e| {
        if let ScSpecEntry::UdtUnionV0(u) = e {
            let name = u.name.to_utf8_string_lossy();
            // Common storage key enum patterns
            if name.contains("Key") || name.contains("DataKey") {
                let variants: Vec<String> = u.cases.iter().map(|c| match c {
                    stellar_xdr::curr::ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_utf8_string_lossy(),
                    stellar_xdr::curr::ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_utf8_string_lossy(),
                }).collect();
                return Some((name, variants));
            }
        }
        // Also check plain enums (not unions)
        if let ScSpecEntry::UdtEnumV0(e) = e {
            let name = e.name.to_utf8_string_lossy();
            if name.contains("Key") || name.contains("DataKey") {
                let variants: Vec<String> = e.cases.iter()
                    .map(|c| c.name.to_utf8_string_lossy())
                    .collect();
                return Some((name, variants));
            }
        }
        None
    });

    let Some((enum_name, variants)) = key_enum else {
        return stmts;
    };

    // Collect variable names that are already bound to enum variants.
    // These are correctly resolved and should NOT be replaced.
    let mut resolved_vars: std::collections::HashSet<String> = std::collections::HashSet::new();
    for stmt in &stmts {
        if let Statement::Let { name, value, .. } = stmt {
            if matches!(value, Expr::EnumVariant { enum_name: en, .. } if en == &enum_name) {
                resolved_vars.insert(name.clone());
            }
        }
    }

    let mut key_to_variant: HashMap<String, usize> = HashMap::new();
    let mut next_substantive = variants.iter().position(|v| !v.to_lowercase().contains("init")).unwrap_or(0);
    let mut next_marker = variants.iter().position(|v| v.to_lowercase().contains("init")).unwrap_or(0);

    stmts.into_iter().map(|stmt| {
        resolve_key_in_stmt(stmt, &enum_name, &variants, &mut key_to_variant,
            &mut next_substantive, &mut next_marker, &resolved_vars)
    }).collect()
}

fn resolve_key_in_stmt(
    stmt: Statement,
    enum_name: &str,
    variants: &[String],
    key_map: &mut HashMap<String, usize>,
    next_sub: &mut usize,
    next_mark: &mut usize,
    resolved_vars: &std::collections::HashSet<String>,
) -> Statement {
    match stmt {
        // Look for storage set/get with unresolved keys
        Statement::Expr(ref expr) | Statement::Let { value: ref expr, .. } => {
            if let Some(resolved) = try_resolve_key_in_method_chain(expr, enum_name, variants, key_map, next_sub, next_mark, resolved_vars) {
                match stmt {
                    Statement::Expr(_) => Statement::Expr(resolved),
                    Statement::Let { name, mutable, .. } => Statement::Let { name, mutable, value: resolved },
                    _ => unreachable!(),
                }
            } else {
                stmt
            }
        }
        Statement::If { condition, then_body, else_body } => Statement::If {
            condition,
            then_body: then_body.into_iter()
                .map(|s| resolve_key_in_stmt(s, enum_name, variants, key_map, next_sub, next_mark, resolved_vars))
                .collect(),
            else_body: else_body.into_iter()
                .map(|s| resolve_key_in_stmt(s, enum_name, variants, key_map, next_sub, next_mark, resolved_vars))
                .collect(),
        },
        other => other,
    }
}

fn try_resolve_key_in_method_chain(
    expr: &Expr,
    enum_name: &str,
    variants: &[String],
    key_map: &mut HashMap<String, usize>,
    next_sub: &mut usize,
    next_mark: &mut usize,
    resolved_vars: &std::collections::HashSet<String>,
) -> Option<Expr> {
    if let Expr::MethodChain { receiver, calls } = expr {
        // Find the storage operation in the chain. It might not be the
        // last call due to .unwrap_or_default() / .unwrap() suffixes.
        let storage_op_idx = calls.iter().position(|c| {
            (c.name == "set" || c.name == "get" || c.name == "has" || c.name == "remove")
                && !c.args.is_empty()
        });
        let is_storage_op = calls.first().map_or(false, |c| c.name == "storage")
            && storage_op_idx.is_some();

        if is_storage_op {
            let op_idx = storage_op_idx.unwrap();
            let storage_call = &calls[op_idx];
            if let Some(key_arg) = storage_call.args.first() {
                // A storage key is "unresolved" if it's NOT already
                // a correctly reconstructed enum variant. Since we know
                // the contract has a DataKey enum, any key that isn't an
                // EnumVariant of that enum needs resolution.
                let is_already_resolved = match key_arg {
                    Expr::Ref(inner) => match inner.as_ref() {
                        Expr::EnumVariant { enum_name: en, .. } => en == enum_name,
                        // Variable that was bound to an enum variant
                        Expr::Var(name) => resolved_vars.contains(name),
                        _ => false,
                    },
                    Expr::EnumVariant { enum_name: en, .. } => en == enum_name,
                    Expr::Var(name) => resolved_vars.contains(name),
                    _ => false,
                };
                let is_unresolved = !is_already_resolved;

                if !is_unresolved {
                    return None;
                }

                // Try to pick the best variant:
                // - For .set() with a struct value: pick a variant that sounds
                //   like the value type (e.g., "Balance" for ClaimableBalance)
                // - For .set() with () value: pick a marker variant ("Init")
                // - Otherwise: pick first unused variant
                let val_arg = if storage_call.name == "set" {
                    storage_call.args.get(1)
                } else {
                    None
                };

                let is_void_value = val_arg.map_or(false, |v| matches!(v,
                    Expr::Ref(inner) if matches!(inner.as_ref(), Expr::Literal(Literal::Unit))
                ));

                // Create a key signature from the unresolved expression
                // so the same key expression gets the same variant.
                let key_sig = format!("{:?}", key_arg);

                // For remove operations, prefer to reuse the variant from
                // the most recent get/has on the same storage tier -- you
                // typically remove what you just loaded.
                let reuse_last = if storage_call.name == "remove" && !key_map.is_empty() {
                    key_map.values().last().copied()
                } else {
                    None
                };

                // `has` operations peek at the next variant without consuming it.
                // They check existence of the same key that a subsequent get/set uses.
                let is_peek = storage_call.name == "has";

                let idx = if let Some(&existing) = key_map.get(&key_sig) {
                    existing
                } else if let Some(last_idx) = reuse_last {
                    last_idx
                } else if is_void_value {
                    // Void value -> pick marker-sounding variant
                    let idx = *next_mark;
                    if !is_peek { *next_mark = (*next_mark + 1).min(variants.len()); }
                    idx
                } else {
                    // Struct/value -> pick substantive variant
                    let idx = *next_sub;
                    if !is_peek { *next_sub = (*next_sub + 1).min(variants.len()); }
                    idx
                };
                key_map.insert(key_sig, idx);

                if idx < variants.len() {
                    let key_expr = Expr::EnumVariant {
                        enum_name: enum_name.to_string(),
                        variant_name: variants[idx].clone(),
                        fields: vec![],
                    };

                    let mut new_calls = calls.clone();
                    let target = &mut new_calls[op_idx];
                    if !target.args.is_empty() {
                        target.args[0] = Expr::Ref(Box::new(key_expr));
                    }

                    return Some(Expr::MethodChain {
                        receiver: receiver.clone(),
                        calls: new_calls,
                    });
                }
            }
        }
    }
    None
}

/// Synthesize DataKey enum variants from Symbol::new + vec storage key patterns.
///
/// When storage operations use `let sym = Symbol::new(&env, "Name");
/// let args = vec![&env, sym, param]; storage.set(&args, ...)`,
/// replace with `storage.set(&DataKey::Name(param), ...)`.
pub(super) fn synthesize_tuple_keys(
    stmts: Vec<Statement>,
    all_entries: &[ScSpecEntry],
) -> Vec<Statement> {
    // Skip if a DataKey enum already exists in the spec
    let has_key_enum = all_entries.iter().any(|e| match e {
        ScSpecEntry::UdtUnionV0(u) => {
            let name = u.name.to_utf8_string_lossy();
            name.contains("Key") || name.contains("DataKey")
        }
        ScSpecEntry::UdtEnumV0(e) => {
            let name = e.name.to_utf8_string_lossy();
            name.contains("Key") || name.contains("DataKey")
        }
        _ => false,
    });
    if has_key_enum { return stmts; }

    // Collect symbol bindings: sym_var -> variant_name
    let mut sym_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for stmt in &stmts {
        if let Statement::Let { name, value: Expr::HostCall { module, name: fn_name, args }, .. } = stmt {
            if module == "Symbol" && fn_name == "new" {
                if let Some(Expr::Literal(Literal::Str(variant))) = args.get(1) {
                    sym_map.insert(name.clone(), variant.clone());
                }
            }
        }
    }
    if sym_map.is_empty() { return stmts; }

    // Collect vec bindings: vec_var -> (sym_var, extra_fields)
    let mut vec_map: std::collections::HashMap<String, (String, Vec<Expr>)> = std::collections::HashMap::new();
    for stmt in &stmts {
        if let Statement::Let { name, value: Expr::MacroCall { name: mac, args }, .. } = stmt {
            if mac == "vec" && args.len() >= 2 {
                // args[0] = &env, args[1] = sym_var, args[2..] = fields
                if let Some(Expr::Var(sym_var)) = args.get(1) {
                    if sym_map.contains_key(sym_var) {
                        let fields: Vec<Expr> = args[2..].to_vec();
                        vec_map.insert(name.clone(), (sym_var.clone(), fields));
                    }
                }
            }
        }
    }
    if vec_map.is_empty() { return stmts; }

    // Rewrite: drop sym/vec Let bindings, replace storage key references
    let sym_vars: std::collections::HashSet<String> = sym_map.keys().cloned().collect();
    let vec_vars: std::collections::HashSet<String> = vec_map.keys().cloned().collect();

    stmts.into_iter().filter_map(|stmt| {
        // Drop sym = Symbol::new() bindings
        if let Statement::Let { name, .. } = &stmt {
            if sym_vars.contains(name) { return None; }
            if vec_vars.contains(name) { return None; }
        }
        // Replace vec_var references in storage calls with DataKey variants
        Some(replace_vec_keys_in_stmt(stmt, &sym_map, &vec_map))
    }).collect()
}

fn replace_vec_keys_in_stmt(
    stmt: Statement,
    sym_map: &std::collections::HashMap<String, String>,
    vec_map: &std::collections::HashMap<String, (String, Vec<Expr>)>,
) -> Statement {
    match stmt {
        Statement::Expr(e) => Statement::Expr(replace_vec_keys_in_expr(e, sym_map, vec_map)),
        Statement::Let { name, mutable, value } => Statement::Let {
            name, mutable,
            value: replace_vec_keys_in_expr(value, sym_map, vec_map),
        },
        Statement::If { condition, then_body, else_body } => Statement::If {
            condition: replace_vec_keys_in_expr(condition, sym_map, vec_map),
            then_body: then_body.into_iter().map(|s| replace_vec_keys_in_stmt(s, sym_map, vec_map)).collect(),
            else_body: else_body.into_iter().map(|s| replace_vec_keys_in_stmt(s, sym_map, vec_map)).collect(),
        },
        other => other,
    }
}

fn replace_vec_keys_in_expr(
    expr: Expr,
    sym_map: &std::collections::HashMap<String, String>,
    vec_map: &std::collections::HashMap<String, (String, Vec<Expr>)>,
) -> Expr {
    match expr {
        Expr::Ref(inner) => {
            if let Expr::Var(ref var_name) = *inner {
                if let Some((sym_var, fields)) = vec_map.get(var_name) {
                    if let Some(variant_name) = sym_map.get(sym_var) {
                        return Expr::Ref(Box::new(Expr::EnumVariant {
                            enum_name: "DataKey".into(),
                            variant_name: variant_name.clone(),
                            fields: fields.clone(),
                        }));
                    }
                }
            }
            Expr::Ref(Box::new(replace_vec_keys_in_expr(*inner, sym_map, vec_map)))
        }
        Expr::Var(ref var_name) => {
            if let Some((sym_var, fields)) = vec_map.get(var_name) {
                if let Some(variant_name) = sym_map.get(sym_var) {
                    return Expr::EnumVariant {
                        enum_name: "DataKey".into(),
                        variant_name: variant_name.clone(),
                        fields: fields.clone(),
                    };
                }
            }
            expr
        }
        Expr::MethodChain { receiver, calls } => Expr::MethodChain {
            receiver: Box::new(replace_vec_keys_in_expr(*receiver, sym_map, vec_map)),
            calls: calls.into_iter().map(|c| MethodCall {
                name: c.name,
                args: c.args.into_iter().map(|a| replace_vec_keys_in_expr(a, sym_map, vec_map)).collect(),
            }).collect(),
        },
        Expr::BinOp { op, left, right } => Expr::BinOp {
            op,
            left: Box::new(replace_vec_keys_in_expr(*left, sym_map, vec_map)),
            right: Box::new(replace_vec_keys_in_expr(*right, sym_map, vec_map)),
        },
        other => other,
    }
}
