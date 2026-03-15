use std::collections::HashMap;

use stellar_xdr::curr::{ScSpecEntry, ScSpecUdtUnionCaseV0};
use walrus::ir::Value;

use crate::ir::{Expr, Literal, MethodCall, Statement};
use crate::wasm_analysis::{StackValue, TrackedHostCall};

use super::super::val_decoding::{resolve_arg, as_ref};
use super::types::to_snake_case;

/// Recognize `get_contract_data(key, storage_type)` -> `env.storage().{tier}().get(&key)`
pub(super) fn recognize_storage_get(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
    all_entries: &[ScSpecEntry],
) -> Option<Statement> {
    let tier = extract_storage_tier(call.args.last()?)?;
    let raw_key = resolve_arg(&call.args[0], param_names, crn);
    let key_expr = as_ref(
        try_reconstruct_enum_key(&raw_key, all_entries)
            .or_else(|| try_enum_key_from_stack_value(&call.args[0], crn, all_entries))
            .unwrap_or(raw_key),
    );

    Some(Statement::Let {
        name: "val".into(),
        mutable: false,
        value: Expr::MethodChain {
            receiver: Box::new(Expr::Var("env".into())),
            calls: vec![
                MethodCall { name: "storage".into(), args: vec![] },
                MethodCall { name: tier.into(), args: vec![] },
                MethodCall { name: "get".into(), args: vec![key_expr] },
                MethodCall { name: "unwrap_or".into(), args: vec![Expr::Literal(Literal::I64(0))] },
            ],
        },
    })
}

/// Recognize `put_contract_data(key, val, storage_type)` as
/// `env.storage().{tier}().set(&key, &val)`.
pub(super) fn recognize_storage_set(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
    all_entries: &[ScSpecEntry],
) -> Option<Statement> {
    let debug = std::env::var("DECOMPILER_DEBUG").is_ok();
    let tier = extract_storage_tier(call.args.last()?)?;
    if debug {
        eprintln!("[storage_set] tier={}, key_arg={:?}", tier, call.args[0]);
        if let StackValue::CallResult(id) = &call.args[0] {
            eprintln!("[storage_set] key is CallResult({}), CRN name={:?}", id, crn.get(id));
        }
    }
    let raw_key = resolve_arg(&call.args[0], param_names, crn);
    if debug {
        eprintln!("[storage_set] raw_key resolved to: {:?}", raw_key);
    }
    let enum_from_expr = try_reconstruct_enum_key(&raw_key, all_entries);
    if debug {
        eprintln!("[storage_set] try_reconstruct_enum_key: {:?}", enum_from_expr);
    }
    let enum_from_sv = if enum_from_expr.is_none() {
        let r = try_enum_key_from_stack_value(&call.args[0], crn, all_entries);
        if debug {
            eprintln!("[storage_set] try_enum_key_from_stack_value: {:?}", r);
        }
        r
    } else { None };
    let key_expr = as_ref(
        enum_from_expr
            .or(enum_from_sv)
            .unwrap_or(raw_key),
    );
    if debug {
        eprintln!("[storage_set] final key_expr: {:?}", key_expr);
    }
    let val_expr = as_ref(resolve_arg(call.args.get(1)?, param_names, crn));

    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![
            MethodCall { name: "storage".into(), args: vec![] },
            MethodCall { name: tier.into(), args: vec![] },
            MethodCall { name: "set".into(), args: vec![key_expr, val_expr] },
        ],
    }))
}

/// Recognize `has_contract_data(key, storage_type)` -> `env.storage().{tier}().has(&key)`
pub(super) fn recognize_storage_has(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
    all_entries: &[ScSpecEntry],
) -> Option<Statement> {
    let tier = extract_storage_tier(call.args.last()?)?;
    let raw_key = resolve_arg(&call.args[0], param_names, crn);
    let key_expr = as_ref(
        try_reconstruct_enum_key(&raw_key, all_entries)
            .or_else(|| try_enum_key_from_stack_value(&call.args[0], crn, all_entries))
            .unwrap_or(raw_key),
    );

    Some(Statement::Let {
        name: "exists".into(),
        mutable: false,
        value: Expr::MethodChain {
            receiver: Box::new(Expr::Var("env".into())),
            calls: vec![
                MethodCall { name: "storage".into(), args: vec![] },
                MethodCall { name: tier.into(), args: vec![] },
                MethodCall { name: "has".into(), args: vec![key_expr] },
            ],
        },
    })
}

/// Recognize `del_contract_data(key, storage_type)` -> `env.storage().{tier}().remove(&key)`
pub(super) fn recognize_storage_del(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
    all_entries: &[ScSpecEntry],
) -> Option<Statement> {
    let tier = extract_storage_tier(call.args.last()?)?;
    let raw_key = resolve_arg(&call.args[0], param_names, crn);
    let key_expr = as_ref(
        try_reconstruct_enum_key(&raw_key, all_entries)
            .or_else(|| try_enum_key_from_stack_value(&call.args[0], crn, all_entries))
            .unwrap_or(raw_key),
    );

    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![
            MethodCall { name: "storage".into(), args: vec![] },
            MethodCall { name: tier.into(), args: vec![] },
            MethodCall { name: "remove".into(), args: vec![key_expr] },
        ],
    }))
}

/// Try to reconstruct an enum variant expression from a resolved key expression.
///
/// When a storage key was built via `vec_new_from_linear_memory` and resolved as
/// a `MacroCall("vec", [&env, symbol_short!("Variant"), ...fields])`, match it
/// against spec union types to produce `DataKey::Variant(fields...)`.
pub(super) fn try_reconstruct_enum_key(key_expr: &Expr, all_entries: &[ScSpecEntry]) -> Option<Expr> {
    // Match: MacroCall { name: "vec", args: [env_ref, symbol_short!("Name"), ...fields] }
    let (variant_name, field_args) = match key_expr {
        Expr::Ref(inner) => return try_reconstruct_enum_key(inner, all_entries),
        Expr::MacroCall { name, args } if name == "vec" => {
            // args[0] is &env, args[1] should be symbol_short!("Variant") or Symbol::new
            if args.len() < 2 { return None; }
            let variant = match &args[1] {
                Expr::MacroCall { name: n, args: sym_args } if n == "symbol_short" => {
                    match sym_args.first() {
                        Some(Expr::Literal(Literal::Str(s))) => s.clone(),
                        _ => return None,
                    }
                }
                Expr::Var(name) => {
                    // Could be a named Symbol variable -- try to match by name
                    name.clone()
                }
                _ => return None,
            };
            let fields: Vec<Expr> = args[2..].to_vec();
            (variant, fields)
        }
        // An EnumVariant that was already reconstructed earlier (e.g. from
        // vec_new_from_linear_memory -> try_match_enum_variant). Pass through.
        Expr::EnumVariant { .. } => return Some(key_expr.clone()),
        Expr::Var(name) => {
            // Already a named variable from a previous let binding -- check if
            // it matches a void enum variant name in the spec.
            let base_name = name
                .strip_suffix(|c: char| c == '_' || c.is_ascii_digit())
                .and_then(|s| s.strip_suffix('_'))
                .unwrap_or(name);
            for entry in all_entries {
                if let ScSpecEntry::UdtUnionV0(union_spec) = entry {
                    for case in union_spec.cases.iter() {
                        if let ScSpecUdtUnionCaseV0::VoidV0(v) = case {
                            let case_name = v.name.to_utf8_string_lossy();
                            let snake = to_snake_case(&case_name);
                            if case_name == *name
                                || snake == *name
                                || snake == base_name
                            {
                                let enum_name = union_spec.name.to_utf8_string_lossy();
                                return Some(Expr::EnumVariant {
                                    enum_name,
                                    variant_name: case_name,
                                    fields: vec![],
                                });
                            }
                        }
                        // Don't match tuple variants by Var name -- if the
                        // variable was already bound as DataKey::Counter(user),
                        // re-wrapping would produce DataKey::Counter(DataKey::Counter(user)).
                    }
                }
            }
            return None;
        }
        _ => return None,
    };

    // Search spec entries for a matching union variant.
    for entry in all_entries {
        if let ScSpecEntry::UdtUnionV0(union_spec) = entry {
            for case in union_spec.cases.iter() {
                let case_name = match case {
                    ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_utf8_string_lossy(),
                    ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_utf8_string_lossy(),
                };
                if case_name == variant_name {
                    let enum_name = union_spec.name.to_utf8_string_lossy();
                    return Some(Expr::EnumVariant {
                        enum_name,
                        variant_name: variant_name.clone(),
                        fields: field_args,
                    });
                }
            }
        }
    }

    // Also check plain enum entries (non-union enums used as void keys).
    for entry in all_entries {
        if let ScSpecEntry::UdtEnumV0(enum_spec) = entry {
            for case in enum_spec.cases.iter() {
                if case.name.to_utf8_string_lossy() == variant_name {
                    let enum_name = enum_spec.name.to_utf8_string_lossy();
                    return Some(Expr::EnumVariant {
                        enum_name,
                        variant_name: variant_name.clone(),
                        fields: field_args,
                    });
                }
            }
        }
    }

    None
}

/// Try to reconstruct an enum key from a raw StackValue.
///
/// When `resolve_arg` produces a generic name like `args_2` that doesn't match
/// any variant, this looks at the underlying `CallResult(id)` -> CRN name and
/// tries matching against spec union variants.  This catches cases where
/// `try_reconstruct_enum_key` fails because the Expr-level name was generic.
pub(super) fn try_enum_key_from_stack_value(
    sv: &StackValue,
    crn: &HashMap<usize, String>,
    all_entries: &[ScSpecEntry],
) -> Option<Expr> {
    let call_id = match sv {
        StackValue::CallResult(id) => *id,
        _ => return None,
    };
    let var_name = crn.get(&call_id)?;
    // Try matching the CRN-assigned name against enum variants.
    let base_name = var_name
        .rsplit_once('_')
        .and_then(|(base, suffix)| {
            if suffix.chars().all(|c| c.is_ascii_digit()) {
                Some(base)
            } else {
                None
            }
        })
        .unwrap_or(var_name);

    for entry in all_entries {
        if let ScSpecEntry::UdtUnionV0(union_spec) = entry {
            for case in union_spec.cases.iter() {
                if let ScSpecUdtUnionCaseV0::VoidV0(v) = case {
                    let case_name = v.name.to_utf8_string_lossy();
                    let snake = to_snake_case(&case_name);
                    if snake == var_name.as_str() || snake == base_name {
                        let enum_name = union_spec.name.to_utf8_string_lossy();
                        return Some(Expr::EnumVariant {
                            enum_name,
                            variant_name: case_name,
                            fields: vec![],
                        });
                    }
                }
                // Don't match tuple variants -- the variable already holds the
                // fully constructed enum value. Re-wrapping would double-nest it.
            }
        }
    }
    None
}

/// Map a storage type constant to its SDK tier name.
///
/// Soroban storage types: 0 = Temporary, 1 = Persistent, 2 = Instance.
pub(super) fn extract_storage_tier(val: &StackValue) -> Option<&'static str> {
    match val {
        StackValue::Const(Value::I64(0)) => Some("temporary"),
        StackValue::Const(Value::I64(1)) => Some("persistent"),
        StackValue::Const(Value::I64(2)) => Some("instance"),
        StackValue::Const(Value::I32(0)) => Some("temporary"),
        StackValue::Const(Value::I32(1)) => Some("persistent"),
        StackValue::Const(Value::I32(2)) => Some("instance"),
        _ => None,
    }
}
