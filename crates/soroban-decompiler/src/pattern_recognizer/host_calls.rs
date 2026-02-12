/// Host call pattern matching.
///
/// Maps individual host function calls to high-level IR statements
/// representing idiomatic Soroban SDK operations.

use std::collections::HashMap;

use stellar_xdr::curr::{ScSpecEntry, ScSpecUdtStructV0, ScSpecUdtUnionCaseV0};
use walrus::ir::Value;

use crate::ir::{Expr, Literal, MethodCall, Statement};
use crate::wasm_analysis::{AnalyzedModule, StackValue, TrackedHostCall};

use super::RecognitionContext;
use super::val_decoding::{
    strip_val_boilerplate, extract_u32_val, try_decode_symbol_small,
    decode_keys_from_linear_memory, resolve_arg, as_ref,
};

/// Try to recognize a single host call and produce an IR statement.
///
/// `crn` is the call-result-names map, which may be partially built
/// during the first pass.
pub(super) fn recognize_call(
    call: &TrackedHostCall,
    ctx: &RecognitionContext,
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let pn = &ctx.param_names;
    let name = call.host_func.name;

    match name {
        // Storage operations
        "get_contract_data" => {
            recognize_storage_get(call, pn, crn)
        }
        "put_contract_data" => {
            recognize_storage_set(call, pn, crn)
        }
        "has_contract_data" => {
            recognize_storage_has(call, pn, crn)
        }
        "del_contract_data" => {
            recognize_storage_del(call, pn, crn)
        }

        // Authorization
        "require_auth" | "require_auth_for_args" => {
            recognize_require_auth(call, pn, crn)
        }

        // Context
        "get_current_contract_address" => Some(Statement::Let {
            name: "contract_addr".into(),
            mutable: false,
            value: Expr::MethodChain {
                receiver: Box::new(Expr::Var("env".into())),
                calls: vec![MethodCall {
                    name: "current_contract_address".into(),
                    args: vec![],
                }],
            },
        }),

        // Crypto
        "verify_sig_ed25519" => {
            recognize_ed25519_verify(call, pn, crn)
        }

        // Events
        "contract_event" => recognize_event(call, pn, crn),

        // Map operations
        "map_new" => Some(Statement::Let {
            name: "map".into(),
            mutable: false,
            value: Expr::HostCall {
                module: "Map".into(),
                name: "new".into(),
                args: vec![Expr::Var("&env".into())],
            },
        }),

        // Vec operations
        "vec_new" => Some(Statement::Let {
            name: "vec".into(),
            mutable: false,
            value: Expr::HostCall {
                module: "Vec".into(),
                name: "new".into(),
                args: vec![Expr::Var("&env".into())],
            },
        }),
        "vec_push_back" | "vec_push_front"
        | "vec_put" | "vec_get"
        | "vec_len" | "vec_pop_back" | "vec_pop_front"
        | "vec_append" | "vec_slice"
        | "vec_unpack_to_linear_memory" => None,

        // Map operations (beyond map_new)
        "map_put" | "map_get" | "map_has" | "map_del"
        | "map_len" | "map_keys" | "map_values" => None,

        // Vec/Symbol/Bytes from linear memory
        "vec_new_from_linear_memory" => {
            recognize_vec_new_from_linear_memory(
                call, pn, crn,
                ctx.vec_contents, ctx.all_entries,
            )
        }
        "map_new_from_linear_memory" => {
            recognize_map_new_from_linear_memory(
                call, pn, crn,
                ctx.map_contents, ctx.all_entries,
                ctx.analyzed,
            )
        }
        "map_unpack_to_linear_memory" => {
            recognize_map_unpack(
                call, pn, crn,
                ctx.all_entries, ctx.analyzed,
                ctx.unpack_field_ids,
            )
        }
        "symbol_new_from_linear_memory" => {
            let value = if let Some(decoded) = ctx.memory_strings.get(&call.call_site_id) {
                Expr::HostCall {
                    module: "Symbol".into(),
                    name: "new".into(),
                    args: vec![
                        Expr::Var("&env".into()),
                        Expr::Literal(Literal::Str(decoded.clone())),
                    ],
                }
            } else {
                Expr::Raw("/* symbol from memory */".into())
            };
            Some(Statement::Let {
                name: "sym".into(),
                mutable: false,
                value,
            })
        }
        "string_new_from_linear_memory" => {
            let value = if let Some(decoded) = ctx.memory_strings.get(&call.call_site_id) {
                Expr::HostCall {
                    module: "String".into(),
                    name: "from_str".into(),
                    args: vec![
                        Expr::Var("&env".into()),
                        Expr::Literal(Literal::Str(decoded.clone())),
                    ],
                }
            } else {
                Expr::Raw("/* string from memory */".into())
            };
            Some(Statement::Let {
                name: "str_val".into(),
                mutable: false,
                value,
            })
        }

        // Symbol / String construction — internal plumbing for type encoding
        "symbol_index_in_linear_memory" => {
            recognize_symbol_index(call, pn, crn, ctx.analyzed)
        }
        "symbol_len" | "symbol_copy_to_linear_memory"
        | "string_len"
        | "string_copy_to_linear_memory" => None,

        // Bytes operations — internal plumbing
        "bytes_new" | "bytes_new_from_linear_memory"
        | "bytes_put" | "bytes_get" | "bytes_len"
        | "bytes_push" | "bytes_pop" | "bytes_append"
        | "bytes_copy_to_linear_memory"
        | "bytes_copy_from_linear_memory" => None,

        // Ledger / context queries
        "get_ledger_sequence" => Some(Statement::Let {
            name: "sequence".into(),
            mutable: false,
            value: Expr::MethodChain {
                receiver: Box::new(Expr::Var("env".into())),
                calls: vec![
                    MethodCall { name: "ledger".into(), args: vec![] },
                    MethodCall { name: "sequence".into(), args: vec![] },
                ],
            },
        }),
        "get_ledger_timestamp" => Some(Statement::Let {
            name: "timestamp".into(),
            mutable: false,
            value: Expr::MethodChain {
                receiver: Box::new(Expr::Var("env".into())),
                calls: vec![
                    MethodCall { name: "ledger".into(), args: vec![] },
                    MethodCall { name: "timestamp".into(), args: vec![] },
                ],
            },
        }),

        // Cross-contract calls
        "call" => recognize_cross_contract_call(call, pn, crn),

        // Logging — skip in decompilation
        "log_from_linear_memory" => None,

        // Val conversions — produce named bindings for the important ones
        "obj_from_u64" => {
            let val = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let { name: "u64_val".into(), mutable: false, value: val })
        }
        "obj_from_i64" => {
            let val = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let { name: "i64_val".into(), mutable: false, value: val })
        }
        "obj_to_u64" => {
            let val = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let { name: "u64_val".into(), mutable: false, value: val })
        }
        "obj_to_i64" => {
            let val = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let { name: "i64_val".into(), mutable: false, value: val })
        }
        "obj_from_u128_pieces" => {
            let hi = resolve_arg(call.args.first()?, pn, crn);
            let lo = resolve_arg(call.args.get(1)?, pn, crn);
            // Detect i128 round-trip: obj_from_pieces(obj_to_hi(X), obj_to_lo(X))
            if let Some(source) = detect_128_roundtrip(&hi, &lo) {
                return Some(Statement::Let {
                    name: "u128_val".into(),
                    mutable: false,
                    value: source,
                });
            }
            Some(Statement::Let {
                name: "u128_val".into(),
                mutable: false,
                value: Expr::BinOp {
                    left: Box::new(Expr::BinOp {
                        left: Box::new(hi),
                        op: crate::ir::BinOp::Shl,
                        right: Box::new(Expr::Literal(Literal::I64(64))),
                    }),
                    op: crate::ir::BinOp::BitOr,
                    right: Box::new(lo),
                },
            })
        }
        "obj_from_i128_pieces" => {
            let hi = resolve_arg(call.args.first()?, pn, crn);
            let lo = resolve_arg(call.args.get(1)?, pn, crn);
            // Detect i128 round-trip: obj_from_pieces(obj_to_hi(X), obj_to_lo(X))
            if let Some(source) = detect_128_roundtrip(&hi, &lo) {
                return Some(Statement::Let {
                    name: "i128_val".into(),
                    mutable: false,
                    value: source,
                });
            }
            Some(Statement::Let {
                name: "i128_val".into(),
                mutable: false,
                value: Expr::BinOp {
                    left: Box::new(Expr::BinOp {
                        left: Box::new(hi),
                        op: crate::ir::BinOp::Shl,
                        right: Box::new(Expr::Literal(Literal::I64(64))),
                    }),
                    op: crate::ir::BinOp::BitOr,
                    right: Box::new(lo),
                },
            })
        }
        // i128/u128 fragment accessors — produce named bindings so downstream
        // i128 assembly (obj_from_*128_pieces) can reference them by name.
        "obj_to_u128_lo64" | "obj_to_i128_lo64" => {
            let src = resolve_arg(call.args.first()?, pn, crn);
            let suffix = match &src {
                Expr::Var(name) => format!("{}_lo", name),
                _ => "lo64".into(),
            };
            Some(Statement::Let { name: suffix, mutable: false, value: src })
        }
        "obj_to_u128_hi64" | "obj_to_i128_hi64" => {
            let src = resolve_arg(call.args.first()?, pn, crn);
            let suffix = match &src {
                Expr::Var(name) => format!("{}_hi", name),
                _ => "hi64".into(),
            };
            Some(Statement::Let { name: suffix, mutable: false, value: src })
        }
        // Fragment accessors for 256 — skip (pieces of larger decompositions)
        "obj_from_u256_pieces" | "obj_from_i256_pieces"
        | "obj_to_u256_hi_hi" | "obj_to_u256_hi_lo"
        | "obj_to_u256_lo_hi" | "obj_to_u256_lo_lo" => None,

        // u256/i256 arithmetic
        "i256_add" | "u256_add" => {
            recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Add)
        }
        "i256_sub" | "u256_sub" => {
            recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Sub)
        }
        "i256_mul" | "u256_mul" => {
            recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Mul)
        }
        "i256_div" | "u256_div" => {
            recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Div)
        }
        "i256_rem_euclid" | "u256_rem_euclid" => {
            recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Rem)
        }
        "i256_shl" | "u256_shl" => {
            recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Shl)
        }
        "i256_shr" | "u256_shr" => {
            recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Shr)
        }
        "i256_pow" | "u256_pow" => {
            recognize_u256_pow(call, pn, crn)
        }

        // TTL / bump operations
        "extend_contract_data_ttl" => recognize_extend_ttl(call, pn, crn),
        "extend_current_contract_instance_and_code_ttl" => {
            recognize_extend_instance_ttl(call, pn, crn)
        }

        // Fail with error
        "fail_with_error" => recognize_fail(call, pn, crn),

        _ => None,
    }
}

/// Recognize `vec_new_from_linear_memory` — may produce an enum variant or a generic vec.
fn recognize_vec_new_from_linear_memory(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
    vec_contents: &HashMap<usize, Vec<StackValue>>,
    all_entries: &[ScSpecEntry],
) -> Option<Statement> {
    if let Some(elements) = vec_contents.get(&call.call_site_id) {
        // Try to recognize as an enum variant.
        // Soroban enums are encoded as vec where first element is SymbolSmall (variant name).
        if let Some(first) = elements.first() {
            if let StackValue::Const(Value::I64(v)) = first {
                if let Some(variant_name) = try_decode_symbol_small(*v) {
                    // Search spec entries for a matching union type.
                    if let Some(stmt) = try_match_enum_variant(
                        &variant_name, elements, param_names, crn, all_entries,
                    ) {
                        return Some(stmt);
                    }
                }
            }
        }

        // Generic vec construction.
        let elem_exprs: Vec<Expr> = elements.iter()
            .map(|el| {
                let stripped = strip_val_boilerplate(el);
                resolve_arg(&stripped, param_names, crn)
            })
            .collect();
        let value = Expr::MacroCall {
            name: "vec".into(),
            args: std::iter::once(Expr::Var("&env".into()))
                .chain(elem_exprs)
                .collect(),
        };
        Some(Statement::Let {
            name: "args".into(),
            mutable: false,
            value,
        })
    } else {
        Some(Statement::Let {
            name: "args".into(),
            mutable: false,
            value: Expr::Raw("/* vec from memory */".into()),
        })
    }
}

/// Try to match decoded vec elements against a spec union (enum) type.
fn try_match_enum_variant(
    variant_name: &str,
    elements: &[StackValue],
    param_names: &[String],
    crn: &HashMap<usize, String>,
    all_entries: &[ScSpecEntry],
) -> Option<Statement> {
    for entry in all_entries {
        if let ScSpecEntry::UdtUnionV0(union_spec) = entry {
            for case in union_spec.cases.iter() {
                let case_name = match case {
                    ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_utf8_string_lossy(),
                    ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_utf8_string_lossy(),
                };
                if case_name == variant_name {
                    let enum_name = union_spec.name.to_utf8_string_lossy();
                    // Fields are elements[1..] (first element is the discriminant symbol).
                    let field_exprs: Vec<Expr> = elements.iter().skip(1)
                        .map(|el| {
                            let stripped = strip_val_boilerplate(el);
                            resolve_arg(&stripped, param_names, crn)
                        })
                        .collect();
                    return Some(Statement::Let {
                        name: to_snake_case(variant_name),
                        mutable: false,
                        value: Expr::EnumVariant {
                            enum_name,
                            variant_name: variant_name.to_string(),
                            fields: field_exprs,
                        },
                    });
                }
            }
        }
    }
    None
}

/// Recognize `map_new_from_linear_memory` — may produce a struct literal.
fn recognize_map_new_from_linear_memory(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
    map_contents: &HashMap<usize, (Vec<String>, Vec<StackValue>)>,
    all_entries: &[ScSpecEntry],
    analyzed: &AnalyzedModule,
) -> Option<Statement> {
    if let Some((keys, values)) = map_contents.get(&call.call_site_id) {
        // Try to match against a spec struct.
        if let Some(struct_spec) = find_struct_by_fields(keys, all_entries) {
            let struct_name = struct_spec.name.to_utf8_string_lossy();
            // Struct fields in the spec are sorted alphabetically (same as map keys).
            let fields: Vec<(String, Expr)> = keys.iter().zip(values.iter())
                .map(|(k, v)| {
                    let stripped = strip_val_boilerplate(v);
                    let expr = resolve_arg(&stripped, param_names, crn);
                    (k.clone(), expr)
                })
                .collect();
            return Some(Statement::Let {
                name: to_snake_case(&struct_name),
                mutable: false,
                value: Expr::StructLiteral {
                    name: struct_name,
                    fields,
                },
            });
        }

        // No matching struct — emit as a generic map literal comment.
        let field_strs: Vec<String> = keys.iter().zip(values.iter())
            .map(|(k, v)| {
                let stripped = strip_val_boilerplate(v);
                let expr = resolve_arg(&stripped, param_names, crn);
                format!("{}: {:?}", k, expr)
            })
            .collect();
        return Some(Statement::Let {
            name: "map_val".into(),
            mutable: false,
            value: Expr::Raw(format!("/* map {{ {} }} */", field_strs.join(", "))),
        });
    }

    // Fallback: try to read keys from the data section directly.
    let keys_ptr = extract_u32_val(call.args.first()?)?;
    let len = extract_u32_val(call.args.get(2)?)?;
    if let Some(keys) = decode_keys_from_linear_memory(keys_ptr, len, analyzed) {
        if let Some(struct_spec) = find_struct_by_fields(&keys, all_entries) {
            let struct_name = struct_spec.name.to_utf8_string_lossy();
            let fields: Vec<(String, Expr)> = keys.iter()
                .map(|k| (k.clone(), Expr::Raw("/* value */".into())))
                .collect();
            return Some(Statement::Let {
                name: to_snake_case(&struct_name),
                mutable: false,
                value: Expr::StructLiteral {
                    name: struct_name,
                    fields,
                },
            });
        }
    }

    Some(Statement::Let {
        name: "map_val".into(),
        mutable: false,
        value: Expr::Raw("/* map from memory */".into()),
    })
}

/// Recognize `map_unpack_to_linear_memory(map, keys_ptr, vals_ptr, len)`.
///
/// When `unpack_field_ids` has entries for this call, the field values are already
/// tracked through memory and named — suppress the statement to avoid noise.
fn recognize_map_unpack(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
    all_entries: &[ScSpecEntry],
    analyzed: &AnalyzedModule,
    unpack_field_ids: &HashMap<usize, Vec<usize>>,
) -> Option<Statement> {
    // If the field values are tracked through memory, suppress the unpack statement.
    // The downstream struct construction will show the actual field values.
    if unpack_field_ids.contains_key(&call.call_site_id) {
        // Still produce a named let-binding so the source name propagates to field names.
        let map_arg = resolve_arg(call.args.first()?, param_names, crn);
        let keys_ptr = extract_u32_val(call.args.get(1)?)?;
        let len = extract_u32_val(call.args.get(3)?)?;
        if let Some(keys) = decode_keys_from_linear_memory(keys_ptr, len, analyzed) {
            if let Some(struct_spec) = find_struct_by_fields(&keys, all_entries) {
                let struct_name = struct_spec.name.to_utf8_string_lossy();
                return Some(Statement::Let {
                    name: to_snake_case(&struct_name),
                    mutable: false,
                    value: map_arg,
                });
            }
        }
        return None;
    }

    let map_arg = resolve_arg(call.args.first()?, param_names, crn);
    let keys_ptr = extract_u32_val(call.args.get(1)?)?;
    let len = extract_u32_val(call.args.get(3)?)?;

    if let Some(keys) = decode_keys_from_linear_memory(keys_ptr, len, analyzed) {
        if let Some(struct_spec) = find_struct_by_fields(&keys, all_entries) {
            let struct_name = struct_spec.name.to_utf8_string_lossy();
            return Some(Statement::Let {
                name: to_snake_case(&struct_name),
                mutable: false,
                value: Expr::Raw(format!("/* unpack {} from {:?} */", struct_name, map_arg)),
            });
        }
        return Some(Statement::Let {
            name: "unpacked".into(),
            mutable: false,
            value: Expr::Raw(format!(
                "/* map_unpack keys=[{}] from {:?} */",
                keys.join(", "),
                map_arg,
            )),
        });
    }

    None
}

/// Recognize `symbol_index_in_linear_memory(sym, strs_ptr, len)`.
///
/// Emits a comment showing the variant names being matched against.
fn recognize_symbol_index(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
    analyzed: &AnalyzedModule,
) -> Option<Statement> {
    let sym_expr = resolve_arg(call.args.first()?, param_names, crn);
    let strs_ptr = extract_u32_val(call.args.get(1)?)?;
    let len = extract_u32_val(call.args.get(2)?)?;

    if let Some(variants) = decode_keys_from_linear_memory(strs_ptr, len, analyzed) {
        return Some(Statement::Let {
            name: "variant_idx".into(),
            mutable: false,
            value: Expr::Raw(format!(
                "/* match {:?} against [{}] */",
                sym_expr,
                variants.join(", "),
            )),
        });
    }

    None
}

/// Find a spec struct whose field names match the given key list.
///
/// Soroban struct fields are sorted alphabetically in the serialized form,
/// matching the order of keys in map_new_from_linear_memory.
fn find_struct_by_fields<'a>(
    keys: &[String],
    all_entries: &'a [ScSpecEntry],
) -> Option<&'a ScSpecUdtStructV0> {
    for entry in all_entries {
        if let ScSpecEntry::UdtStructV0(s) = entry {
            let spec_fields: Vec<String> = s.fields.iter()
                .map(|f| f.name.to_utf8_string_lossy())
                .collect();
            // Spec fields sorted alphabetically to match map key order.
            let mut sorted_fields = spec_fields.clone();
            sorted_fields.sort();
            if sorted_fields == keys {
                return Some(s);
            }
        }
    }
    None
}

/// Detect i128/u128 round-trip pattern: obj_from_*128_pieces(obj_to_hi(X), obj_to_lo(X)).
///
/// When both `hi` and `lo` resolve to variables named `{base}_hi` / `{base}_lo` with
/// the same base, the entire operation is a no-op pass-through of the original i128 value.
/// Returns the source expression if detected.
fn detect_128_roundtrip(hi: &Expr, lo: &Expr) -> Option<Expr> {
    if let (Expr::Var(hi_name), Expr::Var(lo_name)) = (hi, lo) {
        let base_h = hi_name.strip_suffix("_hi");
        let base_l = lo_name.strip_suffix("_lo");
        if let (Some(bh), Some(bl)) = (base_h, base_l) {
            if bh == bl {
                return Some(Expr::Var(bh.to_string()));
            }
        }
    }
    None
}

/// Convert a PascalCase or camelCase name to snake_case.
fn to_snake_case(name: &str) -> String {
    let mut result = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(ch.to_lowercase().next().unwrap_or(ch));
    }
    result
}

/// Recognize a u256/i256 binary arithmetic operation.
fn recognize_u256_binop(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
    op: crate::ir::BinOp,
) -> Option<Statement> {
    let lhs = resolve_arg(call.args.first()?, param_names, crn);
    let rhs = resolve_arg(call.args.get(1)?, param_names, crn);
    Some(Statement::Let {
        name: "result".into(),
        mutable: false,
        value: Expr::BinOp {
            left: Box::new(lhs),
            op,
            right: Box::new(rhs),
        },
    })
}

/// Recognize a u256/i256 pow operation as a method call.
fn recognize_u256_pow(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let base = resolve_arg(call.args.first()?, param_names, crn);
    let exp = resolve_arg(call.args.get(1)?, param_names, crn);
    Some(Statement::Let {
        name: "result".into(),
        mutable: false,
        value: Expr::MethodChain {
            receiver: Box::new(base),
            calls: vec![MethodCall { name: "pow".into(), args: vec![exp] }],
        },
    })
}

/// Recognize `get_contract_data(key, storage_type)` → `env.storage().{tier}().get(&key)`
fn recognize_storage_get(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let tier = extract_storage_tier(call.args.last()?)?;
    let key_expr = as_ref(resolve_arg(&call.args[0], param_names, crn));

    Some(Statement::Let {
        name: "val".into(),
        mutable: false,
        value: Expr::MethodChain {
            receiver: Box::new(Expr::Var("env".into())),
            calls: vec![
                MethodCall { name: "storage".into(), args: vec![] },
                MethodCall { name: tier.into(), args: vec![] },
                MethodCall { name: "get".into(), args: vec![key_expr] },
            ],
        },
    })
}

/// Recognize `put_contract_data(key, val, storage_type)` as
/// `env.storage().{tier}().set(&key, &val)`.
fn recognize_storage_set(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let tier = extract_storage_tier(call.args.last()?)?;
    let key_expr = as_ref(resolve_arg(&call.args[0], param_names, crn));
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

/// Recognize `has_contract_data(key, storage_type)` → `env.storage().{tier}().has(&key)`
fn recognize_storage_has(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let tier = extract_storage_tier(call.args.last()?)?;
    let key_expr = as_ref(resolve_arg(&call.args[0], param_names, crn));

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

/// Recognize `del_contract_data(key, storage_type)` → `env.storage().{tier}().remove(&key)`
fn recognize_storage_del(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let tier = extract_storage_tier(call.args.last()?)?;
    let key_expr = as_ref(resolve_arg(&call.args[0], param_names, crn));

    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![
            MethodCall { name: "storage".into(), args: vec![] },
            MethodCall { name: tier.into(), args: vec![] },
            MethodCall { name: "remove".into(), args: vec![key_expr] },
        ],
    }))
}

/// Recognize `require_auth(addr)` → `{addr}.require_auth()`
fn recognize_require_auth(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let addr_expr = resolve_arg(call.args.first()?, param_names, crn);
    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(addr_expr),
        calls: vec![MethodCall { name: "require_auth".into(), args: vec![] }],
    }))
}

/// Recognize `verify_sig_ed25519(pk, msg, sig)` → `env.crypto().ed25519_verify(&pk, &msg, &sig)`
fn recognize_ed25519_verify(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let pk = as_ref(resolve_arg(call.args.first()?, param_names, crn));
    let msg = as_ref(resolve_arg(call.args.get(1)?, param_names, crn));
    let sig = as_ref(resolve_arg(call.args.get(2)?, param_names, crn));

    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![
            MethodCall { name: "crypto".into(), args: vec![] },
            MethodCall { name: "ed25519_verify".into(), args: vec![pk, msg, sig] },
        ],
    }))
}

/// Recognize `contract_event(topics, data)` → `env.events().publish(topics, data)`
fn recognize_event(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let topics = resolve_arg(call.args.first()?, param_names, crn);
    let data = resolve_arg(call.args.get(1)?, param_names, crn);

    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![
            MethodCall { name: "events".into(), args: vec![] },
            MethodCall { name: "publish".into(), args: vec![topics, data] },
        ],
    }))
}

/// Recognize `call(contract, func, args)` → `env.invoke_contract(&addr, func, args)`
fn recognize_cross_contract_call(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let addr = as_ref(resolve_arg(call.args.first()?, param_names, crn));
    let func = resolve_arg(call.args.get(1)?, param_names, crn);
    let args = resolve_arg(call.args.get(2)?, param_names, crn);

    Some(Statement::Let {
        name: "result".into(),
        mutable: false,
        value: Expr::MethodChain {
            receiver: Box::new(Expr::Var("env".into())),
            calls: vec![MethodCall {
                name: "invoke_contract".into(),
                args: vec![addr, func, args],
            }],
        },
    })
}

/// Recognize `extend_contract_data_ttl(key, type, threshold, extend_to)`
/// → `env.storage().{tier}().extend_ttl(&key, threshold, extend_to)`
fn recognize_extend_ttl(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let key_expr = as_ref(resolve_arg(call.args.first()?, param_names, crn));
    let tier = extract_storage_tier(call.args.get(1)?)?;
    let threshold = resolve_arg(call.args.get(2)?, param_names, crn);
    let extend_to = resolve_arg(call.args.get(3)?, param_names, crn);

    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![
            MethodCall { name: "storage".into(), args: vec![] },
            MethodCall { name: tier.into(), args: vec![] },
            MethodCall { name: "extend_ttl".into(), args: vec![key_expr, threshold, extend_to] },
        ],
    }))
}

/// Recognize `extend_current_contract_instance_and_code_ttl(threshold, extend_to)`
/// → `env.storage().instance().extend_ttl(threshold, extend_to)`
fn recognize_extend_instance_ttl(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let threshold = resolve_arg(call.args.first()?, param_names, crn);
    let extend_to = resolve_arg(call.args.get(1)?, param_names, crn);

    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![
            MethodCall { name: "storage".into(), args: vec![] },
            MethodCall { name: "instance".into(), args: vec![] },
            MethodCall { name: "extend_ttl".into(), args: vec![threshold, extend_to] },
        ],
    }))
}

/// Recognize `fail_with_error(error)` → `panic!("{error}")`
fn recognize_fail(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let error = resolve_arg(call.args.first()?, param_names, crn);
    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![MethodCall {
            name: "panic_with_error".into(),
            args: vec![error],
        }],
    }))
}

/// Map a storage type constant to its SDK tier name.
///
/// Soroban storage types: 0 = Temporary, 1 = Persistent, 2 = Instance.
fn extract_storage_tier(val: &StackValue) -> Option<&'static str> {
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
