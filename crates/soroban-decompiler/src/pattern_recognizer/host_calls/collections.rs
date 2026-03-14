use std::collections::HashMap;

use stellar_xdr::curr::{ScSpecEntry, ScSpecUdtUnionCaseV0};
use walrus::ir::Value;

use crate::ir::{Expr, MethodCall, Statement};
use crate::wasm_analysis::{AnalyzedModule, StackValue, TrackedHostCall};

use super::super::val_decoding::{
    strip_val_boilerplate, extract_u32_val, try_decode_symbol_small,
    decode_keys_from_linear_memory, resolve_arg,
};
use super::types::{find_struct_by_fields, to_snake_case};

/// Recognize `vec_new_from_linear_memory` -- may produce an enum variant or a generic vec.
pub(super) fn recognize_vec_new_from_linear_memory(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
    vec_contents: &HashMap<usize, Vec<StackValue>>,
    all_entries: &[ScSpecEntry],
    memory_strings: &HashMap<usize, String>,
) -> Option<Statement> {
    if let Some(elements) = vec_contents.get(&call.call_site_id) {
        // Try to recognize as an enum variant.
        // Soroban enums are encoded as vec where first element is a symbol (variant name).
        if let Some(first) = elements.first() {
            // Strip Val encoding wrapper from the first element before matching.
            let first_stripped = strip_val_boilerplate(first);
            let variant_name = match &first_stripped {
                // SymbolSmall: decode directly from the tagged constant.
                StackValue::Const(Value::I64(v)) => try_decode_symbol_small(*v),
                // CallResult from symbol_new_from_linear_memory: look up the
                // decoded string from memory_strings.
                StackValue::CallResult(call_id) => memory_strings.get(call_id).cloned(),
                _ => None,
            };
            if let Some(vname) = variant_name {
                if let Some(stmt) = try_match_enum_variant(
                    &vname, elements, param_names, crn, all_entries,
                ) {
                    return Some(stmt);
                }
            }
        }

        // Generic vec construction.
        // Merge i128 hi/lo pairs: when two consecutive elements form
        // (value, value >> 63) they represent a single i128 argument.
        let mut elem_exprs: Vec<Expr> = Vec::new();
        let mut i = 0;
        while i < elements.len() {
            if i + 1 < elements.len() {
                if let Some(merged) = try_merge_i128_pair(&elements[i], &elements[i + 1]) {
                    let stripped = strip_val_boilerplate(&merged);
                    elem_exprs.push(resolve_arg(&stripped, param_names, crn));
                    i += 2;
                    continue;
                }
            }
            let stripped = strip_val_boilerplate(&elements[i]);
            elem_exprs.push(resolve_arg(&stripped, param_names, crn));
            i += 1;
        }
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
        // Fallback for 1-element vecs (void enum keys): if len=1, try to find
        // the symbol from a preceding symbol_new_from_linear_memory whose
        // CallResult is in memory_strings. The WASM pattern stores the symbol
        // into the frame and then calls vec_new_from_linear_memory with len=1.
        let len = extract_u32_val(call.args.get(1)?);
        if len == Some(1) {
            // Heuristic: look at recent memory_strings entries with a call_site_id
            // just before this one (the symbol_new call typically precedes the vec call).
            let our_id = call.call_site_id;
            for check_id in (our_id.saturating_sub(5)..our_id).rev() {
                if let Some(sym_name) = memory_strings.get(&check_id) {
                    // Try matching against a void enum variant
                    if let Some(stmt) = try_match_enum_variant(
                        sym_name, &[StackValue::Unknown], param_names, crn, all_entries,
                    ) {
                        return Some(stmt);
                    }
                }
            }
        }

        Some(Statement::Let {
            name: "args".into(),
            mutable: false,
            value: Expr::Raw("/* vec from memory */".into()),
        })
    }
}

/// Try to match decoded vec elements against a spec union (enum) type.
pub(super) fn try_match_enum_variant(
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
                    // For void variants (no fields), emit an empty fields list
                    // regardless of vec contents. For tuple variants, fields
                    // are elements[1..] (first element is the discriminant symbol).
                    let is_void = matches!(case, ScSpecUdtUnionCaseV0::VoidV0(_));
                    let field_exprs: Vec<Expr> = if is_void {
                        vec![]
                    } else {
                        elements.iter().skip(1)
                            .map(|el| {
                                let stripped = strip_val_boilerplate(el);
                                resolve_arg(&stripped, param_names, crn)
                            })
                            .collect()
                    };
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

/// Recognize `map_new_from_linear_memory` -- may produce a struct literal.
pub(super) fn recognize_map_new_from_linear_memory(
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

        // No matching struct -- emit as a StructLiteral with field values.
        // Soroban maps with string keys are typically used as anonymous
        // struct-like objects in authorization contexts.
        let fields: Vec<(String, Expr)> = keys.iter().zip(values.iter())
            .map(|(k, v)| {
                let stripped = strip_val_boilerplate(v);
                let expr = resolve_arg(&stripped, param_names, crn);
                (k.clone(), expr)
            })
            .collect();
        return Some(Statement::Let {
            name: "map_val".into(),
            mutable: false,
            value: Expr::StructLiteral {
                name: "map".into(),
                fields,
            },
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
/// tracked through memory and named -- suppress the statement to avoid noise.
pub(super) fn recognize_map_unpack(
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
pub(super) fn recognize_symbol_index(
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

/// Detect i128 hi/lo pair in vec elements.
///
/// WASM stores i128 values as two consecutive i64 entries in linear memory:
///   - lo: `value >> 8` (I64Small tag stripping, resolved by strip_val_boilerplate)
///   - hi: `value >> 63` (sign extension for the high 64 bits)
///
/// When `lo` and `hi` share the same base value and `hi` is `base >> 63`,
/// the pair represents a single i128 argument. Returns the base value.
///
/// Also handles the more general pattern where lo comes from obj_to_i128_lo64
/// and hi comes from obj_to_i128_hi64 of the same source, or where both
/// are derived from the same Param/CallResult.
pub(super) fn try_merge_i128_pair(lo_raw: &StackValue, hi_raw: &StackValue) -> Option<StackValue> {
    use crate::ir::BinOp as B;

    // Pattern 1: lo = X >> 8 (or just X after strip), hi = X >> 63
    // The lo element after strip_val_boilerplate becomes the base value.
    let lo_stripped = strip_val_boilerplate(lo_raw);

    // Check if hi is `base >> 63` where base matches lo_stripped
    if let StackValue::BinOp { op: B::Shr, left: hi_base, right: hi_shift } = hi_raw {
        if matches!(hi_shift.as_ref(), StackValue::Const(Value::I64(63))) {
            // Check if the hi base matches the lo base (before stripping).
            // lo_raw is typically `base >> 8`, so hi_base should equal
            // the base of lo_raw (i.e., the part before >> 8).
            let lo_base = match lo_raw {
                StackValue::BinOp { op: B::Shr, left, right }
                    if matches!(right.as_ref(), StackValue::Const(Value::I64(8)))
                    => left.as_ref(),
                _ => lo_raw,
            };
            if format!("{:?}", hi_base.as_ref()) == format!("{:?}", lo_base) {
                return Some(lo_stripped);
            }
        }
    }

    // Pattern 2: lo = Const(I64(2)) (Void tag), hi = X >> 63
    // This happens when the lo part is a Void Val (tag 2, value 0).
    // The pair represents i128(0) sign-extended.
    if matches!(lo_raw, StackValue::Const(Value::I64(2))) {
        if let StackValue::BinOp { op: B::Shr, right: hi_shift, .. } = hi_raw {
            if matches!(hi_shift.as_ref(), StackValue::Const(Value::I64(63))) {
                // i128(0) encoded as (Void, sign_ext)
                return Some(StackValue::Const(Value::I64(0)));
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
pub(super) fn detect_128_roundtrip(hi: &Expr, lo: &Expr) -> Option<Expr> {
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

/// Recognize a u256/i256 binary arithmetic operation.
pub(super) fn recognize_u256_binop(
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
pub(super) fn recognize_u256_pow(
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
