/// Val encoding/decoding and expression resolution.
///
/// Handles Soroban's tagged Val format (64-bit words with type tags),
/// symbol decoding, and resolution of stack values to IR expressions.

use std::collections::HashMap;

use walrus::ir::Value;

use crate::ir::{Expr, Literal};
use crate::wasm_analysis::{AnalyzedModule, StackValue, TrackedHostCall};

// ---------------------------------------------------------------------------
// Soroban Val / Symbol decoding
// ---------------------------------------------------------------------------

/// Tag value for SymbolSmall in the lower 8 bits of a Soroban Val.
const TAG_SYMBOL_SMALL: u64 = 14;

/// Number of bits per encoded character.
const CODE_BITS: u32 = 6;

/// Maximum characters in a small symbol.
const MAX_SMALL_CHARS: u32 = 9;

const TAG_SYMBOL_SMALL_U8: u64 = TAG_SYMBOL_SMALL;

/// Extract a u32 value from a tagged U32Val StackValue.
///
/// U32Val has tag 4 in the lower 8 bits, value in bits 32-63.
/// Handles both direct constants like `Const(I64(21474836484))` and
/// computed expressions like `(I32(1048576) << 32) | I64(4)`.
pub fn extract_u32_val(sv: &StackValue) -> Option<u32> {
    // Direct tagged constant: Const(I64(tagged_val))
    if let StackValue::Const(Value::I64(v)) = sv {
        let uv = *v as u64;
        if uv & 0xFF == 4 {
            return Some((uv >> 32) as u32);
        }
    }
    // Computed tagged expression: strip Val boilerplate to get raw constant
    let stripped = strip_val_boilerplate(sv);
    match &stripped {
        StackValue::Const(Value::I32(v)) => Some(*v as u32),
        StackValue::Const(Value::I64(v)) => Some(*v as u32),
        _ => None,
    }
}

/// Recursively strip Val encoding/decoding boilerplate from a StackValue tree.
///
/// Soroban passes all values as 64-bit tagged Vals across the WASM boundary.
/// The compiler inserts shift/mask operations to encode and decode:
///   - U32Val/I32Val: `param >> 32` (decode), `(result << 32) | tag` (encode)
///   - U64Small/I64Small: `param >> 8` (decode), `(result << 8) | tag` (encode)
///
/// This function strips these patterns so the decompiled output shows the
/// logical operation (e.g., `a + b`) rather than the raw bit manipulation.
pub fn strip_val_boilerplate(val: &StackValue) -> StackValue {
    use crate::ir::BinOp as B;

    match val {
        // Decode: (val >> 32) for U32Val, (val >> 8) for U64Small.
        StackValue::BinOp { op: B::Shr, left, right } => {
            let is_decode_shift = matches!(
                right.as_ref(),
                StackValue::Const(
                    Value::I64(32) | Value::I32(32)
                    | Value::I64(8) | Value::I32(8)
                )
            );
            if is_decode_shift {
                return strip_val_boilerplate(left);
            }
            StackValue::BinOp {
                op: B::Shr,
                left: Box::new(strip_val_boilerplate(left)),
                right: Box::new(strip_val_boilerplate(right)),
            }
        }
        // Encode: (inner << N) | tag, or (val & mask) | tag.
        StackValue::BinOp { op: B::BitOr, left, right } => {
            let is_small_tag = matches!(
                right.as_ref(),
                StackValue::Const(Value::I64(t))
                    if (*t as u64) <= 14
            );

            if is_small_tag {
                // (inner << N) | tag
                if let StackValue::BinOp {
                    op: B::Shl,
                    left: inner,
                    right: shift,
                } = left.as_ref()
                {
                    let is_val_shift = matches!(
                        shift.as_ref(),
                        StackValue::Const(
                            Value::I64(32) | Value::I32(32)
                            | Value::I64(8) | Value::I32(8)
                        )
                    );
                    if is_val_shift {
                        return strip_val_boilerplate(inner);
                    }
                }
                // (val & 0xFFFFFFFF00000000) | tag
                if let StackValue::BinOp {
                    op: B::BitAnd,
                    left: inner,
                    right: mask,
                } = left.as_ref()
                {
                    if matches!(
                        mask.as_ref(),
                        StackValue::Const(Value::I64(m))
                            if *m as u64 == 0xFFFF_FFFF_0000_0000
                    ) {
                        return strip_val_boilerplate(inner);
                    }
                }
            }
            // (val | 0) is a no-op.
            if matches!(
                right.as_ref(),
                StackValue::Const(Value::I64(0) | Value::I32(0))
            ) {
                return strip_val_boilerplate(left);
            }
            StackValue::BinOp {
                op: B::BitOr,
                left: Box::new(strip_val_boilerplate(left)),
                right: Box::new(strip_val_boilerplate(right)),
            }
        }
        // BitAnd masks in Val encoding/decoding.
        StackValue::BinOp { op: B::BitAnd, left, right } => {
            if let StackValue::Const(Value::I64(m)) = right.as_ref() {
                let mu = *m as u64;
                // High mask: (val & 0xFFFFFFFF00000000)
                if mu == 0xFFFF_FFFF_0000_0000 {
                    return strip_val_boilerplate(left);
                }
                // Low mask: (val & 0x00000000FFFFFFFF)
                if mu == 0x0000_0000_FFFF_FFFF {
                    return strip_val_boilerplate(left);
                }
                // Tag-preserving mask: (val & ((0xFFFFFFFF << 32) | tag))
                // where tag is a Soroban type tag. Strips to just the value.
                let tag = mu & 0xFF;
                let high = mu >> 32;
                if tag <= 14 && high == 0xFFFF_FFFF {
                    return strip_val_boilerplate(left);
                }
            }
            StackValue::BinOp {
                op: B::BitAnd,
                left: Box::new(strip_val_boilerplate(left)),
                right: Box::new(strip_val_boilerplate(right)),
            }
        }
        // Other BinOps — recurse.
        StackValue::BinOp { op, left, right } => {
            StackValue::BinOp {
                op: *op,
                left: Box::new(strip_val_boilerplate(left)),
                right: Box::new(strip_val_boilerplate(right)),
            }
        }
        // Recurse into UnOps
        StackValue::UnOp { op, operand } => {
            StackValue::UnOp {
                op: *op,
                operand: Box::new(strip_val_boilerplate(operand)),
            }
        }
        // Leaf nodes — return as-is
        _ => val.clone(),
    }
}

/// If the return value is a CallResult from a Val encoding function
/// (obj_from_u64, obj_from_i64, etc.), return the first argument passed
/// to that function — that's the real pre-encoding value.
///
/// Also handles the inline small-value encoding pattern:
/// `(value << 8) | tag` which appears as BinOp(BitOr, BinOp(Shl, val, 8), tag).
pub fn unwrap_val_encoding(
    ret: &StackValue,
    host_calls: &[TrackedHostCall],
) -> Option<StackValue> {
    match ret {
        // Return is a CallResult from a host function — check if it's a Val encoder.
        StackValue::CallResult(call_id) => {
            for call in host_calls.iter().rev() {
                if call.call_site_id == *call_id {
                    let name = call.host_func.name;
                    if matches!(
                        name,
                        "obj_from_u64" | "obj_from_i64"
                        | "obj_from_u128_pieces" | "obj_from_i128_pieces"
                        | "obj_from_u256_pieces" | "obj_from_i256_pieces"
                    ) {
                        // The first arg is the pre-encoding value.
                        return call.args.first().cloned();
                    }
                    break;
                }
            }
            None
        }
        // Inline small-value encoding: (value << 8) | tag_const
        // Unwrap to just the value.
        StackValue::BinOp {
            op: crate::ir::BinOp::BitOr,
            left,
            right,
        } => {
            if let StackValue::BinOp {
                op: crate::ir::BinOp::Shl,
                left: inner,
                right: shift,
            } = left.as_ref()
            {
                let is_shift_8 = matches!(
                    shift.as_ref(),
                    StackValue::Const(Value::I64(8))
                );
                let is_small_tag = matches!(
                    right.as_ref(),
                    StackValue::Const(Value::I64(t)) if *t <= 14
                );
                if is_shift_8 && is_small_tag {
                    return Some(*inner.clone());
                }
            }
            None
        }
        _ => None,
    }
}

/// Try to decode a 64-bit Val as a small Soroban symbol.
///
/// Returns the decoded string if the value has the SymbolSmall tag and
/// all encoded characters are valid.
pub fn try_decode_symbol_small(val: i64) -> Option<String> {
    let v = val as u64;

    // Check tag (lower 8 bits).
    if v & 0xFF != TAG_SYMBOL_SMALL {
        return None;
    }

    // Extract the body (bits 8..63). The upper 2 bits of the 56-bit body
    // should be zero for valid small symbols.
    let mut body = (v >> 8) & 0x00ff_ffff_ffff_ffff;

    let mut chars = Vec::with_capacity(MAX_SMALL_CHARS as usize);
    for _ in 0..MAX_SMALL_CHARS {
        let code = (body >> ((MAX_SMALL_CHARS - 1) * CODE_BITS)) & 0x3F;
        body <<= CODE_BITS;
        if code == 0 {
            continue; // padding
        }
        let ch = match code as u8 {
            1 => b'_',
            n @ 2..=11 => b'0' + n - 2,
            n @ 12..=37 => b'A' + n - 12,
            n @ 38..=63 => b'a' + n - 38,
            _ => return None,
        };
        chars.push(ch);
    }

    if chars.is_empty() {
        return None;
    }

    Some(String::from_utf8(chars).ok()?)
}

/// Decode N symbol Vals from raw bytes (each is an 8-byte little-endian i64).
///
/// Used to read key arrays from WASM data sections for map_new_from_linear_memory.
/// Each 8-byte entry is a Soroban tagged Val that should be a SymbolSmall.
pub fn decode_symbol_vals_from_bytes(bytes: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    for chunk in bytes.chunks_exact(8) {
        let val = i64::from_le_bytes(chunk.try_into().unwrap());
        if let Some(sym) = try_decode_symbol_small(val) {
            result.push(sym);
        } else {
            result.push(format!("unknown_{:016x}", val as u64));
        }
    }
    result
}

/// Decode keys from the data section, handling both formats:
/// 1. SymbolSmall Vals (8-byte LE i64 with tag=14)
/// 2. Slice descriptors: (u32 ptr, u32 len) pairs pointing to string data
///
/// The Soroban SDK encodes struct field keys as slice descriptors in the data section.
pub fn decode_keys_from_linear_memory(
    keys_ptr: u32,
    len: u32,
    analyzed: &AnalyzedModule,
) -> Option<Vec<String>> {
    let bytes = analyzed.read_linear_memory(keys_ptr, len * 8)?;

    // First try: SymbolSmall Vals
    let syms = decode_symbol_vals_from_bytes(&bytes);
    if syms.iter().all(|s| !s.starts_with("unknown_")) {
        return Some(syms);
    }

    // Second try: (u32 ptr, u32 len) slice descriptors
    let mut result = Vec::new();
    for chunk in bytes.chunks_exact(8) {
        let ptr = u32::from_le_bytes(chunk[0..4].try_into().ok()?);
        let slen = u32::from_le_bytes(chunk[4..8].try_into().ok()?);
        if slen > 64 { return None; } // sanity limit
        if let Some(str_bytes) = analyzed.read_linear_memory(ptr, slen) {
            if let Ok(s) = String::from_utf8(str_bytes) {
                result.push(s);
            } else {
                return None;
            }
        } else {
            return None;
        }
    }
    if result.len() == len as usize {
        return Some(result);
    }
    None
}

/// Try to interpret a 64-bit Val as a known Soroban tagged value.
///
/// Soroban Vals are 64-bit words where the low 8 bits are a type tag
/// and the upper bits carry the payload. This function decodes:
///   Tag 0 = False, Tag 1 = True, Tag 2 = Void,
///   Tag 3 = Error, Tag 4 = U32Val, Tag 5 = I32Val,
///   Tag 6 = U64Small, Tag 7 = I64Small, Tag 14 = SymbolSmall.
fn try_decode_val(val: i64) -> Option<Expr> {
    let v = val as u64;
    let tag = v & 0xFF;

    match tag {
        // Tags 0 (False), 1 (True): skip decoding these as booleans.
        // After strip_val_boilerplate, raw I64(0) and I64(1) are common as
        // plain integer constants in arithmetic. Decoding them as false/true
        // produces nonsensical output like ((false - (false + ...))).
        0 if v == 0 => Some(Expr::Literal(Literal::I64(0))),
        1 if v >> 8 == 0 => Some(Expr::Literal(Literal::I64(1))),
        // Void (tag 2): body must be 0
        2 if v >> 8 == 0 => Some(Expr::Raw("/* void */".into())),
        // Error (tag 3): major = error code, minor = error type
        3 => {
            let error_code = (v >> 32) as u32;
            let error_type = ((v >> 8) & 0xFF_FFFF) as u32;
            Some(Expr::Raw(format!("/* Error(type={error_type}, code={error_code}) */")))
        }
        // U32Val (tag 4): value in bits 32-63
        4 => {
            let value = (v >> 32) as u32;
            Some(Expr::Literal(Literal::I64(value as i64)))
        }
        // I32Val (tag 5): value in bits 32-63 (as signed)
        5 => {
            let value = (v >> 32) as i32;
            Some(Expr::Literal(Literal::I64(value as i64)))
        }
        // U64Small (tag 6): value in bits 8-63 (56-bit unsigned)
        6 => {
            let value = v >> 8;
            Some(Expr::Literal(Literal::I64(value as i64)))
        }
        // I64Small (tag 7): value in bits 8-63 (sign-extended 56-bit)
        7 => {
            let body = v >> 8;
            let value = if body & (1 << 55) != 0 {
                (body | 0xFF00_0000_0000_0000) as i64
            } else {
                body as i64
            };
            Some(Expr::Literal(Literal::I64(value)))
        }
        // SymbolSmall (tag 14)
        TAG_SYMBOL_SMALL_U8 => {
            try_decode_symbol_small(val).map(|sym| Expr::MacroCall {
                name: "symbol_short".into(),
                args: vec![Expr::Literal(Literal::Str(sym))],
            })
        }
        _ => None,
    }
}

/// Resolve a stack value to an IR expression, using spec param names where possible.
///
/// Strips Val encoding/decoding boilerplate first, then resolves to Expr.
pub fn resolve_arg(
    val: &StackValue,
    param_names: &[String],
    call_result_names: &HashMap<usize, String>,
) -> Expr {
    let stripped = strip_val_boilerplate(val);
    resolve_arg_inner(&stripped, param_names, call_result_names)
}

/// Inner resolver without stripping (avoids redundant re-stripping in recursion).
fn resolve_arg_inner(
    val: &StackValue,
    param_names: &[String],
    call_result_names: &HashMap<usize, String>,
) -> Expr {
    match val {
        StackValue::Const(Value::I32(v)) => Expr::Literal(Literal::I32(*v)),
        StackValue::Const(Value::I64(v)) => {
            // Try to decode as a Soroban tagged Val (e.g., SymbolSmall).
            if let Some(expr) = try_decode_val(*v) {
                expr
            } else {
                Expr::Literal(Literal::I64(*v))
            }
        }
        StackValue::Const(Value::F32(v)) => Expr::Literal(Literal::F32(*v)),
        StackValue::Const(Value::F64(v)) => Expr::Literal(Literal::F64(*v)),
        StackValue::Const(Value::V128(_)) => Expr::Raw("/* v128 */".into()),
        StackValue::Param(idx) => {
            // param_names is a unified array: when has_implicit_env,
            // param_names[0]="env", param_names[1..]=spec inputs.
            // When !has_implicit_env, param_names[0..]=spec inputs directly.
            if let Some(name) = param_names.get(*idx) {
                Expr::Var(name.clone())
            } else {
                Expr::Var(format!("param_{idx}"))
            }
        }
        StackValue::Local(local_id) => {
            // Local IDs are module-global walrus indices, not function-relative.
            // Only Param(idx) reliably maps to spec parameter names.
            Expr::Var(format!("local_{}", local_id.index()))
        }
        StackValue::CallResult(call_id) => {
            if let Some(var_name) = call_result_names.get(call_id) {
                Expr::Var(var_name.clone())
            } else {
                Expr::Raw("/* computed */".into())
            }
        }
        StackValue::BinOp { op, left, right } => {
            let l = resolve_arg_inner(left, param_names, call_result_names);
            let r = resolve_arg_inner(right, param_names, call_result_names);
            Expr::BinOp {
                left: Box::new(l),
                op: *op,
                right: Box::new(r),
            }
        }
        StackValue::UnOp { op, operand } => {
            let e = resolve_arg_inner(operand, param_names, call_result_names);
            Expr::UnOp {
                op: *op,
                operand: Box::new(e),
            }
        }
        StackValue::Unknown => Expr::Raw("/* unknown */".into()),
    }
}

/// Wrap an expression in a reference (`&expr`) for contexts that need borrows.
///
/// Skips wrapping for `env` and already-referenced variables.
pub fn as_ref(expr: Expr) -> Expr {
    match &expr {
        Expr::Var(name) if name == "env" => expr,
        Expr::Var(name) if name.starts_with('&') => expr,
        Expr::Var(name) => Expr::Var(format!("&{name}")),
        _ => expr,
    }
}
