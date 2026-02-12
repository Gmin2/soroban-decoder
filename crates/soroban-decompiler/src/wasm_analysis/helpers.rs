/// Utility free functions for WASM analysis.
///
/// Contains value inspection, address decomposition, memory decoding,
/// and WASM operator mapping helpers.

use std::collections::HashMap;

use walrus::ir::{self, BinaryOp, UnaryOp};
use walrus::LocalId;

use super::{AnalyzedModule, StackValue};

/// Merge locals from two branches after an if/else.
///
/// Keeps a local if both branches agree on the value, or if only
/// one branch touched it. Removes locals where the two branches
/// disagree.
pub fn merge_locals(
    cons_locals: &mut HashMap<LocalId, StackValue>,
    alt_locals: &HashMap<LocalId, StackValue>,
) {
    let snapshot = cons_locals.clone();
    for (lid, cons_val) in &snapshot {
        if let Some(alt_val) = alt_locals.get(lid) {
            if format!("{cons_val:?}") != format!("{alt_val:?}") {
                cons_locals.remove(lid);
            }
        }
    }
    // Add locals from alt that cons doesn't have.
    for (lid, alt_val) in alt_locals {
        if !snapshot.contains_key(lid) {
            cons_locals.insert(*lid, alt_val.clone());
        }
    }
}

/// Check whether a [`StackValue`] tree contains any `Unknown` nodes.
///
/// Values derived from `Unknown` (e.g. stack pointer arithmetic)
/// should NOT be stored in `locals_state` so that `local.get` falls
/// back to `Local(id)`, enabling `decompose_address` to track memory
/// stores/loads through frame pointers.
pub fn contains_unknown(sv: &StackValue) -> bool {
    match sv {
        StackValue::Unknown => true,
        StackValue::BinOp { left, right, .. } => {
            contains_unknown(left) || contains_unknown(right)
        }
        StackValue::UnOp { operand, .. } => {
            contains_unknown(operand)
        }
        _ => false,
    }
}

/// Decompose an address StackValue into (LocalId, base_offset).
///
/// Recursively handles nested Add/Sub chains like `(Local(id) + 16) + (0 + 8)`.
/// The WASM compiler often generates multi-level address arithmetic for
/// stack-allocated arrays used by vec_new_from_linear_memory.
pub fn decompose_address(
    addr: &StackValue,
) -> Option<(LocalId, i64)> {
    match addr {
        StackValue::Local(lid) => Some((*lid, 0)),
        StackValue::BinOp {
            op: crate::ir::BinOp::Add,
            left,
            right,
        } => {
            // Try left as base, right as constant offset.
            if let Some((lid, base)) = decompose_address(left) {
                if let Some(rv) = eval_const_i64(right) {
                    return Some((lid, base + rv));
                }
            }
            // Try right as base, left as constant offset.
            if let Some((lid, base)) = decompose_address(right) {
                if let Some(lv) = eval_const_i64(left) {
                    return Some((lid, base + lv));
                }
            }
            None
        }
        StackValue::BinOp {
            op: crate::ir::BinOp::Sub,
            left,
            right,
        } => {
            if let Some((lid, base)) = decompose_address(left) {
                if let Some(rv) = eval_const_i64(right) {
                    return Some((lid, base - rv));
                }
            }
            None
        }
        _ => None,
    }
}

/// Evaluate a StackValue as a compile-time constant integer.
///
/// Handles literal constants and simple Add/Sub/Mul of constants.
fn eval_const_i64(sv: &StackValue) -> Option<i64> {
    use crate::ir::BinOp as B;
    match sv {
        StackValue::Const(ir::Value::I32(n)) => Some(*n as i64),
        StackValue::Const(ir::Value::I64(n)) => Some(*n),
        StackValue::BinOp { op: B::Add, left, right } => {
            Some(eval_const_i64(left)? + eval_const_i64(right)?)
        }
        StackValue::BinOp { op: B::Sub, left, right } => {
            Some(eval_const_i64(left)? - eval_const_i64(right)?)
        }
        StackValue::BinOp { op: B::Mul, left, right } => {
            Some(eval_const_i64(left)? * eval_const_i64(right)?)
        }
        _ => None,
    }
}

/// Try to decode vec elements from memory stores for `vec_new_from_linear_memory`.
///
/// The ptr arg points to an array of consecutive 8-byte tagged Val entries.
/// Strips Val encoding from ptr to get the base address, then reads elements
/// from memory_state at consecutive 8-byte offsets.
///
/// **Spill area fallback:** WASM compilers often store the actual values in a
/// spill area (e.g. `$frame+0`, `$frame+8`) and then use a loop to copy them
/// to the vec array (e.g. `$frame+16`, `$frame+24`). Since our single-pass
/// simulation doesn't fully execute loops, the copy may be incomplete. When
/// the direct read has missing elements, we fall back to reading consecutive
/// entries starting at offset 0 from the same local — the spill area.
pub fn try_decode_vec_elements(
    args: &[StackValue],
    memory_state: &HashMap<(LocalId, i64), StackValue>,
) -> Option<Vec<StackValue>> {
    let ptr_raw = args.get(0)?;
    let len_raw = args.get(1)?;

    // Strip Val encoding from ptr: (expr << 32) | 4 → expr
    let ptr_stripped = crate::pattern_recognizer::strip_val_boilerplate(ptr_raw);
    let (base_local, base_offset) = decompose_address(&ptr_stripped)?;

    // Extract len as u32
    let len = crate::pattern_recognizer::extract_u32_val(len_raw)?;
    if len > 16 { return None; } // sanity limit

    // First, try reading directly from the vec array.
    let mut elements = Vec::new();
    let mut all_found = true;
    for i in 0..len {
        let offset = base_offset + (i as i64) * 8;
        if let Some(val) = memory_state.get(&(base_local, offset)) {
            elements.push(val.clone());
        } else {
            all_found = false;
            elements.push(StackValue::Unknown);
        }
    }

    if all_found && !elements.iter().all(|v| matches!(v, StackValue::Unknown)) {
        return Some(elements);
    }

    // Fallback: try reading from common spill area offsets.
    // The compiler stores values at $frame+N, $frame+N+8, ... then copies them
    // to the vec array via a loop that our single-pass simulation doesn't fully run.
    for spill_base in &[0i64, 8, 16, 24, 32, 48] {
        if *spill_base == base_offset { continue; }
        let mut spill_elements = Vec::new();
        let mut spill_ok = true;
        for i in 0..len {
            let offset = *spill_base + (i as i64) * 8;
            if let Some(val) = memory_state.get(&(base_local, offset)) {
                spill_elements.push(val.clone());
            } else {
                spill_ok = false;
                break;
            }
        }
        if spill_ok && !spill_elements.iter().all(|v| matches!(v, StackValue::Unknown)) {
            return Some(spill_elements);
        }
    }

    // Partial result: return whatever we found directly (may have Unknown gaps).
    if elements.iter().any(|v| !matches!(v, StackValue::Unknown)) {
        return Some(elements);
    }

    None
}

/// Try to decode map elements from `map_new_from_linear_memory(keys_ptr, vals_ptr, len)`.
///
/// Reads keys from the WASM data section (they're symbol Vals embedded in the binary),
/// and reads values from the memory_state (stack-allocated tagged Vals).
pub fn try_decode_map_elements(
    args: &[StackValue],
    memory_state: &HashMap<(LocalId, i64), StackValue>,
    analyzed: &AnalyzedModule,
) -> Option<(Vec<String>, Vec<StackValue>)> {
    let keys_ptr_raw = args.get(0)?;
    let vals_ptr_raw = args.get(1)?;
    let len_raw = args.get(2)?;

    let len = crate::pattern_recognizer::extract_u32_val(len_raw)?;
    if len > 32 { return None; } // sanity limit

    // Keys: read from the data section (they're static symbol constants).
    let keys_ptr = crate::pattern_recognizer::extract_u32_val(keys_ptr_raw)?;
    let keys = crate::pattern_recognizer::decode_keys_from_linear_memory(keys_ptr, len, analyzed)?;

    // Values: read from memory_state at the vals_ptr location.
    let vals_stripped = crate::pattern_recognizer::strip_val_boilerplate(vals_ptr_raw);
    let mut values = Vec::new();
    if let Some((base_local, base_offset)) = decompose_address(&vals_stripped) {
        for i in 0..len {
            let offset = base_offset + (i as i64) * 8;
            let val = memory_state.get(&(base_local, offset))
                .cloned()
                .unwrap_or(StackValue::Unknown);
            values.push(val);
        }
    } else {
        // Can't resolve values, use unknowns
        values = vec![StackValue::Unknown; len as usize];
    }

    Some((keys, values))
}

/// Map a walrus BinaryOp to our IR BinOp, returning None for unmappable ops.
pub fn map_binop(op: &BinaryOp) -> Option<crate::ir::BinOp> {
    use crate::ir::BinOp as B;
    use BinaryOp::*;
    match op {
        // Arithmetic
        I32Add | I64Add | F32Add | F64Add => Some(B::Add),
        I32Sub | I64Sub | F32Sub | F64Sub => Some(B::Sub),
        I32Mul | I64Mul | F32Mul | F64Mul => Some(B::Mul),
        I32DivS | I32DivU | I64DivS | I64DivU
        | F32Div | F64Div => Some(B::Div),
        I32RemS | I32RemU | I64RemS | I64RemU => Some(B::Rem),

        // Bitwise
        I32And | I64And => Some(B::BitAnd),
        I32Or | I64Or => Some(B::BitOr),
        I32Xor | I64Xor => Some(B::BitXor),
        I32Shl | I64Shl => Some(B::Shl),
        I32ShrS | I32ShrU | I64ShrS | I64ShrU => Some(B::Shr),

        // Comparisons
        I32Eq | I64Eq | F32Eq | F64Eq => Some(B::Eq),
        I32Ne | I64Ne | F32Ne | F64Ne => Some(B::Ne),
        I32LtS | I32LtU | I64LtS | I64LtU
        | F32Lt | F64Lt => Some(B::Lt),
        I32LeS | I32LeU | I64LeS | I64LeU
        | F32Le | F64Le => Some(B::Le),
        I32GtS | I32GtU | I64GtS | I64GtU
        | F32Gt | F64Gt => Some(B::Gt),
        I32GeS | I32GeU | I64GeS | I64GeU
        | F32Ge | F64Ge => Some(B::Ge),

        // Rotations, SIMD, etc.
        _ => None,
    }
}

/// Map a walrus UnaryOp to our IR UnOp, returning None for unmappable ops.
///
/// Most WASM unary ops are type conversions (wrap, extend, trunc) which are
/// handled specially in the caller rather than mapped here.
pub fn map_unop(op: &UnaryOp) -> Option<crate::ir::UnOp> {
    use crate::ir::UnOp as U;
    match op {
        UnaryOp::F32Neg | UnaryOp::F64Neg => Some(U::Neg),
        UnaryOp::I32Eqz | UnaryOp::I64Eqz => Some(U::Not),
        _ => None,
    }
}
