//! Loop body pattern recognition.
//!
//! Detects structured loop patterns (vec iteration, range loops) from
//! the raw analyzed blocks and their already-built IR statements.

use crate::ir::{Expr, Statement};
use crate::wasm_analysis::AnalyzedBlock;

use super::RecognitionContext;
use super::guard_analysis::is_vec_iteration_boilerplate;
use super::val_decoding;

/// Try to recognize a structured loop pattern from analyzed blocks and their
/// already-built statements.
///
/// Detects two patterns:
/// 1. **Vec iteration**: body contains `vec_len(v)` and `vec_get(v, i)` calls
///    -> emits `ForEach { var_name: "item", collection: v, body }`
/// 2. **Range iteration**: body contains arithmetic accumulation with a counter
///    -> emits `ForRange { var_name: "i", bound, body }`
///
/// Falls back to `None` if no pattern is recognized.
pub(super) fn try_recognize_loop_pattern(
    analyzed_body: &[AnalyzedBlock],
    body_stmts: &[Statement],
    ctx: &RecognitionContext,
) -> Option<Statement> {
    // Scan analyzed blocks for vec_len and vec_get host calls.
    let mut vec_len_collection: Option<Expr> = None;
    let mut vec_get_var: Option<String> = None;
    let mut has_vec_get = false;

    for block in analyzed_body {
        if let AnalyzedBlock::HostCall(call) = block {
            match call.host_func.name {
                "vec_len" => {
                    // The first arg to vec_len is the vec being iterated.
                    if let Some(arg) = call.args.first() {
                        let stripped = val_decoding::strip_val_boilerplate(arg);
                        let expr = val_decoding::resolve_arg(
                            &stripped,
                            &ctx.param_names,
                            &ctx.call_result_names,
                        );
                        vec_len_collection = Some(expr);
                    }
                }
                "vec_get" => {
                    has_vec_get = true;
                    // The result name for vec_get is the loop variable.
                    if let Some(name) = ctx.call_result_names.get(&call.call_site_id) {
                        vec_get_var = Some(name.clone());
                    }
                }
                _ => {}
            }
        }
        // Recurse into nested if/else blocks inside the loop.
        scan_loop_body_nested(block, ctx, &mut vec_len_collection, &mut vec_get_var, &mut has_vec_get);
    }

    if let Some(collection) = vec_len_collection {
        let filtered_body: Vec<Statement> = body_stmts.iter()
            .filter(|s| !is_vec_iteration_boilerplate(s))
            .cloned()
            .collect();

        if has_vec_get {
            // Pattern 1: vec iteration (vec_len + vec_get)
            let var_name = vec_get_var.unwrap_or_else(|| "item".to_string());
            return Some(Statement::ForEach {
                var_name,
                collection,
                body: filtered_body,
            });
        } else {
            // Pattern 2: range loop -- vec_len without vec_get means `for i in 0..len`
            return Some(Statement::ForRange {
                var_name: "i".to_string(),
                bound: collection,
                body: filtered_body,
            });
        }
    }

    None
}

/// Recursively scan nested blocks inside a loop body for vec_len/vec_get calls.
fn scan_loop_body_nested(
    block: &AnalyzedBlock,
    ctx: &RecognitionContext,
    vec_len_collection: &mut Option<Expr>,
    vec_get_var: &mut Option<String>,
    has_vec_get: &mut bool,
) {
    match block {
        AnalyzedBlock::If { then_block, else_block, .. } => {
            for b in then_block.iter().chain(else_block.iter()) {
                if let AnalyzedBlock::HostCall(call) = b {
                    match call.host_func.name {
                        "vec_len" => {
                            if vec_len_collection.is_none() {
                                if let Some(arg) = call.args.first() {
                                    let stripped = val_decoding::strip_val_boilerplate(arg);
                                    let expr = val_decoding::resolve_arg(
                                        &stripped,
                                        &ctx.param_names,
                                        &ctx.call_result_names,
                                    );
                                    *vec_len_collection = Some(expr);
                                }
                            }
                        }
                        "vec_get" => {
                            *has_vec_get = true;
                            if vec_get_var.is_none() {
                                if let Some(name) = ctx.call_result_names.get(&call.call_site_id) {
                                    *vec_get_var = Some(name.clone());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                scan_loop_body_nested(b, ctx, vec_len_collection, vec_get_var, has_vec_get);
            }
        }
        AnalyzedBlock::Loop { body, .. } => {
            for b in body {
                if let AnalyzedBlock::HostCall(call) = b {
                    match call.host_func.name {
                        "vec_len" => {
                            if vec_len_collection.is_none() {
                                if let Some(arg) = call.args.first() {
                                    let stripped = val_decoding::strip_val_boilerplate(arg);
                                    let expr = val_decoding::resolve_arg(
                                        &stripped,
                                        &ctx.param_names,
                                        &ctx.call_result_names,
                                    );
                                    *vec_len_collection = Some(expr);
                                }
                            }
                        }
                        "vec_get" => {
                            *has_vec_get = true;
                            if vec_get_var.is_none() {
                                if let Some(name) = ctx.call_result_names.get(&call.call_site_id) {
                                    *vec_get_var = Some(name.clone());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                scan_loop_body_nested(b, ctx, vec_len_collection, vec_get_var, has_vec_get);
            }
        }
        AnalyzedBlock::HostCall(_) => {}
    }
}
