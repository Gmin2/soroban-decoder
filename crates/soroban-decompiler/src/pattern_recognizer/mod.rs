/// Pattern recognition: maps WASM host call sequences to idiomatic Soroban SDK operations.
///
/// Takes tracked host calls (with resolved arguments from stack simulation) and
/// the contract spec, then produces high-level IR statements that correspond to
/// SDK method calls like `env.storage().persistent().get(...)`.

use std::collections::HashMap;

use stellar_xdr::curr::{ScSpecEntry, ScSpecFunctionV0};

use crate::ir::{Expr, FunctionIR, Statement};
use crate::wasm_analysis::{AnalyzedBlock, AnalyzedModule, StackValue, TrackedHostCall};

mod host_calls;
mod val_decoding;
mod optimization;

pub use val_decoding::{
    strip_val_boilerplate, extract_u32_val, decode_keys_from_linear_memory,
};

/// Bundles all context needed during pattern recognition.
pub(super) struct RecognitionContext<'a> {
    pub(super) analyzed: &'a AnalyzedModule,
    pub(super) all_entries: &'a [ScSpecEntry],
    pub(super) param_names: Vec<String>,
    pub(super) call_result_names: HashMap<usize, String>,
    pub(super) memory_strings: HashMap<usize, String>,
    pub(super) vec_contents: &'a HashMap<usize, Vec<StackValue>>,
    pub(super) map_contents: &'a HashMap<usize, (Vec<String>, Vec<StackValue>)>,
    #[allow(dead_code)]
    pub(super) unpack_field_ids: &'a HashMap<usize, Vec<usize>>,
}

/// Recognize SDK patterns in a function's host calls and produce IR.
///
/// Returns `None` if the function has no recognizable body.
pub fn recognize(
    analyzed: &AnalyzedModule,
    spec: &ScSpecFunctionV0,
    all_entries: &[ScSpecEntry],
) -> Option<FunctionIR> {
    let export_name = spec.name.to_utf8_string_lossy();

    let analysis = analyzed.analyze_export(&export_name).ok()?;
    let impl_func_id = analysis.impl_func_id;

    let stack_analysis = analyzed.analyze_function_stack(impl_func_id);

    // Determine if the impl function has an implicit env parameter.
    // New-style: WASM params = spec inputs + 1 (env is param 0)
    // Old-style: WASM params = spec inputs (no implicit env, all params are user values)
    let wasm_params = analyzed.wasm_param_count(impl_func_id);
    let spec_inputs = spec.inputs.len() as usize;
    let has_implicit_env = wasm_params > spec_inputs;
    let param_names = param_names_from_spec(spec, has_implicit_env);

    // Pre-decode string/symbol literals from the WASM data section.
    let memory_strings = build_memory_strings(&stack_analysis.host_calls, analyzed);

    let map_contents = &stack_analysis.map_contents;
    let unpack_field_ids = &stack_analysis.unpack_field_ids;

    // Build a preliminary context for the first pass (empty
    // call_result_names — they're populated during the scan).
    let preliminary_ctx = RecognitionContext {
        analyzed,
        all_entries,
        param_names: param_names.clone(),
        call_result_names: HashMap::new(),
        memory_strings: memory_strings.clone(),
        vec_contents: &stack_analysis.vec_contents,
        map_contents,
        unpack_field_ids,
    };

    // First pass: assign variable names to let-binding results.
    let call_result_names = build_call_result_names(
        &stack_analysis.host_calls,
        &preliminary_ctx,
    );

    // Build the final context for the second pass.
    let ctx = RecognitionContext {
        call_result_names: call_result_names.clone(),
        ..preliminary_ctx
    };

    // Second pass: build hierarchical statements from the analyzed blocks.
    let mut statements = build_statements_from_blocks(
        &stack_analysis.blocks, &ctx,
    );

    // If the function has a meaningful return expression, emit it.
    // First try to "see through" Val encoding wrappers — if the return value
    // comes from obj_from_u64/obj_from_i64/etc., the real return is the arg
    // passed to that function. Then strip Val boilerplate (>> 32, << 8, etc.)
    let effective_return = stack_analysis.return_expr.as_ref().and_then(|ret| {
        val_decoding::unwrap_val_encoding(ret, &stack_analysis.host_calls)
            .or(Some(ret.clone()))
    });

    if let Some(ret_val) = &effective_return {
        let stripped = strip_val_boilerplate(ret_val);
        let ret_expr = val_decoding::resolve_arg(&stripped, &param_names, &call_result_names);
        if should_emit_return_expr(&ret_expr) {
            statements.push(Statement::Return(Some(ret_expr)));
        }
    }

    // Common subexpression elimination: when two Let bindings produce the
    // same expression, remove the duplicate and rewrite references.
    statements = optimization::eliminate_common_subexprs(statements);

    // Dead variable elimination: remove Let bindings whose names are never
    // referenced in subsequent statements or expressions.
    statements = optimization::eliminate_dead_vars(statements);

    if statements.is_empty() {
        return None;
    }

    Some(FunctionIR {
        name: export_name,
        body: statements,
    })
}

/// Pre-decode string/symbol literals from the WASM data section.
///
/// Scans all host calls for `symbol_new_from_linear_memory` and
/// `string_new_from_linear_memory`, extracts their ptr/len arguments
/// (tagged U32Val constants), and reads the actual bytes from the data section.
fn build_memory_strings(
    calls: &[TrackedHostCall],
    analyzed: &AnalyzedModule,
) -> HashMap<usize, String> {
    let mut strings = HashMap::new();
    for call in calls {
        let name = call.host_func.name;
        if name == "symbol_new_from_linear_memory" || name == "string_new_from_linear_memory" {
            let ptr = call.args.get(0).and_then(extract_u32_val);
            let len = call.args.get(1).and_then(extract_u32_val);
            if let (Some(p), Some(l)) = (ptr, len) {
                if let Some(bytes) = analyzed.read_linear_memory(p, l) {
                    if let Ok(s) = String::from_utf8(bytes) {
                        strings.insert(call.call_site_id, s);
                    }
                }
            }
        }
    }
    strings
}

/// First pass: scan all host calls and assign variable names to
/// let-binding results.
fn build_call_result_names(
    calls: &[TrackedHostCall],
    ctx: &RecognitionContext,
) -> HashMap<usize, String> {
    let mut crn: HashMap<usize, String> = HashMap::new();
    let mut name_counts: HashMap<String, usize> = HashMap::new();

    for call in calls {
        if let Some(mut stmt) = host_calls::recognize_call(call, ctx, &crn) {
            if let Statement::Let { name, .. } = &mut stmt {
                let base = name.clone();
                let count = name_counts
                    .entry(base.clone())
                    .or_insert(0);
                if *count > 0 {
                    *name = format!("{base}_{count}");
                }
                *count += 1;
                crn.insert(call.call_site_id, name.clone());
            }
        }

        // Name synthetic fields from map unpack operations.
        name_unpack_fields(
            call,
            "map_unpack_to_linear_memory",
            ctx,
            &mut crn,
        );

        // Name synthetic fields from vec unpack operations.
        name_vec_unpack_fields(call, ctx, &mut crn);
    }

    crn
}

/// Assign names to synthetic field CallResults from map unpack.
fn name_unpack_fields(
    call: &TrackedHostCall,
    expected_name: &str,
    ctx: &RecognitionContext,
    crn: &mut HashMap<usize, String>,
) {
    if call.host_func.name != expected_name {
        return;
    }
    let Some(field_ids) =
        ctx.unpack_field_ids.get(&call.call_site_id)
    else {
        return;
    };
    let keys_ptr = extract_u32_val(
        call.args.get(1).unwrap_or(&StackValue::Unknown),
    );
    let len = extract_u32_val(
        call.args.get(3).unwrap_or(&StackValue::Unknown),
    );
    let (Some(kp), Some(l)) = (keys_ptr, len) else {
        return;
    };
    let Some(keys) = decode_keys_from_linear_memory(
        kp, l, ctx.analyzed,
    ) else {
        return;
    };
    let source = crn
        .get(&call.call_site_id)
        .cloned()
        .unwrap_or_else(|| "unpacked".into());
    for (i, fid) in field_ids.iter().enumerate() {
        if let Some(key) = keys.get(i) {
            crn.insert(*fid, format!("{source}.{key}"));
        }
    }
}

/// Assign names to synthetic field CallResults from vec unpack.
fn name_vec_unpack_fields(
    call: &TrackedHostCall,
    ctx: &RecognitionContext,
    crn: &mut HashMap<usize, String>,
) {
    if call.host_func.name != "vec_unpack_to_linear_memory" {
        return;
    }
    let Some(field_ids) =
        ctx.unpack_field_ids.get(&call.call_site_id)
    else {
        return;
    };
    let source = crn
        .get(&call.call_site_id)
        .cloned()
        .unwrap_or_else(|| "unpacked".into());
    for (i, fid) in field_ids.iter().enumerate() {
        crn.insert(*fid, format!("{source}[{i}]"));
    }
}

/// Second pass: recursively build IR statements from hierarchical
/// analyzed blocks.
fn build_statements_from_blocks(
    blocks: &[AnalyzedBlock],
    ctx: &RecognitionContext,
) -> Vec<Statement> {
    let mut stmts = Vec::new();

    for block in blocks {
        match block {
            AnalyzedBlock::HostCall(call) => {
                if let Some(mut stmt) =
                    host_calls::recognize_call(call, ctx, &ctx.call_result_names)
                {
                    // Re-apply the name from the first pass.
                    if let Statement::Let { name, .. } = &mut stmt {
                        if let Some(assigned) =
                            ctx.call_result_names
                                .get(&call.call_site_id)
                        {
                            *name = assigned.clone();
                        }
                    }
                    stmts.push(stmt);
                }
            }
            AnalyzedBlock::If {
                condition,
                then_block,
                else_block,
            } => {
                let then_stmts =
                    build_statements_from_blocks(then_block, ctx);
                let else_stmts =
                    build_statements_from_blocks(else_block, ctx);
                if then_stmts.is_empty() && else_stmts.is_empty() {
                    continue;
                }
                let cond_expr = match condition {
                    Some(cond_val) => {
                        let stripped = strip_val_boilerplate(cond_val);
                        val_decoding::resolve_arg(
                            &stripped,
                            &ctx.param_names,
                            &ctx.call_result_names,
                        )
                    }
                    None => Expr::Raw("/* condition */".into()),
                };
                stmts.push(Statement::If {
                    condition: cond_expr,
                    then_body: then_stmts,
                    else_body: else_stmts,
                });
            }
            AnalyzedBlock::Loop { body, .. } => {
                // Flatten loops: most WASM loops in Soroban contracts
                // are compiler-generated, not user-written.
                let body_stmts =
                    build_statements_from_blocks(body, ctx);
                stmts.extend(body_stmts);
            }
        }
    }

    stmts
}

/// Decide whether a resolved return expression is worth emitting.
///
/// Filters out noise like `/* computed */`, `/* unknown */`, `/* void */`
/// but allows named variables, literals, and operations through.
fn should_emit_return_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Raw(s) => {
            // Suppress void, unknown, computed placeholders
            !s.contains("void") && !s.contains("unknown") && !s.contains("computed")
        }
        Expr::Literal(_) | Expr::Var(_) | Expr::MethodChain { .. }
        | Expr::BinOp { .. } | Expr::UnOp { .. } | Expr::HostCall { .. }
        | Expr::MacroCall { .. } | Expr::StructLiteral { .. }
        | Expr::EnumVariant { .. } => true,
    }
}

/// Extract parameter names from a spec function.
///
/// When `has_implicit_env` is true, Param(0) is the implicit env and
/// Param(1..) map to spec inputs (standard new-style dispatcher).
/// When false, Param(0) maps directly to spec input 0 (old-style contracts).
fn param_names_from_spec(spec: &ScSpecFunctionV0, has_implicit_env: bool) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if has_implicit_env {
        names.push("env".into()); // Param(0) = env
    }
    for input in spec.inputs.iter() {
        names.push(input.name.to_utf8_string_lossy());
    }
    names
}
