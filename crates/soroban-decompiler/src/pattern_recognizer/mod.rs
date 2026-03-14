//! Pattern recognition: maps WASM host call sequences to idiomatic Soroban SDK operations.
//!
//! This is the third stage of the decompilation pipeline. It takes the tracked
//! host function calls (with resolved arguments from stack simulation) and the
//! contract spec, then produces high-level [`crate::ir`] statements that
//! correspond to SDK method calls like `env.storage().persistent().get(...)`.
//!
//! The recognition process runs in two passes:
//!
//! 1. **Name assignment** -- scans all host calls and assigns variable names
//!    to let-binding results. Struct field names are resolved from map/vec
//!    unpack operations using the WASM data section.
//!
//! 2. **Statement building** -- walks the analyzed block tree (preserving
//!    if/else and loop structure) and converts each host call into an IR
//!    statement using the names from the first pass.
//!
//! After both passes, the result goes through two optimization passes:
//! common subexpression elimination and dead variable elimination.
//!
//! # Submodules
//!
//! - [`host_calls`] -- per-host-function pattern matching (storage, auth,
//!   ledger, crypto, token, etc.)
//! - [`val_decoding`] -- Soroban Val encoding/decoding, symbol resolution,
//!   and expression resolution from stack values to IR expressions
//! - [`optimization`] -- CSE, DCE, and variable renaming passes

use std::collections::HashMap;

use stellar_xdr::curr::{ScSpecEntry, ScSpecFunctionV0, ScSpecTypeDef};

use crate::ir::{Expr, FunctionIR, Statement};
use crate::wasm_analysis::{AnalyzedBlock, AnalyzedModule, StackValue, TrackedHostCall};

pub mod host_calls;
pub mod val_decoding;
pub mod optimization;

pub use val_decoding::{
    strip_val_boilerplate, extract_u32_val, decode_keys_from_linear_memory,
};

/// Bundles all context needed during pattern recognition.
pub struct RecognitionContext<'a> {
    pub analyzed: &'a AnalyzedModule,
    pub all_entries: &'a [ScSpecEntry],
    pub param_names: Vec<String>,
    pub call_result_names: HashMap<usize, String>,
    pub memory_strings: HashMap<usize, String>,
    pub vec_contents: &'a HashMap<usize, Vec<StackValue>>,
    pub map_contents: &'a HashMap<usize, (Vec<String>, Vec<StackValue>)>,
    #[allow(dead_code)]
    pub unpack_field_ids: &'a HashMap<usize, Vec<usize>>,
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

    // Set thread-local memory strings so resolve_arg can resolve
    // unnamed CallResults to their decoded string/symbol literals.
    val_decoding::set_memory_strings(&memory_strings);

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

    if std::env::var("DECOMPILER_DEBUG_IR").is_ok() {
        eprintln!("[IR] {} statements before optimization:", statements.len());
        for (i, s) in statements.iter().enumerate() {
            eprintln!("  [{}] {:?}", i, s);
        }
    }

    // Common subexpression elimination: when two Let bindings produce the
    // same expression, remove the duplicate and rewrite references.
    statements = optimization::eliminate_common_subexprs(statements);

    // Dead variable elimination: remove Let bindings whose names are never
    // referenced in subsequent statements or expressions.
    statements = optimization::eliminate_dead_vars(statements);

    // i128 arithmetic collapse: simplify carry-chain expansions that the
    // WASM compiler generates for i128 operations (sign-extension, double
    // negation, zero-multiplication, and deeply nested arithmetic).
    statements = optimization::collapse_i128_patterns(statements);

    // Constant guard folding: evaluate constant if-conditions and inline
    // or remove trivially true/false branches, type tag checks, and
    // non-boolean br_if continuation artifacts.
    statements = optimization::fold_constant_guards(statements);

    // Hoist scoped bindings: when a Let binding inside an if block is
    // referenced by subsequent statements, flatten the if to fix scoping.
    // Must run AFTER fold_constant_guards so type tag guards are removed
    // and the has()/get() pattern is exposed at the correct nesting level.
    statements = optimization::hoist_scoped_bindings(statements);

    // Re-run CSE after hoisting: guard folding and hoisting may expose
    // duplicate bindings that were previously hidden inside nested if blocks
    // (e.g. duplicate Symbol::new("Counter") or DataKey::Counter(user)).
    statements = optimization::eliminate_common_subexprs(statements);

    // Identity binding elimination: remove `let x = y;` and replace
    // all references to x with y (including dotted paths like x.field).
    statements = optimization::eliminate_identity_bindings(statements);

    // Run DCE again after all optimization passes.
    statements = optimization::eliminate_dead_vars(statements);

    // Error branch reconstruction: for Result-returning functions, detect
    // the WASM default-then-override pattern where the error branch is lost
    // during simulation. Pattern: `If { cond, then_body: [side_effects], else: [] }`
    // followed by `Return(val)` → move return into if-then, add Err return to else.
    let is_result = spec.outputs.to_option()
        .map_or(false, |t| matches!(t, ScSpecTypeDef::Result(_)));
    if is_result {
        statements = reconstruct_error_branches(statements, all_entries);
    }

    if statements.is_empty() {
        return None;
    }

    Some(FunctionIR {
        name: export_name,
        body: statements,
    })
}

/// Reconstruct error branches in Result-returning functions.
///
/// Detects the WASM default-then-override pattern where `local = Error; if (ok) { ...; local = Ok; } return local;`
/// was flattened to `If { cond, then: [side_effects], else: [] }; Return(val)` because the error
/// value was lost during simulation. Moves the Return into the if-then body and adds an Err return
/// to the else branch.
fn reconstruct_error_branches(stmts: Vec<Statement>, all_entries: &[ScSpecEntry]) -> Vec<Statement> {
    // Find the first error enum variant value for the Err branch.
    let first_error_val = all_entries.iter().find_map(|e| {
        if let ScSpecEntry::UdtErrorEnumV0(err) = e {
            err.cases.first().map(|c| c.value)
        } else {
            None
        }
    });
    let error_val = match first_error_val {
        Some(v) => v,
        None => return stmts, // No error enum defined, nothing to do
    };

    let n = stmts.len();
    if n < 2 {
        return stmts;
    }

    // Look for the pattern: If { cond, then: [has side effects], else: [] } followed by Return(val)
    let last_idx = n - 1;
    let penult_idx = n - 2;

    let is_pattern = matches!(
        (&stmts[penult_idx], &stmts[last_idx]),
        (
            Statement::If { else_body, .. },
            Statement::Return(Some(_))
        ) if else_body.is_empty()
    );

    if !is_pattern {
        return stmts;
    }

    // Check that the if-then body has side effects (storage write, event publish, etc.)
    // to distinguish from read-only guards that shouldn't get error branches.
    let has_side_effects = if let Statement::If { then_body, .. } = &stmts[penult_idx] {
        then_body.iter().any(|s| matches!(s, Statement::Expr(_)))
    } else {
        false
    };

    if !has_side_effects {
        return stmts;
    }

    // Reconstruct: move Return into if-then, add Err return to else
    let mut result: Vec<Statement> = stmts[..penult_idx].to_vec();
    let return_stmt = stmts[last_idx].clone();

    if let Statement::If { condition, then_body, .. } = &stmts[penult_idx] {
        let mut new_then = then_body.clone();
        new_then.push(return_stmt);

        let error_placeholder = format!("__contract_error_{}", error_val);
        let else_body = vec![
            Statement::Return(Some(Expr::Var(error_placeholder))),
        ];

        result.push(Statement::If {
            condition: condition.clone(),
            then_body: new_then,
            else_body,
        });
    }

    result
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

    let debug = std::env::var("DECOMPILER_DEBUG").is_ok();

    for call in calls {
        if debug && (call.host_func.name.contains("put_contract_data")
            || call.host_func.name.contains("symbol_new")
            || call.host_func.name.contains("vec_new_from_linear")
            || call.host_func.name.contains("map_new_from_linear"))
        {
            eprintln!("[CRN] call_site_id={} func={} args={:?}",
                call.call_site_id, call.host_func.name,
                call.args.iter().take(3).collect::<Vec<_>>());
        }

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
                if debug && (call.host_func.name.contains("symbol_new")
                    || call.host_func.name.contains("vec_new_from_linear")
                    || call.host_func.name.contains("map_new_from_linear")
                    || call.host_func.name.contains("put_contract_data"))
                {
                    eprintln!("[CRN] -> Let name='{}' for call_site_id={}", name, call.call_site_id);
                }
            }
        }

        // For intermediate host calls that don't produce Let bindings,
        // assign heuristic names so downstream references resolve
        // instead of showing "/* computed */".
        if !crn.contains_key(&call.call_site_id) {
            let hname = call.host_func.name;
            let base: String = match hname {
                "vec_new_from_linear_memory" | "vec_new" => "args".into(),
                "map_new_from_linear_memory" | "map_new" => "map_val".into(),
                "bytes_new_from_linear_memory" | "bytes_new" => "bytes_val".into(),
                "obj_from_u128_pieces" => "u128_val".into(),
                "obj_from_i128_pieces" => "i128_val".into(),
                "obj_from_u64" | "obj_from_i64" | "obj_from_u256_pieces"
                | "obj_from_i256_pieces" => "val".into(),
                "vec_len" | "map_len" | "bytes_len" => "len".into(),
                "vec_get" | "map_get" => "item".into(),
                // Generic fallback: derive name from host function name.
                _ => hname
                    .strip_prefix("bls12_381_")
                    .or_else(|| hname.strip_prefix("bn254_"))
                    .unwrap_or(hname)
                    .replace("_to_", "_")
                    .into(),
            };
            let count = name_counts.entry(base.clone()).or_insert(0);
            let name = if *count > 0 {
                format!("{base}_{count}")
            } else {
                base
            };
            *count += 1;
            crn.insert(call.call_site_id, name.clone());
            if debug && (hname.contains("symbol_new")
                || hname.contains("vec_new_from_linear")
                || hname.contains("map_new_from_linear")
                || hname.contains("put_contract_data"))
            {
                eprintln!("[CRN] -> heuristic name='{}' for call_site_id={} (func={})", name, call.call_site_id, hname);
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
                guard_trap,
                ..
            } => {
                // Guard/precondition pattern: if cond { panic!() }
                // The continuation should be FLAT, not nested inside else.
                if *guard_trap {
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

                    // Only emit panic for user-level preconditions: direct
                    // comparisons between named variables/params (e.g.
                    // `amount_b < min_b_for_a`). Skip SDK-generated guards:
                    // type tag checks, decode checks, overflow checks, and
                    // any non-comparison expressions.
                    let is_user_precondition = is_user_comparison(&cond_expr);

                    if is_user_precondition {
                        stmts.push(Statement::If {
                            condition: cond_expr,
                            then_body: vec![Statement::Expr(
                                Expr::MacroCall {
                                    name: "panic".into(),
                                    args: vec![Expr::Literal(crate::ir::Literal::Str(
                                        "precondition failed".into(),
                                    ))],
                                },
                            )],
                            else_body: vec![],
                        });
                    }
                    // Process remaining blocks as flat siblings regardless
                    let nested = build_statements_from_blocks(else_block, ctx);
                    stmts.extend(nested);
                    continue;
                }

                let then_stmts =
                    build_statements_from_blocks(then_block, ctx);
                let else_stmts =
                    build_statements_from_blocks(else_block, ctx);
                // Skip empty if/else blocks unless one branch contains
                // error handling (panic_with_error) — we want to preserve
                // error branching even when one side is empty.
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

                // Guard pattern: when the then branch is empty and
                // the else branch has content, negate the condition
                // and emit `if !cond { else_body }` for cleaner output.
                // This handles both the error/trap guard pattern
                // (alt_unreachable) and the br_if continuation pattern
                // where `block { br_if; ...body... }` becomes
                // `if cond {} else { body }`.
                if then_stmts.is_empty() && !else_stmts.is_empty() {
                    let negated = Expr::UnOp {
                        op: crate::ir::UnOp::Not,
                        operand: Box::new(cond_expr),
                    };
                    stmts.push(Statement::If {
                        condition: negated,
                        then_body: else_stmts,
                        else_body: vec![],
                    });
                } else {
                    stmts.push(Statement::If {
                        condition: cond_expr,
                        then_body: then_stmts,
                        else_body: else_stmts,
                    });
                }
            }
            AnalyzedBlock::Loop { body, has_back_edge } => {
                let body_stmts =
                    build_statements_from_blocks(body, ctx);
                if *has_back_edge {
                    if let Some(loop_stmt) = try_recognize_loop_pattern(body, &body_stmts, ctx) {
                        stmts.push(loop_stmt);
                        continue;
                    }
                }
                // Flatten: compiler artifacts, unrecognized loops, or
                // single-iteration loops all get inlined.
                stmts.extend(body_stmts);
            }
        }
    }

    stmts
}

/// Try to recognize a structured loop pattern from analyzed blocks and their
/// already-built statements.
///
/// Detects two patterns:
/// 1. **Vec iteration**: body contains `vec_len(v)` and `vec_get(v, i)` calls
///    → emits `ForEach { var_name: "item", collection: v, body }`
/// 2. **Range iteration**: body contains arithmetic accumulation with a counter
///    → emits `ForRange { var_name: "i", bound, body }`
///
/// Falls back to `None` if no pattern is recognized.
fn try_recognize_loop_pattern(
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
            // Pattern 2: range loop — vec_len without vec_get means `for i in 0..len`
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

/// Check if an expression is a user-level comparison suitable for
/// a precondition guard (`if cond { panic!() }`).
///
/// A user comparison is a relational operator (Lt, Le, Gt, Ge, Eq, Ne)
/// where both sides reference named variables (Var), not raw literals
/// or compiler-generated artifacts like bit shifts.
fn is_user_comparison(expr: &Expr) -> bool {
    use crate::ir::BinOp as B;
    match expr {
        Expr::BinOp { op: B::Lt | B::Le | B::Gt | B::Ge | B::Eq | B::Ne, left, right } => {
            has_named_var(left) && has_named_var(right)
                && !is_type_tag_check_expr(expr)
                && !is_overflow_check_expr(expr)
                && !is_arithmetic_overflow_check(expr)
        }
        _ => false,
    }
}

/// Detect compiler-generated arithmetic overflow checks.
///
/// Pattern: `(a + b) < a` or `(a + b) < b` — generated by the compiler
/// for `checked_add` (which Soroban uses for all `+=` operations).
/// Also: `a < (a - b)` for underflow checks on subtraction.
fn is_arithmetic_overflow_check(expr: &Expr) -> bool {
    use crate::ir::BinOp as B;
    match expr {
        // (a + b) < a  or  (a + b) < b
        Expr::BinOp { op: B::Lt, left, right } => {
            if let Expr::BinOp { op: B::Add, left: add_l, right: add_r } = left.as_ref() {
                // (a + b) < a — left operand of addition matches right of comparison
                if format!("{:?}", add_l) == format!("{:?}", right)
                    || format!("{:?}", add_r) == format!("{:?}", right) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// Check if an expression tree contains at least one named variable
/// (Var that's not a raw/computed placeholder).
fn has_named_var(expr: &Expr) -> bool {
    match expr {
        Expr::Var(name) => !name.starts_with("local_") && !name.starts_with("/*"),
        Expr::BinOp { left, right, .. } => has_named_var(left) || has_named_var(right),
        Expr::UnOp { operand, .. } => has_named_var(operand),
        Expr::Ref(inner) => has_named_var(inner),
        _ => false,
    }
}

/// Check if an expression is a Soroban type tag check.
///
/// Pattern: `(expr & 0xFF) != constant` or `(expr & 255) != constant`.
/// These are generated by the SDK to validate Val type tags at runtime
/// and should be stripped during decompilation.
fn is_type_tag_check_expr(expr: &Expr) -> bool {
    use crate::ir::BinOp as B;
    match expr {
        // (x & 255) != N  or  (x & 255) == N
        Expr::BinOp { op: B::Ne | B::Eq, left, .. } => {
            matches!(left.as_ref(),
                Expr::BinOp { op: B::BitAnd, right, .. }
                if matches!(right.as_ref(),
                    Expr::Literal(crate::ir::Literal::I64(255))
                    | Expr::Literal(crate::ir::Literal::I32(255))
                )
            )
        }
        _ => false,
    }
}

/// Check if an expression is an i128 decode/conversion check.
///
/// Pattern: `literal == literal` or `literal != literal` where both are
/// small integer constants — these come from i128 decoder helpers checking
/// return status. Handles both I32 and I64 literal types.
fn is_decode_check_expr(expr: &Expr) -> bool {
    use crate::ir::BinOp as B;
    match expr {
        Expr::BinOp { op: B::Eq | B::Ne, left, right } => {
            let is_small_const = |e: &Expr| match e {
                Expr::Literal(crate::ir::Literal::I32(v)) => v.unsigned_abs() <= 32,
                Expr::Literal(crate::ir::Literal::I64(v)) => v.unsigned_abs() <= 32,
                _ => false,
            };
            is_small_const(left) && is_small_const(right)
        }
        _ => false,
    }
}

/// Check if an expression is an overflow guard from i128 arithmetic.
///
/// Pattern: `((a >> 63) ^ (b >> 63)) & (...) < 0` — generated by the
/// compiler for i128 subtraction overflow detection.
fn is_overflow_check_expr(expr: &Expr) -> bool {
    use crate::ir::BinOp as B;
    // Top-level: something < 0
    if let Expr::BinOp { op: B::Lt, right, left, .. } = expr {
        let is_zero = matches!(right.as_ref(),
            Expr::Literal(crate::ir::Literal::I64(0))
            | Expr::Literal(crate::ir::Literal::I32(0))
        );
        if is_zero && contains_shr63(left) {
            return true;
        }
    }
    false
}

/// Recursively check if an expression contains `>> 63` shifts
/// (characteristic of i128 overflow detection).
fn contains_shr63(expr: &Expr) -> bool {
    use crate::ir::BinOp as B;
    match expr {
        Expr::BinOp { op: B::Shr, right, .. } => {
            matches!(right.as_ref(),
                Expr::Literal(crate::ir::Literal::I64(63))
                | Expr::Literal(crate::ir::Literal::I32(63))
            ) || contains_shr63(right)
        }
        Expr::BinOp { left, right, .. } => {
            contains_shr63(left) || contains_shr63(right)
        }
        Expr::UnOp { operand, .. } => contains_shr63(operand),
        _ => false,
    }
}

/// Check if a statement is boilerplate from the vec iteration pattern
/// (vec_len let-binding that was absorbed into the for-each/for-range header).
///
/// Only removes `len*` bindings — NOT `item*` bindings, which carry the
/// actual loop variable data used in the loop body.
fn is_vec_iteration_boilerplate(stmt: &Statement) -> bool {
    match stmt {
        Statement::Let { name, .. } => {
            name == "len" || name.starts_with("len_")
        }
        _ => false,
    }
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
        | Expr::EnumVariant { .. } | Expr::Ref(_) => true,
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
