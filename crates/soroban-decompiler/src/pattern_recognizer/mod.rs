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
//! - [`guard_analysis`] -- guard/comparison classification helpers
//! - [`error_branches`] -- error branch reconstruction for Result-returning fns
//! - [`loop_patterns`] -- loop body pattern recognition (vec iteration, ranges)
//! - [`token_fix`] -- token address void fix
//! - [`param_subst`] -- parameter pass-through substitution
//! - [`event_recognition`] -- event struct pattern matching
//! - [`storage_keys`] -- storage key resolution and tuple key synthesis

use std::collections::HashMap;

use stellar_xdr::curr::{ScSpecEntry, ScSpecFunctionV0, ScSpecTypeDef};

use crate::ir::{Expr, FunctionIR, Statement};
use crate::wasm_analysis::{AnalyzedBlock, AnalyzedModule, StackValue, TrackedHostCall};

pub mod host_calls;
pub mod val_decoding;
pub mod optimization;
mod guard_analysis;
mod error_branches;
mod loop_patterns;
mod token_fix;
mod param_subst;
mod event_recognition;
mod storage_keys;

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
        if guard_analysis::should_emit_return_expr(&ret_expr) {
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

    // Synthesize DataKey tuple keys: when storage operations use
    // `vec![&env, Symbol::new("Variant"), param]` as keys, replace with
    // `DataKey::Variant(param)` enum variants.
    statements = storage_keys::synthesize_tuple_keys(statements, all_entries);

    // Re-run CSE after hoisting: guard folding and hoisting may expose
    // duplicate bindings that were previously hidden inside nested if blocks
    // (e.g. duplicate Symbol::new("Counter") or DataKey::Counter(user)).
    statements = optimization::eliminate_common_subexprs(statements);

    // Identity binding elimination: remove `let x = y;` and replace
    // all references to x with y (including dotted paths like x.field).
    statements = optimization::eliminate_identity_bindings(statements);

    // Increment pattern: transform `let val = .get().unwrap_or(0);
    // .set(&key, &(val + 1))` into `let mut count = ...; count += 1;
    // .set(&key, &count)`.
    statements = optimization::reconstruct_increment_pattern(statements);

    // Struct field mutation: transform `let val = get(); let s = Struct { f: val.f + X };
    // set(&key, &s)` into `let mut state = get(); state.f += X; set(&key, &state)`.
    statements = optimization::reconstruct_struct_mutation(statements);

    // Split cross-contract client chains into two statements:
    // `client::new(&env, &addr).method(args)` →
    // `let client = client::new(&env, &addr); client.method(args)`
    // Must run BEFORE inline_single_use_bindings to avoid re-merging.
    statements = optimization::split_client_calls(statements);

    // Inline single-use bindings: collapse `let x = expr; x.method()`
    // into `expr.method()` when x is used only once as a receiver.
    // Note: skips `client` bindings produced by split_client_calls since
    // the client is used once — we need the inline pass to NOT merge them back.
    statements = optimization::inline_single_use_bindings(statements);

    // Normalize integer comparisons: `x < 6` → `x <= 5`, etc.
    statements = optimization::normalize_comparisons(statements);

    // Event struct recognition: transform raw `env.events().publish(args, data)`
    // into `EventStruct { field: data }.publish(&env)` when a matching event
    // spec entry exists.
    statements = event_recognition::recognize_event_structs(statements, all_entries);

    // Run DCE again after all optimization passes.
    statements = optimization::eliminate_dead_vars(statements);

    // Struct field pass-through: when a struct literal has a field of the
    // same type as a function parameter, substitute the parameter reference
    // instead of the (potentially incorrect) reconstructed value.
    statements = param_subst::substitute_param_pass_through(statements, spec, all_entries);

    // Storage key resolution: when a storage operation uses an unresolved
    // key (Default::default() or local_N), try to match it against the
    // contract's enum variants using the constructor call's constant arg.
    statements = storage_keys::resolve_storage_keys(statements, all_entries);

    // Fix void token addresses: when token::Client::new(&env, &()) appears
    // and a preceding storage-loaded struct has a "token" field, use it.
    statements = token_fix::fix_void_token_addresses(statements);

    // Re-run DCE: the substitution and key resolution passes may have
    // orphaned bindings (e.g. time_bound_1 replaced by time_bound).
    statements = optimization::eliminate_dead_vars(statements);

    // Error branch reconstruction: for Result-returning functions, detect
    // the WASM default-then-override pattern where the error branch is lost
    // during simulation. Pattern: `If { cond, then_body: [side_effects], else: [] }`
    // followed by `Return(val)` → move return into if-then, add Err return to else.
    let is_result = spec.outputs.to_option()
        .map_or(false, |t| matches!(t, ScSpecTypeDef::Result(_)));
    if is_result {
        statements = error_branches::reconstruct_error_branches(statements, all_entries);
    }

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
                    // Decode U32Val-space comparison constants. The WASM
                    // compiler generates `result < (N << 32)` for fast
                    // length checks without decoding the U32Val.
                    let cond_expr = guard_analysis::decode_val_comparison_constants(cond_expr);

                    let is_user_precondition = guard_analysis::is_user_comparison(&cond_expr);

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
                    if let Some(loop_stmt) = loop_patterns::try_recognize_loop_pattern(body, &body_stmts, ctx) {
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
