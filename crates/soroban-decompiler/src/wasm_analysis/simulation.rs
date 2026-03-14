/// Stack simulation engine for WASM function analysis.
///
/// Simulates the WASM operand stack to track values flowing through
/// local variables, function calls, and memory operations.

use std::collections::HashMap;

use walrus::{FunctionId, FunctionKind, LocalFunction, LocalId, Module};
use walrus::ir::{self, BinaryOp, Instr, InstrSeqId, InstrSeqType, UnaryOp};

use crate::host_functions::HostFunction;
use super::{AnalyzedModule, AnalyzedBlock, FunctionStackAnalysis, MemBase, StackValue, TrackedHostCall};
use super::helpers::{
    contains_unknown, decompose_address, merge_locals,
    try_decode_vec_elements, try_decode_map_elements, map_binop, map_unop,
};

/// Mutable state threaded through stack simulation.
///
/// Groups the many mutable references that [`AnalyzedModule::simulate_seq`]
/// needs, keeping the function signature manageable.
struct SimulationState {
    stack: Vec<StackValue>,
    tracked: Vec<TrackedHostCall>,
    blocks: Vec<AnalyzedBlock>,
    locals_state: HashMap<LocalId, StackValue>,
    memory_state: HashMap<(MemBase, i64), StackValue>,
    vec_contents: HashMap<usize, Vec<StackValue>>,
    map_contents: HashMap<usize, (Vec<String>, Vec<StackValue>)>,
    unpack_field_ids: HashMap<usize, Vec<usize>>,
    next_call_id: usize,
    /// Captured return value when `Return` instruction is hit inside a
    /// nested block. This prevents the Block drain from discarding it.
    return_value: Option<StackValue>,
}

impl SimulationState {
    /// Create an empty simulation state.
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            tracked: Vec::new(),
            blocks: Vec::new(),
            locals_state: HashMap::new(),
            memory_state: HashMap::new(),
            vec_contents: HashMap::new(),
            map_contents: HashMap::new(),
            unpack_field_ids: HashMap::new(),
            next_call_id: 0,
            return_value: None,
        }
    }

    /// Allocate a unique call-site ID.
    fn alloc_call_id(&mut self) -> usize {
        let id = self.next_call_id;
        self.next_call_id += 1;
        id
    }
}

impl AnalyzedModule {
    /// Simulate the WASM stack for a function to extract host calls
    /// and the return expression.
    ///
    /// Tracks local variable assignments so that values flowing through
    /// locals (e.g. a function parameter stored in a temp local) are
    /// resolved back to their origin. Function parameters are tagged
    /// as [`StackValue::Param`].
    pub fn analyze_function_stack(
        &self,
        func_id: FunctionId,
    ) -> FunctionStackAnalysis {
        let mut state = SimulationState::new();
        self.analyze_function_stack_inner(
            func_id, &[], 0, &mut state,
        );

        // Prefer the explicitly captured return value (from `Return`
        // instructions inside nested blocks) over whatever remains on
        // the stack, since the Block drain may have removed it.
        let return_expr = state.return_value.or_else(|| state.stack.pop());
        FunctionStackAnalysis {
            blocks: state.blocks,
            host_calls: state.tracked,
            return_expr,
            vec_contents: state.vec_contents,
            map_contents: state.map_contents,
            unpack_field_ids: state.unpack_field_ids,
            memory_state: state.memory_state,
        }
    }

    /// Inner recursive implementation with caller-supplied arg values
    /// and a depth limit to prevent unbounded recursion.
    fn analyze_function_stack_inner(
        &self,
        func_id: FunctionId,
        caller_args: &[StackValue],
        depth: usize,
        state: &mut SimulationState,
    ) {
        if depth > 9 {
            return;
        }

        let func = self.module.funcs.get(func_id);
        let local_func = match &func.kind {
            FunctionKind::Local(lf) => lf,
            _ => return,
        };

        // Pre-populate locals state: map each function arg to
        // Param(index) or to the caller-supplied value if available.
        for (i, arg_id) in local_func.args.iter().enumerate() {
            let val = caller_args
                .get(i)
                .cloned()
                .unwrap_or(StackValue::Param(i));
            state.locals_state.insert(*arg_id, val);
        }

        self.simulate_seq(
            local_func,
            local_func.entry_block(),
            state,
            depth,
        );
    }

    /// Recursively simulate the stack for one instruction sequence.
    ///
    /// Returns `Some(target_seq_id)` if the sequence ended with a `Br`
    /// targeting an ancestor block. The caller should propagate the
    /// break upward until the matching block is reached, skipping
    /// remaining instructions in intermediate blocks.
    fn simulate_seq(
        &self,
        func: &LocalFunction,
        seq_id: InstrSeqId,
        state: &mut SimulationState,
        depth: usize,
    ) -> Option<InstrSeqId> {
        let seq = func.block(seq_id);
        self.simulate_instrs(func, &seq.instrs, state, depth)
    }

    /// Simulate a slice of instructions. Factored out of `simulate_seq`
    /// so that `BrIf` handling can recurse on the remaining tail.
    fn simulate_instrs(
        &self,
        func: &LocalFunction,
        instrs: &[(Instr, ir::InstrLocId)],
        state: &mut SimulationState,
        depth: usize,
    ) -> Option<InstrSeqId> {
        let mut idx = 0;
        while idx < instrs.len() {
            let (instr, _) = &instrs[idx];
            idx += 1;
            match instr {
                Instr::Const(c) => {
                    state.stack.push(StackValue::Const(c.value));
                }
                Instr::LocalGet(lg) => {
                    let val = state
                        .locals_state
                        .get(&lg.local)
                        .cloned()
                        .unwrap_or(StackValue::Local(lg.local));
                    state.stack.push(val);
                }
                Instr::LocalSet(ls) => {
                    if let Some(val) = state.stack.pop() {
                        if contains_unknown(&val) {
                            state.locals_state.remove(&ls.local);
                        } else {
                            state.locals_state.insert(ls.local, val);
                        }
                    }
                }
                Instr::LocalTee(lt) => {
                    if let Some(val) = state.stack.last() {
                        if contains_unknown(val) {
                            state.locals_state.remove(&lt.local);
                        } else {
                            state.locals_state.insert(
                                lt.local,
                                val.clone(),
                            );
                        }
                    }
                }
                Instr::GlobalGet(gg) => {
                    state.stack.push(StackValue::Global(gg.global));
                }
                Instr::GlobalSet(_) => {
                    state.stack.pop();
                }
                Instr::Call(call) => {
                    self.simulate_call(
                        func, call, state, depth,
                    );
                }
                Instr::Block(b) => {
                    let pre_len = state.stack.len();
                    let br_target = self.simulate_seq(
                        func, b.seq, state, depth,
                    );
                    // Enforce the block's declared result type.
                    let result_count = seq_result_count(
                        &self.module, func.block(b.seq),
                    );
                    let expected = pre_len + result_count;
                    if state.stack.len() > expected {
                        // Before draining, capture the top-of-stack as a
                        // potential return value. This handles functions
                        // that leave a value on the stack without an
                        // explicit Return instruction.
                        if state.return_value.is_none() {
                            state.return_value = state.stack.last().cloned();
                        }
                        let excess = state.stack.len() - expected;
                        state.stack.drain(pre_len..pre_len + excess);
                    }
                    // If a `br` targeted this block, the break is consumed.
                    // If it targeted an ancestor, propagate upward.
                    if let Some(target) = br_target {
                        if target != b.seq {
                            return Some(target);
                        }
                        // Break targets this block — continue with
                        // the instructions after the block normally.
                    }
                }
                Instr::Loop(l) => {
                    self.simulate_loop(func, l, state, depth);
                }
                Instr::IfElse(ie) => {
                    self.simulate_if_else(
                        func, ie, state, depth,
                    );
                }
                Instr::Drop(_) => {
                    state.stack.pop();
                }
                Instr::Select(_) => {
                    self.simulate_select(state);
                }
                Instr::Binop(b) => {
                    self.simulate_binop(&b.op, state);
                }
                Instr::Unop(u) => {
                    self.simulate_unop(&u.op, state);
                }
                Instr::Load(load) => {
                    self.simulate_load(load, state, depth);
                }
                Instr::Store(store) => {
                    self.simulate_store(store, state, depth);
                }
                Instr::MemorySize(_) => {
                    state.stack.push(StackValue::Unknown);
                }
                Instr::MemoryCopy(_) | Instr::MemoryFill(_) => {
                    // Memory bulk ops — pop args but don't track.
                    state.stack.pop();
                    state.stack.pop();
                    state.stack.pop();
                }
                Instr::MemoryGrow(_) => {
                    state.stack.pop();
                    state.stack.push(StackValue::Unknown);
                }
                Instr::Return(_) => {
                    // Capture the return value before breaking so that
                    // the Block drain cannot discard it.
                    if state.return_value.is_none() {
                        state.return_value = state.stack.last().cloned();
                    }
                    break;
                }
                Instr::Unreachable(_) => {
                    break;
                }
                Instr::Br(br) => {
                    // Signal the break target to the caller so that
                    // intermediate blocks skip their remaining code.
                    return Some(br.block);
                }
                Instr::BrIf(_br) => {
                    let condition = state.stack.pop();
                    let remaining = &instrs[idx..];

                    // Check if the remaining instructions contain any
                    // host calls or meaningful control flow. If so,
                    // model the br_if as an AnalyzedBlock::If where
                    // the else-block is the continuation (condition
                    // false / branch not taken) and the then-block is
                    // empty (condition true / branch taken = exit).
                    if remaining_has_calls(remaining) {
                        // Save the "taken" path state (condition true,
                        // branch exits to target block).
                        let taken_stack = state.stack.clone();
                        let taken_locals = state.locals_state.clone();
                        let taken_memory = state.memory_state.clone();

                        // Simulate the continuation (branch NOT taken)
                        // in the current state.
                        let saved_blocks =
                            std::mem::take(&mut state.blocks);
                        let cont_br = self.simulate_instrs(
                            func, remaining, state, depth,
                        );
                        let cont_blocks = std::mem::replace(
                            &mut state.blocks,
                            saved_blocks,
                        );

                        // Check if continuation ends in unreachable/br
                        let cont_ends_unreachable =
                            remaining_ends_unreachable(remaining);

                        if !cont_blocks.is_empty() {
                            // The condition in br_if means "if true,
                            // branch away". The continuation runs when
                            // condition is false. Emit:
                            // `if cond { /*taken: exit block*/ }
                            //  else { continuation }`
                            state.blocks.push(AnalyzedBlock::If {
                                condition,
                                then_block: vec![],
                                else_block: cont_blocks,
                                alt_unreachable: cont_ends_unreachable,
                            });
                        }

                        // After the enclosing block, both the "taken"
                        // path and the continuation converge. Choose
                        // the best state for subsequent instructions.
                        if cont_ends_unreachable || cont_br.is_some() {
                            // Continuation doesn't fall through — use
                            // the taken path's state exclusively.
                            state.stack = taken_stack;
                            state.locals_state = taken_locals;
                            state.memory_state = taken_memory;
                        } else {
                            // Both paths converge. Keep the
                            // continuation's locals as-is rather than
                            // merging, since the continuation is the
                            // "body" of the conditional (the happy
                            // path with storage ops, computations,
                            // etc.) and provides more useful bindings
                            // for downstream resolution. The "taken"
                            // path merely exits the block early.
                            state.memory_state.extend(taken_memory);
                        }

                        // All remaining instructions have been
                        // consumed by the continuation simulation.
                        // If the continuation ended with a br to an
                        // outer block, propagate it so that enclosing
                        // blocks skip their remaining code (e.g.
                        // switch-case with br to merge point).
                        if let Some(target) = cont_br {
                            return Some(target);
                        }
                        break;
                    }
                    // No meaningful content after br_if — fall through
                    // as before (just pop the condition).
                }
                Instr::BrTable(bt) => {
                    let disc = state.stack.pop();
                    // If the discriminant is a known constant, resolve
                    // the branch target and propagate as a Br.
                    // This enables correct enum variant selection when
                    // the discriminant is passed as a constant arg.
                    if let Some(idx) = disc.as_ref().and_then(|d| {
                        match d {
                            StackValue::Const(ir::Value::I32(n)) => {
                                Some(*n as usize)
                            }
                            StackValue::Const(ir::Value::I64(n)) => {
                                Some(*n as usize)
                            }
                            _ => None,
                        }
                    }) {
                        let target = bt.blocks
                            .get(idx)
                            .copied()
                            .unwrap_or(bt.default);
                        return Some(target);
                    }
                    // Unknown discriminant — fall through (no jump).
                }
                _ => {}
            }
        }
        None
    }

    /// Simulate a function call instruction.
    fn simulate_call(
        &self,
        func: &LocalFunction,
        call: &ir::Call,
        state: &mut SimulationState,
        depth: usize,
    ) {
        let callee = self.module.funcs.get(call.func);
        let ty = self.module.types.get(callee.ty());
        let param_count = ty.params().len();
        let result_count = ty.results().len();

        let args = if state.stack.len() >= param_count {
            let split = state.stack.len() - param_count;
            state.stack.split_off(split)
        } else {
            state.stack.clear();
            vec![StackValue::Unknown; param_count]
        };

        if let Some(hf) = self.host_func_map.get(&call.func) {
            self.simulate_host_call(
                hf, call.func, &args, result_count, state,
            );
        } else {
            self.simulate_local_call(
                func, call.func, &args,
                result_count, depth, state,
            );
        }
    }

    /// Record a direct host function call and decode any memory
    /// side-effects (vec/map construction, unpacking).
    fn simulate_host_call(
        &self,
        hf: &'static HostFunction,
        func_id: FunctionId,
        args: &[StackValue],
        result_count: usize,
        state: &mut SimulationState,
    ) {
        let id = state.alloc_call_id();

        // Decode vec contents for vec_new_from_linear_memory.
        if hf.name == "vec_new_from_linear_memory" {
            if let Some(elems) = try_decode_vec_elements(
                args, &state.memory_state,
            ) {
                if std::env::var("DECOMPILER_DEBUG_VEC").is_ok() {
                    eprintln!("[VEC id={}] {} elements:", id, elems.len());
                    for (i, el) in elems.iter().enumerate() {
                        eprintln!("  [{}] {:?}", i, el);
                    }
                }
                state.vec_contents.insert(id, elems);
            }
        }

        // Decode map contents for map_new_from_linear_memory.
        if hf.name == "map_new_from_linear_memory" {
            if let Some((keys, vals)) = try_decode_map_elements(
                args, &state.memory_state, self,
            ) {
                state.map_contents.insert(id, (keys, vals));
            }
        }

        // Model unpack-to-linear-memory writes.
        self.model_unpack_writes(
            hf.name, args, id, state,
        );

        let tc = TrackedHostCall {
            host_func: hf,
            func_id,
            call_site_id: id,
            args: args.to_vec(),
        };
        state.blocks.push(AnalyzedBlock::HostCall(TrackedHostCall {
            host_func: tc.host_func,
            func_id: tc.func_id,
            call_site_id: tc.call_site_id,
            args: tc.args.clone(),
        }));
        state.tracked.push(tc);
        for _ in 0..result_count {
            state.stack.push(StackValue::CallResult(id));
        }
    }

    /// Model host memory writes for map/vec unpack operations.
    ///
    /// These host functions write tagged Val entries into a caller-
    /// provided buffer. We record synthetic `CallResult` IDs in
    /// `memory_state` so downstream loads can resolve them.
    fn model_unpack_writes(
        &self,
        name: &str,
        args: &[StackValue],
        call_id: usize,
        state: &mut SimulationState,
    ) {
        // map_unpack: args = [map, keys_pos, vals_pos, len]
        // vec_unpack: args = [vec, vals_pos, len]
        let (ptr_idx, len_idx) = match name {
            "map_unpack_to_linear_memory" => (2, 3),
            "vec_unpack_to_linear_memory" => (1, 2),
            _ => return,
        };

        let Some(ptr_raw) = args.get(ptr_idx) else {
            return;
        };
        let stripped = crate::pattern_recognizer::strip_val_boilerplate(
            ptr_raw,
        );
        let Some((base_local, base_offset)) =
            decompose_address(&stripped)
        else {
            return;
        };

        let len = args
            .get(len_idx)
            .and_then(|a| {
                crate::pattern_recognizer::extract_u32_val(a)
            })
            .unwrap_or(0);

        let mut field_ids = Vec::new();
        for i in 0..len {
            let offset = base_offset + (i as i64) * 8;
            let field_id = state.alloc_call_id();
            state.memory_state.insert(
                (base_local, offset),
                StackValue::CallResult(field_id),
            );
            field_ids.push(field_id);
        }
        state.unpack_field_ids.insert(call_id, field_ids);
    }

    /// Recursively trace into a local function call, merging its
    /// results back into the caller's simulation state.
    fn simulate_local_call(
        &self,
        _func: &LocalFunction,
        callee_id: FunctionId,
        args: &[StackValue],
        result_count: usize,
        depth: usize,
        state: &mut SimulationState,
    ) {
        // Build a child SimulationState for the callee.
        // Inherit the parent's memory_state so the callee can read
        // values that the caller stored to the linear memory frame.
        let mut child = SimulationState::new();
        child.next_call_id = state.next_call_id;
        child.memory_state = state.memory_state.clone();

        self.analyze_function_stack_inner(
            callee_id, args, depth + 1, &mut child,
        );

        state.next_call_id = child.next_call_id;

        let inner_has_host_calls = !child.tracked.is_empty();

        // Inline helper functions up to a reasonable limit to
        // capture token transfers, storage ops, etc.
        if child.tracked.len() <= 16 {
            state.blocks.extend(child.blocks);
        }
        state.tracked.extend(child.tracked);
        state.vec_contents.extend(child.vec_contents);
        state.map_contents.extend(child.map_contents);
        state.unpack_field_ids.extend(child.unpack_field_ids);
        state.memory_state.extend(child.memory_state);

        let return_expr = child.return_value.or_else(|| child.stack.pop());
        let result_val = self.resolve_local_call_result(
            args,
            return_expr,
            inner_has_host_calls,
            result_count,
            state,
        );
        for _ in 0..result_count {
            state.stack.push(result_val.clone());
        }
    }

    /// Determine the result value from a local function call.
    ///
    /// Prefers the callee's return expression, then tries a pass-through
    /// heuristic for simple wrappers, and falls back to a fresh
    /// `CallResult`.
    fn resolve_local_call_result(
        &self,
        args: &[StackValue],
        return_expr: Option<StackValue>,
        has_host_calls: bool,
        result_count: usize,
        state: &mut SimulationState,
    ) -> StackValue {
        if result_count != 1 {
            return StackValue::CallResult(state.alloc_call_id());
        }

        // Prefer the callee's return expression.
        if let Some(ret) = return_expr {
            return ret;
        }

        // No return expr and no host calls: try pass-through heuristic.
        if !has_host_calls {
            let non_env: Vec<_> = args
                .iter()
                .filter(|a| {
                    matches!(a, StackValue::Param(i) if *i != 0)
                })
                .collect();
            if non_env.len() == 1 {
                return non_env[0].clone();
            }
            if args.len() == 1 {
                if let StackValue::Param(idx) = &args[0] {
                    return StackValue::Param(*idx);
                }
            }
        }

        StackValue::CallResult(state.alloc_call_id())
    }

    /// Simulate a loop instruction.
    fn simulate_loop(
        &self,
        func: &LocalFunction,
        l: &ir::Loop,
        state: &mut SimulationState,
        depth: usize,
    ) {
        let saved_blocks = std::mem::take(&mut state.blocks);
        self.simulate_seq(func, l.seq, state, depth);
        let loop_blocks = std::mem::replace(
            &mut state.blocks,
            saved_blocks,
        );

        let has_back_edge = seq_has_back_edge(func, l.seq);
        if !loop_blocks.is_empty() {
            state.blocks.push(AnalyzedBlock::Loop {
                body: loop_blocks,
                has_back_edge,
            });
        }
    }

    /// Simulate an if/else instruction, merging branch states.
    fn simulate_if_else(
        &self,
        func: &LocalFunction,
        ie: &ir::IfElse,
        state: &mut SimulationState,
        depth: usize,
    ) {
        let condition = state.stack.pop();

        let saved_stack = state.stack.clone();
        let saved_locals = state.locals_state.clone();
        let saved_memory = state.memory_state.clone();

        // Simulate consequent branch.
        let saved_blocks = std::mem::take(&mut state.blocks);
        self.simulate_seq(func, ie.consequent, state, depth);
        let then_blocks = std::mem::replace(
            &mut state.blocks,
            saved_blocks,
        );
        let cons_unreachable =
            seq_ends_unreachable(func, ie.consequent);
        let cons_memory = state.memory_state.clone();

        // Simulate alternative branch with saved state.
        state.memory_state = saved_memory;
        let mut alt_stack = saved_stack;
        let mut alt_locals = saved_locals;

        let saved_blocks = std::mem::take(&mut state.blocks);
        let orig_stack = std::mem::replace(
            &mut state.stack,
            alt_stack,
        );
        let orig_locals = std::mem::replace(
            &mut state.locals_state,
            alt_locals,
        );
        self.simulate_seq(func, ie.alternative, state, depth);
        let else_blocks = std::mem::replace(
            &mut state.blocks,
            saved_blocks,
        );
        alt_stack = std::mem::replace(&mut state.stack, orig_stack);
        alt_locals = std::mem::replace(
            &mut state.locals_state,
            orig_locals,
        );
        let alt_unreachable =
            seq_ends_unreachable(func, ie.alternative);

        // Emit If block if at least one branch has content.
        if !then_blocks.is_empty() || !else_blocks.is_empty() {
            state.blocks.push(AnalyzedBlock::If {
                condition,
                then_block: then_blocks,
                else_block: else_blocks,
                alt_unreachable,
            });
        }

        // Merge branch states.
        self.merge_branch_states(
            &alt_stack,
            &alt_locals,
            &cons_memory,
            cons_unreachable,
            alt_unreachable,
            func,
            ie,
            state,
        );
    }

    /// Merge locals, stack, and memory after an if/else branch.
    fn merge_branch_states(
        &self,
        alt_stack: &[StackValue],
        alt_locals: &HashMap<LocalId, StackValue>,
        cons_memory: &HashMap<(MemBase, i64), StackValue>,
        cons_unreachable: bool,
        alt_unreachable: bool,
        func: &LocalFunction,
        ie: &ir::IfElse,
        state: &mut SimulationState,
    ) {
        if cons_unreachable && !alt_unreachable {
            // Consequent traps — use alternative state.
            state.stack = alt_stack.to_vec();
            state.locals_state = alt_locals.clone();
        } else if alt_unreachable && !cons_unreachable {
            // Alternative traps — consequent state is already live.
            state.memory_state.extend(cons_memory.clone());
        } else {
            // Both branches live — merge conservatively.
            state.memory_state.extend(cons_memory.clone());

            let result_count = seq_result_count(
                &self.module,
                func.block(ie.consequent),
            );
            let new_len =
                state.stack.len().saturating_sub(result_count);
            state.stack.truncate(new_len);
            for _ in 0..result_count {
                state.stack.push(StackValue::Unknown);
            }

            merge_locals(
                &mut state.locals_state,
                alt_locals,
            );
        }
    }

    /// Simulate a `select` instruction.
    fn simulate_select(&self, state: &mut SimulationState) {
        state.stack.pop(); // condition
        let val_false =
            state.stack.pop().unwrap_or(StackValue::Unknown);
        let val_true =
            state.stack.pop().unwrap_or(StackValue::Unknown);
        let result = if matches!(val_true, StackValue::Unknown) {
            val_false
        } else {
            val_true
        };
        state.stack.push(result);
    }

    /// Simulate a binary operation.
    fn simulate_binop(
        &self,
        op: &BinaryOp,
        state: &mut SimulationState,
    ) {
        let right =
            state.stack.pop().unwrap_or(StackValue::Unknown);
        let left =
            state.stack.pop().unwrap_or(StackValue::Unknown);

        // Constant folding: evaluate i32 ops at simulation time.
        // This enables br_table to resolve when the discriminant
        // is a constant masked by i32.and (e.g. `disc & 0xFF`).
        if let (
            StackValue::Const(ir::Value::I32(l)),
            StackValue::Const(ir::Value::I32(r)),
        ) = (&left, &right)
        {
            let folded = match op {
                BinaryOp::I32Add => Some(l.wrapping_add(*r)),
                BinaryOp::I32Sub => Some(l.wrapping_sub(*r)),
                BinaryOp::I32Mul => Some(l.wrapping_mul(*r)),
                BinaryOp::I32And => Some(l & r),
                BinaryOp::I32Or => Some(l | r),
                BinaryOp::I32Xor => Some(l ^ r),
                BinaryOp::I32Shl => Some(l.wrapping_shl(*r as u32)),
                BinaryOp::I32ShrU => Some((*l as u32).wrapping_shr(*r as u32) as i32),
                BinaryOp::I32ShrS => Some(l.wrapping_shr(*r as u32)),
                _ => None,
            };
            if let Some(v) = folded {
                state.stack.push(StackValue::Const(ir::Value::I32(v)));
                return;
            }
        }

        // Constant folding: evaluate i64 ops at simulation time.
        // This enables SymbolSmall and other tagged Val constants
        // constructed via bit manipulation (e.g. `(chars << 8) | 14`)
        // to be folded into a single Const that try_decode_val can decode.
        if let (
            StackValue::Const(ir::Value::I64(l)),
            StackValue::Const(ir::Value::I64(r)),
        ) = (&left, &right)
        {
            let folded = match op {
                BinaryOp::I64Add => Some(l.wrapping_add(*r)),
                BinaryOp::I64Sub => Some(l.wrapping_sub(*r)),
                BinaryOp::I64Mul => Some(l.wrapping_mul(*r)),
                BinaryOp::I64And => Some(l & r),
                BinaryOp::I64Or => Some(l | r),
                BinaryOp::I64Xor => Some(l ^ r),
                BinaryOp::I64Shl => Some(l.wrapping_shl(*r as u32)),
                BinaryOp::I64ShrU => Some((*l as u64).wrapping_shr(*r as u32) as i64),
                BinaryOp::I64ShrS => Some(l.wrapping_shr(*r as u32)),
                _ => None,
            };
            if let Some(v) = folded {
                state.stack.push(StackValue::Const(ir::Value::I64(v)));
                return;
            }
        }

        // Mixed constant folding: i32/i64 pairs from type conversions.
        // The WASM compiler sometimes mixes i32 and i64 constants via
        // extend/wrap operations. Handle the common case where one
        // operand is i32 and the other is i64 by promoting to i64.
        let mixed_i64 = match (&left, &right) {
            (StackValue::Const(ir::Value::I32(l)), StackValue::Const(ir::Value::I64(r))) => {
                Some((*l as i64, *r))
            }
            (StackValue::Const(ir::Value::I64(l)), StackValue::Const(ir::Value::I32(r))) => {
                Some((*l, *r as i64))
            }
            _ => None,
        };
        if let Some((l, r)) = mixed_i64 {
            let folded = match op {
                BinaryOp::I64Add => Some(l.wrapping_add(r)),
                BinaryOp::I64Sub => Some(l.wrapping_sub(r)),
                BinaryOp::I64Mul => Some(l.wrapping_mul(r)),
                BinaryOp::I64And => Some(l & r),
                BinaryOp::I64Or => Some(l | r),
                BinaryOp::I64Xor => Some(l ^ r),
                BinaryOp::I64Shl => Some(l.wrapping_shl(r as u32)),
                BinaryOp::I64ShrU => Some((l as u64).wrapping_shr(r as u32) as i64),
                BinaryOp::I64ShrS => Some(l.wrapping_shr(r as u32)),
                _ => None,
            };
            if let Some(v) = folded {
                state.stack.push(StackValue::Const(ir::Value::I64(v)));
                return;
            }
        }

        if let Some(ir_op) = map_binop(op) {
            state.stack.push(StackValue::BinOp {
                op: ir_op,
                left: Box::new(left),
                right: Box::new(right),
            });
        } else {
            state.stack.push(StackValue::Unknown);
        }
    }

    /// Simulate a unary operation.
    fn simulate_unop(
        &self,
        op: &UnaryOp,
        state: &mut SimulationState,
    ) {
        let operand =
            state.stack.pop().unwrap_or(StackValue::Unknown);
        if let Some(ir_op) = map_unop(op) {
            state.stack.push(StackValue::UnOp {
                op: ir_op,
                operand: Box::new(operand),
            });
        } else {
            // Type conversions: fold constants to the target type,
            // otherwise propagate the inner value transparently.
            match op {
                UnaryOp::I32WrapI64 => {
                    if let StackValue::Const(ir::Value::I64(v)) = &operand {
                        state.stack.push(StackValue::Const(ir::Value::I32(*v as i32)));
                    } else {
                        state.stack.push(operand);
                    }
                }
                UnaryOp::I64ExtendSI32 => {
                    if let StackValue::Const(ir::Value::I32(v)) = &operand {
                        state.stack.push(StackValue::Const(ir::Value::I64(*v as i64)));
                    } else {
                        state.stack.push(operand);
                    }
                }
                UnaryOp::I64ExtendUI32 => {
                    if let StackValue::Const(ir::Value::I32(v)) = &operand {
                        state.stack.push(StackValue::Const(ir::Value::I64(*v as u32 as i64)));
                    } else {
                        state.stack.push(operand);
                    }
                }
                _ => {
                    state.stack.push(StackValue::Unknown);
                }
            }
        }
    }

    /// Simulate a memory load instruction.
    ///
    /// First tries resolving from tracked memory stores (memory_state).
    /// Falls back to reading constant values from the WASM data section
    /// when the address is a compile-time constant — this handles patterns
    /// like loading SymbolSmall constants embedded in the data section
    /// (e.g. event topic symbols loaded via `i64.load` from a static address).
    fn simulate_load(
        &self,
        load: &ir::Load,
        state: &mut SimulationState,
        _depth: usize,
    ) {
        let addr =
            state.stack.pop().unwrap_or(StackValue::Unknown);
        let result =
            if let Some((lid, base)) = decompose_address(&addr) {
                let eff = base + load.arg.offset as i64;
                state
                    .memory_state
                    .get(&(lid, eff))
                    .cloned()
                    .unwrap_or(StackValue::Unknown)
            } else {
                // Try to evaluate the address as a constant for data section reads.
                self.try_load_from_data_section(&addr, load)
                    .unwrap_or(StackValue::Unknown)
            };
        state.stack.push(result);
    }

    /// Try to load a value from the WASM data section at a constant address.
    ///
    /// When the WASM code loads from a compile-time constant address (e.g.
    /// `i32.const 1048576; i64.load`), this reads the bytes from the data
    /// section and returns the appropriate `StackValue::Const`.
    fn try_load_from_data_section(
        &self,
        addr: &StackValue,
        load: &ir::Load,
    ) -> Option<StackValue> {
        // Evaluate the address to a constant.
        let base_addr = match addr {
            StackValue::Const(ir::Value::I32(v)) => *v as u64,
            StackValue::Const(ir::Value::I64(v)) => *v as u64,
            _ => return None,
        };
        let eff_addr = base_addr + load.arg.offset as u64;

        // Determine load size from the kind.
        let load_size = load.kind.width();

        // Read bytes from the data section.
        let bytes = self.read_linear_memory(eff_addr as u32, load_size as u32)?;

        // Convert to the appropriate StackValue based on load kind.
        match load.kind {
            ir::LoadKind::I64 { .. } => {
                if bytes.len() == 8 {
                    let val = i64::from_le_bytes(bytes.try_into().ok()?);
                    Some(StackValue::Const(ir::Value::I64(val)))
                } else {
                    None
                }
            }
            ir::LoadKind::I32 { .. } => {
                if bytes.len() == 4 {
                    let val = i32::from_le_bytes(bytes.try_into().ok()?);
                    Some(StackValue::Const(ir::Value::I32(val)))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Simulate a memory store instruction.
    fn simulate_store(
        &self,
        store: &ir::Store,
        state: &mut SimulationState,
        _depth: usize,
    ) {
        let val =
            state.stack.pop().unwrap_or(StackValue::Unknown);
        let addr =
            state.stack.pop().unwrap_or(StackValue::Unknown);
        if let Some((base_id, base)) = decompose_address(&addr) {
            let eff = base + store.arg.offset as i64;
            state.memory_state.insert((base_id, eff), val);
        }
    }
}

/// How many result values an InstrSeq produces.
fn seq_result_count(module: &Module, seq: &ir::InstrSeq) -> usize {
    match seq.ty {
        InstrSeqType::Simple(None) => 0,
        InstrSeqType::Simple(Some(_)) => 1,
        InstrSeqType::MultiValue(ty) => module.types.get(ty).results().len(),
    }
}

/// Check if a sequence ends with `Unreachable` (trap/panic path).
fn seq_ends_unreachable(
    func: &LocalFunction,
    seq_id: InstrSeqId,
) -> bool {
    let seq = func.block(seq_id);
    seq.instrs
        .last()
        .map_or(false, |(i, _)| matches!(i, Instr::Unreachable(_)))
}

/// Check if a slice of remaining instructions contains any function calls
/// (host or local). Used by `BrIf` handling to decide whether to model
/// the conditional branch as an `AnalyzedBlock::If`.
fn remaining_has_calls(instrs: &[(Instr, ir::InstrLocId)]) -> bool {
    for (instr, _) in instrs {
        match instr {
            Instr::Call(_) => return true,
            Instr::Block(b) => {
                // We can't easily inspect the block's seq here without
                // the func reference, but calls inside blocks are common.
                // Conservatively return true for non-empty blocks.
                let _ = b;
            }
            Instr::IfElse(_) => return true,
            Instr::Loop(_) => return true,
            _ => {}
        }
    }
    false
}

/// Check if a slice of instructions ends in `Unreachable`.
fn remaining_ends_unreachable(instrs: &[(Instr, ir::InstrLocId)]) -> bool {
    instrs
        .last()
        .map_or(false, |(i, _)| matches!(i, Instr::Unreachable(_)))
}

/// Check if a loop body contains a br or br_if that targets the loop itself.
///
/// In WASM, `loop` creates a label at the *beginning* of its body. A `br` or
/// `br_if` targeting that label is a back-edge (continues the loop). If no
/// back-edge exists, the loop is a compiler artifact and should be flattened.
fn seq_has_back_edge(
    func: &LocalFunction,
    loop_seq_id: InstrSeqId,
) -> bool {
    fn check_seq(
        func: &LocalFunction,
        seq_id: InstrSeqId,
        target: InstrSeqId,
    ) -> bool {
        let seq = func.block(seq_id);
        for (instr, _) in &seq.instrs {
            match instr {
                Instr::Br(br) if br.block == target => return true,
                Instr::BrIf(br) if br.block == target => return true,
                Instr::Block(b) => {
                    if check_seq(func, b.seq, target) { return true; }
                }
                Instr::Loop(l) => {
                    if check_seq(func, l.seq, target) { return true; }
                }
                Instr::IfElse(ie) => {
                    if check_seq(func, ie.consequent, target) { return true; }
                    if check_seq(func, ie.alternative, target) { return true; }
                }
                _ => {}
            }
        }
        false
    }
    check_seq(func, loop_seq_id, loop_seq_id)
}
