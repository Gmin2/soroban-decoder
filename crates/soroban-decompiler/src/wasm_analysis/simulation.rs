/// Stack simulation engine for WASM function analysis.
///
/// Simulates the WASM operand stack to track values flowing through
/// local variables, function calls, and memory operations.

use std::collections::HashMap;

use walrus::{FunctionId, FunctionKind, LocalFunction, LocalId, Module};
use walrus::ir::{self, BinaryOp, Instr, InstrSeqId, InstrSeqType, UnaryOp};

use crate::host_functions::HostFunction;
use super::{AnalyzedModule, AnalyzedBlock, FunctionStackAnalysis, StackValue, TrackedHostCall};
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
    memory_state: HashMap<(LocalId, i64), StackValue>,
    vec_contents: HashMap<usize, Vec<StackValue>>,
    map_contents: HashMap<usize, (Vec<String>, Vec<StackValue>)>,
    unpack_field_ids: HashMap<usize, Vec<usize>>,
    next_call_id: usize,
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

        let return_expr = state.stack.pop();
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
        if depth > 5 {
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
    fn simulate_seq(
        &self,
        func: &LocalFunction,
        seq_id: InstrSeqId,
        state: &mut SimulationState,
        depth: usize,
    ) {
        let seq = func.block(seq_id);
        for (instr, _) in &seq.instrs {
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
                Instr::GlobalGet(_) => {
                    state.stack.push(StackValue::Unknown);
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
                    self.simulate_seq(
                        func, b.seq, state, depth,
                    );
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
                    self.simulate_load(load, state);
                }
                Instr::Store(store) => {
                    self.simulate_store(store, state);
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
                Instr::Return(_)
                | Instr::Unreachable(_)
                | Instr::Br(_) => {}
                Instr::BrIf(_) | Instr::BrTable(_) => {
                    state.stack.pop();
                }
                _ => {}
            }
        }
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
        let mut child = SimulationState::new();
        child.next_call_id = state.next_call_id;

        self.analyze_function_stack_inner(
            callee_id, args, depth + 1, &mut child,
        );

        state.next_call_id = child.next_call_id;

        let inner_has_host_calls = !child.tracked.is_empty();

        // Only inline small helpers (<=4 host calls) to avoid
        // flooding the output from complex enum constructors.
        if child.tracked.len() <= 4 {
            state.blocks.extend(child.blocks);
        }
        state.tracked.extend(child.tracked);
        state.vec_contents.extend(child.vec_contents);
        state.map_contents.extend(child.map_contents);
        state.unpack_field_ids.extend(child.unpack_field_ids);
        state.memory_state.extend(child.memory_state);

        let return_expr = child.stack.pop();
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
        cons_memory: &HashMap<(LocalId, i64), StackValue>,
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
            // Type conversions propagate the inner value.
            match op {
                UnaryOp::I32WrapI64
                | UnaryOp::I64ExtendSI32
                | UnaryOp::I64ExtendUI32 => {
                    state.stack.push(operand);
                }
                _ => {
                    state.stack.push(StackValue::Unknown);
                }
            }
        }
    }

    /// Simulate a memory load instruction.
    fn simulate_load(
        &self,
        load: &ir::Load,
        state: &mut SimulationState,
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
                StackValue::Unknown
            };
        state.stack.push(result);
    }

    /// Simulate a memory store instruction.
    fn simulate_store(
        &self,
        store: &ir::Store,
        state: &mut SimulationState,
    ) {
        let val =
            state.stack.pop().unwrap_or(StackValue::Unknown);
        let addr =
            state.stack.pop().unwrap_or(StackValue::Unknown);
        if let Some((lid, base)) = decompose_address(&addr) {
            let eff = base + store.arg.offset as i64;
            state.memory_state.insert((lid, eff), val);
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
