/// Dispatcher tracing and function body analysis.
///
/// Traces through Soroban dispatcher wrapper chains to find the real
/// implementation function, and collects statistics about function bodies.

use std::collections::HashMap;

use walrus::{FunctionId, FunctionKind, LocalFunction, Module};
use walrus::ir::{self, dfs_in_order, Instr, Visitor};

use crate::host_functions::HostFunction;
use super::{AnalyzedModule, HostCallSite};

/// Internal statistics collected from a function body traversal.
#[derive(Default)]
pub(super) struct FunctionBodyStats {
    pub(super) host_calls: Vec<HostCallSite>,
    pub(super) local_call_count: usize,
    pub(super) has_branches: bool,
    pub(super) has_loops: bool,
    pub(super) instruction_count: usize,
}

/// Visitor that collects host calls, local calls, and control flow info.
struct BodyAnalyzer<'a> {
    module: &'a Module,
    host_func_map: &'a HashMap<FunctionId, &'static HostFunction>,
    host_calls: Vec<HostCallSite>,
    local_call_count: usize,
    has_branches: bool,
    has_loops: bool,
    instruction_count: usize,
}

impl<'instr> Visitor<'instr> for BodyAnalyzer<'_> {
    fn visit_instr(
        &mut self,
        _instr: &'instr Instr,
        _loc: &'instr ir::InstrLocId,
    ) {
        self.instruction_count += 1;
    }

    fn visit_call(&mut self, call: &ir::Call) {
        match &self.module.funcs.get(call.func).kind {
            FunctionKind::Import(imp) => {
                let import = self.module.imports.get(imp.import);
                if let Some(hf) = self.host_func_map.get(&call.func) {
                    self.host_calls.push(HostCallSite {
                        semantic_module: hf.module.to_string(),
                        semantic_name: hf.name.to_string(),
                        raw_module: import.module.clone(),
                        raw_field: import.name.clone(),
                    });
                } else {
                    self.host_calls.push(HostCallSite {
                        semantic_module: import.module.clone(),
                        semantic_name: import.name.clone(),
                        raw_module: import.module.clone(),
                        raw_field: import.name.clone(),
                    });
                }
            }
            FunctionKind::Local(_) => {
                self.local_call_count += 1;
            }
            FunctionKind::Uninitialized(_) => {}
        }
    }

    fn visit_if_else(&mut self, _: &ir::IfElse) {
        self.has_branches = true;
    }

    fn visit_br_if(&mut self, _: &ir::BrIf) {
        self.has_branches = true;
    }

    fn visit_loop(&mut self, _: &ir::Loop) {
        self.has_loops = true;
    }
}

impl AnalyzedModule {
    /// Trace through Soroban dispatcher wrappers to find the real implementation.
    ///
    /// Soroban exports follow a dispatcher chain:
    ///   export "fn_name" → extern wrapper → invoke_raw → real impl
    ///
    /// Each wrapper calls exactly one other local function. We follow this
    /// chain until we find a function that calls multiple local functions
    /// or calls host functions directly (indicating it's doing real work).
    pub(super) fn trace_to_impl(&self, func_id: FunctionId) -> FunctionId {
        let mut current = func_id;

        for _ in 0..5 {
            let func = self.module.funcs.get(current);
            let local_func = match &func.kind {
                FunctionKind::Local(lf) => lf,
                _ => break,
            };

            let unique_local_calls = collect_unique_local_calls(
                &self.module, local_func,
            );
            let has_host_calls = has_any_host_call(
                &self.module, &self.host_func_map, local_func,
            );

            // If this function calls host functions, it's doing real work — stop.
            if has_host_calls {
                break;
            }

            // If exactly one local call target and no host calls, it's a wrapper.
            if unique_local_calls.len() == 1 {
                current = unique_local_calls[0];
                continue;
            }

            break;
        }

        current
    }

    /// Collect detailed statistics about a function's body.
    pub(super) fn analyze_function_body(&self, func_id: FunctionId) -> FunctionBodyStats {
        let func = self.module.funcs.get(func_id);
        let local_func = match &func.kind {
            FunctionKind::Local(lf) => lf,
            _ => return FunctionBodyStats::default(),
        };

        let mut visitor = BodyAnalyzer {
            module: &self.module,
            host_func_map: &self.host_func_map,
            host_calls: Vec::new(),
            local_call_count: 0,
            has_branches: false,
            has_loops: false,
            instruction_count: 0,
        };

        dfs_in_order(&mut visitor, local_func, local_func.entry_block());

        FunctionBodyStats {
            host_calls: visitor.host_calls,
            local_call_count: visitor.local_call_count,
            has_branches: visitor.has_branches,
            has_loops: visitor.has_loops,
            instruction_count: visitor.instruction_count,
        }
    }
}

/// Collect unique local function call targets from a function body.
fn collect_unique_local_calls(
    module: &Module,
    func: &LocalFunction,
) -> Vec<FunctionId> {
    struct Collector<'a> {
        module: &'a Module,
        calls: Vec<FunctionId>,
    }

    impl<'instr> Visitor<'instr> for Collector<'_> {
        fn visit_call(&mut self, call: &ir::Call) {
            let kind = &self.module.funcs.get(call.func).kind;
            if matches!(kind, FunctionKind::Local(_))
                && !self.calls.contains(&call.func)
            {
                self.calls.push(call.func);
            }
        }
    }

    let mut collector = Collector {
        module,
        calls: Vec::new(),
    };
    dfs_in_order(&mut collector, func, func.entry_block());
    collector.calls
}

/// Check if a function body calls any host (imported) functions.
fn has_any_host_call(
    module: &Module,
    host_func_map: &HashMap<FunctionId, &'static HostFunction>,
    func: &LocalFunction,
) -> bool {
    struct Checker<'a> {
        module: &'a Module,
        host_func_map: &'a HashMap<FunctionId, &'static HostFunction>,
        found: bool,
    }

    impl<'instr> Visitor<'instr> for Checker<'_> {
        fn visit_call(&mut self, call: &ir::Call) {
            if self.found {
                return;
            }
            let kind = &self.module.funcs.get(call.func).kind;
            if let FunctionKind::Import(_) = kind {
                if self.host_func_map.contains_key(&call.func) {
                    self.found = true;
                }
            }
        }
    }

    let mut checker = Checker { module, host_func_map, found: false };
    dfs_in_order(&mut checker, func, func.entry_block());
    checker.found
}
