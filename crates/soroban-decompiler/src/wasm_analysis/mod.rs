/// WASM module analysis for Soroban contract decompilation.
///
/// Parses a WASM binary with walrus, resolves host function imports,
/// traces through Soroban dispatcher chains to find implementation functions,
/// and extracts structured analysis of each contract function's body.

use std::collections::HashMap;

use anyhow::{Context, Result};
use walrus::{ExportItem, FunctionId, LocalId, Module};
use walrus::ir;

use crate::host_functions::{self, HostFunction};

mod simulation;
mod analysis;
mod helpers;

/// Analyzed WASM module with resolved host function mappings.
pub struct AnalyzedModule {
    pub(super) module: Module,
    /// Maps imported FunctionId → resolved HostFunction.
    pub(super) host_func_map: HashMap<FunctionId, &'static HostFunction>,
}

/// Analysis results for a single exported contract function.
#[derive(Debug)]
pub struct FunctionAnalysis {
    pub export_name: String,
    pub export_func_id: FunctionId,
    pub impl_func_id: FunctionId,
    pub host_calls: Vec<HostCallSite>,
    pub local_call_count: usize,
    pub has_branches: bool,
    pub has_loops: bool,
    pub instruction_count: usize,
}

/// A resolved host function call found in a function body.
#[derive(Debug, Clone)]
pub struct HostCallSite {
    pub semantic_module: String,
    pub semantic_name: String,
    pub raw_module: String,
    pub raw_field: String,
}

/// An abstract value tracked during stack simulation.
#[derive(Debug, Clone)]
pub enum StackValue {
    /// A constant (i32, i64, f32, f64).
    Const(ir::Value),
    /// A function parameter by index (0-based, excludes implicit env).
    Param(usize),
    /// A local variable we couldn't resolve further.
    Local(LocalId),
    /// Return value from a function call, identified by unique call-site ID.
    CallResult(usize),
    /// A binary operation on two tracked values.
    BinOp {
        op: crate::ir::BinOp,
        left: Box<StackValue>,
        right: Box<StackValue>,
    },
    /// A unary operation on a tracked value.
    UnOp {
        op: crate::ir::UnOp,
        operand: Box<StackValue>,
    },
    /// Value we can't statically determine.
    Unknown,
}

/// A host function call with its resolved arguments from stack simulation.
#[derive(Debug)]
pub struct TrackedHostCall {
    pub host_func: &'static HostFunction,
    pub func_id: FunctionId,
    /// Unique identifier for this call site (distinguishes multiple calls
    /// to the same host function).
    pub call_site_id: usize,
    pub args: Vec<StackValue>,
}

/// A block in the analyzed function body, preserving control flow structure.
#[derive(Debug)]
pub enum AnalyzedBlock {
    /// A host function call.
    HostCall(TrackedHostCall),
    /// An if/else block.
    If {
        condition: Option<StackValue>,
        then_block: Vec<AnalyzedBlock>,
        else_block: Vec<AnalyzedBlock>,
    },
    /// A loop block.
    Loop {
        body: Vec<AnalyzedBlock>,
        /// True if the loop contains a br/br_if targeting itself (real loop).
        /// False means it's a compiler artifact and should be flattened.
        has_back_edge: bool,
    },
}

/// Complete result of stack-simulating a function body.
#[derive(Debug)]
pub struct FunctionStackAnalysis {
    /// Analyzed blocks preserving control flow structure.
    pub blocks: Vec<AnalyzedBlock>,

    /// Flat list of all host function calls (for call_result_names
    /// mapping).
    pub host_calls: Vec<TrackedHostCall>,

    /// The value left on the stack at function exit (the return value).
    pub return_expr: Option<StackValue>,

    /// Decoded vec contents from `vec_new_from_linear_memory` calls.
    /// Maps call_site_id to a list of element [`StackValue`]s.
    pub vec_contents: HashMap<usize, Vec<StackValue>>,

    /// Decoded map contents from `map_new_from_linear_memory` calls.
    /// Maps call_site_id to (keys, values).
    pub map_contents: HashMap<usize, (Vec<String>, Vec<StackValue>)>,

    /// Field IDs from unpack-to-linear-memory calls.
    /// Maps the unpack call_site_id to synthetic field CallResult IDs.
    pub unpack_field_ids: HashMap<usize, Vec<usize>>,

    /// Memory state: maps `(LocalId, offset)` to [`StackValue`] for
    /// stores through pointers. Propagated from callees so that caller
    /// loads can resolve callee-written values.
    pub memory_state: HashMap<(LocalId, i64), StackValue>,
}

impl AnalyzedModule {
    /// Parse a WASM binary and build host function mappings.
    pub fn from_wasm(wasm: &[u8]) -> Result<Self> {
        let module = Module::from_buffer(wasm)
            .context("failed to parse WASM with walrus")?;
        let host_func_map = build_host_func_map(&module);
        Ok(Self { module, host_func_map })
    }

    /// Get a reference to the underlying walrus module.
    pub fn module(&self) -> &Module {
        &self.module
    }

    /// Analyze a single exported function by name.
    pub fn analyze_export(&self, name: &str) -> Result<FunctionAnalysis> {
        let export_func_id = self.module.exports.get_func(name)
            .with_context(|| format!("no export named '{name}'"))?;
        let impl_func_id = self.trace_to_impl(export_func_id);
        let stats = self.analyze_function_body(impl_func_id);

        Ok(FunctionAnalysis {
            export_name: name.to_string(),
            export_func_id,
            impl_func_id,
            host_calls: stats.host_calls,
            local_call_count: stats.local_call_count,
            has_branches: stats.has_branches,
            has_loops: stats.has_loops,
            instruction_count: stats.instruction_count,
        })
    }

    /// Analyze all function exports in the module.
    pub fn analyze_all_exports(&self) -> Vec<FunctionAnalysis> {
        let exports: Vec<(String, FunctionId)> = self.module.exports.iter()
            .filter_map(|e| match e.item {
                ExportItem::Function(fid) => Some((e.name.clone(), fid)),
                _ => None,
            })
            .collect();

        exports.into_iter().filter_map(|(name, fid)| {
            let impl_func_id = self.trace_to_impl(fid);
            let stats = self.analyze_function_body(impl_func_id);
            Some(FunctionAnalysis {
                export_name: name,
                export_func_id: fid,
                impl_func_id,
                host_calls: stats.host_calls,
                local_call_count: stats.local_call_count,
                has_branches: stats.has_branches,
                has_loops: stats.has_loops,
                instruction_count: stats.instruction_count,
            })
        }).collect()
    }

    /// Look up whether a FunctionId is a known Soroban host function.
    pub fn get_host_func(&self, func_id: FunctionId) -> Option<&'static HostFunction> {
        self.host_func_map.get(&func_id).copied()
    }

    /// Get the number of WASM-level parameters for a function.
    pub fn wasm_param_count(&self, func_id: FunctionId) -> usize {
        let func = self.module.funcs.get(func_id);
        let ty = self.module.types.get(func.ty());
        ty.params().len()
    }

    /// Read bytes from the WASM data section at a given linear memory address.
    ///
    /// Soroban contracts embed string/symbol literals in the WASM data section.
    /// Host calls like `symbol_new_from_linear_memory(ptr, len)` reference these.
    pub fn read_linear_memory(&self, offset: u32, len: u32) -> Option<Vec<u8>> {
        use walrus::ConstExpr;

        for data in self.module.data.iter() {
            if let walrus::DataKind::Active { offset: ref const_expr, .. } = data.kind {
                let seg_offset = match const_expr {
                    ConstExpr::Value(ir::Value::I32(off)) => *off as u32,
                    ConstExpr::Value(ir::Value::I64(off)) => *off as u32,
                    _ => continue,
                };
                let seg_end = seg_offset + data.value.len() as u32;
                if offset >= seg_offset && offset.checked_add(len)? <= seg_end {
                    let local_start = (offset - seg_offset) as usize;
                    let local_end = local_start + len as usize;
                    return Some(data.value[local_start..local_end].to_vec());
                }
            }
        }
        None
    }
}

/// Build a mapping from imported FunctionId to resolved HostFunction.
fn build_host_func_map(module: &Module) -> HashMap<FunctionId, &'static HostFunction> {
    let mut map = HashMap::new();
    for import in module.imports.iter() {
        if let walrus::ImportKind::Function(fid) = import.kind {
            if let Some(hf) = host_functions::lookup(&import.module, &import.name) {
                map.insert(fid, hf);
            }
        }
    }
    map
}
