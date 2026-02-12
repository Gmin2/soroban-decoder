//! Soroban host function database.
//!
//! Soroban contracts interact with the runtime through host function imports.
//! Each host function has a raw WASM-level export name (e.g. `"l"`, `"_"`)
//! and a semantic name (e.g. `"get_contract_data"`, `"require_auth"`). This
//! module loads the complete mapping from the bundled `env.json` file, which
//! is sourced from the
//! [`rs-soroban-env`](https://github.com/nickliao6/soroban-env-host) crate.
//!
//! The database is initialized lazily on first access and lives for the
//! lifetime of the process. All string data is leaked to `&'static str` so
//! that [`HostFunction`] references can be shared freely without lifetime
//! concerns.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;

/// A resolved Soroban host function with its full metadata.
///
/// Each instance describes one function exported by the Soroban host
/// environment, including its semantic name, argument types, return type,
/// and documentation string from the upstream specification.
#[derive(Debug, Clone)]
pub struct HostFunction {
    /// Semantic module name (e.g. `"ledger"`, `"context"`, `"crypto"`).
    pub module: &'static str,
    /// Raw WASM module export string used in the import table.
    pub module_export: &'static str,
    /// Semantic function name (e.g. `"get_contract_data"`, `"require_auth"`).
    pub name: &'static str,
    /// Raw WASM function export string used in the import table.
    pub fn_export: &'static str,
    /// Typed argument list.
    pub args: Vec<HostFunctionArg>,
    /// Return type name (e.g. `"Val"`, `"Void"`, `"U32Val"`).
    pub return_type: &'static str,
    /// Documentation string from the upstream Soroban environment spec.
    pub docs: &'static str,
}

/// A single argument in a [`HostFunction`] signature.
#[derive(Debug, Clone)]
pub struct HostFunctionArg {
    /// Argument name (e.g. `"key"`, `"val"`, `"storage_type"`).
    pub name: &'static str,
    /// Argument type (e.g. `"Val"`, `"U32Val"`, `"StorageType"`).
    pub r#type: &'static str,
}

#[derive(Deserialize)]
struct EnvJson {
    modules: Vec<ModuleJson>,
}

#[derive(Deserialize)]
struct ModuleJson {
    name: String,
    export: String,
    functions: Vec<FunctionJson>,
}

#[derive(Deserialize)]
struct FunctionJson {
    name: String,
    export: String,
    args: Vec<ArgJson>,
    r#return: String,
    #[serde(default)]
    docs: String,
}

#[derive(Deserialize)]
struct ArgJson {
    name: String,
    r#type: String,
}

/// Lookup table keyed by `(module_export, fn_export)` -> `HostFunction`.
///
/// Built once from the bundled `env.json` (sourced from `rs-soroban-env`).
static HOST_FUNCTIONS: LazyLock<HashMap<(String, String), HostFunction>> =
    LazyLock::new(|| {
        let json_str: &'static str = include_str!("env.json");
        let env: EnvJson = serde_json::from_str(json_str).expect("failed to parse env.json");

        let mut map = HashMap::new();
        for module in &env.modules {
            let mod_name: &'static str = leak_str(&module.name);
            let mod_export: &'static str = leak_str(&module.export);
            for func in &module.functions {
                let fn_name: &'static str = leak_str(&func.name);
                let fn_export: &'static str = leak_str(&func.export);
                let return_type: &'static str = leak_str(&func.r#return);
                let docs: &'static str = leak_str(&func.docs);
                let args = func
                    .args
                    .iter()
                    .map(|a| HostFunctionArg {
                        name: leak_str(&a.name),
                        r#type: leak_str(&a.r#type),
                    })
                    .collect();

                map.insert(
                    (mod_export.to_string(), fn_export.to_string()),
                    HostFunction {
                        module: mod_name,
                        module_export: mod_export,
                        name: fn_name,
                        fn_export,
                        args,
                        return_type,
                        docs,
                    },
                );
            }
        }
        map
    });

/// Resolve a WASM import to its semantic host function.
///
/// Looks up the `(module_export, fn_export)` pair in the lazily-initialized
/// database. Returns the matched [`HostFunction`] with full metadata, or
/// `None` if the import is not a recognized Soroban host function.
pub fn lookup(module_export: &str, fn_export: &str) -> Option<&'static HostFunction> {
    HOST_FUNCTIONS.get(&(module_export.to_string(), fn_export.to_string()))
}

/// Total number of known host functions.
pub fn count() -> usize {
    HOST_FUNCTIONS.len()
}

/// Leak a String to get a &'static str (safe for one-time init).
fn leak_str(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}
