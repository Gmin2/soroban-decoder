use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct HostFunction {
    pub module: &'static str,
    pub module_export: &'static str,
    pub name: &'static str,
    pub fn_export: &'static str,
    pub args: Vec<HostFunctionArg>,
    pub return_type: &'static str,
    pub docs: &'static str,
}

#[derive(Debug, Clone)]
pub struct HostFunctionArg {
    pub name: &'static str,
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
