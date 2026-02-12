# soroban-decompiler

Rust library for decompiling Soroban smart contracts from compiled WASM back to readable Rust source code.

This crate implements the full decompilation pipeline: extracting contract metadata from `contractspecv0` WASM custom sections, analyzing bytecode through stack simulation, recognizing Soroban SDK patterns in host function call sequences, and generating formatted Rust output. It is designed to be embedded in other tools (IDEs, block explorers, audit pipelines) as a library dependency. The companion `soroban-decompiler-cli` crate wraps this library in a command-line interface.


## Usage

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
soroban-decompiler = { path = "../soroban-decompiler" }
```

The primary entry point is the `decompile` function, which takes raw WASM bytes and returns formatted Rust source code as a string.

```rust
use soroban_decompiler::{decompile, DecompileOptions};

let wasm_bytes = std::fs::read("contract.wasm").unwrap();

// Full decompilation: types, signatures, and function bodies.
let options = DecompileOptions { signatures_only: false };
let rust_source = decompile(&wasm_bytes, &options).unwrap();
println!("{}", rust_source);
```

The `signatures_only` option skips bytecode analysis entirely and reconstructs only type definitions and function signatures from the contract spec. This is fast and useful when you only need the contract interface.

```rust
let options = DecompileOptions { signatures_only: true };
let signatures = decompile(&wasm_bytes, &options).unwrap();
```


## Pipeline stages

Each stage of the pipeline is also available as a standalone function for tools that need intermediate results.

**Spec extraction** returns the raw Stellar XDR spec entries, which carry struct definitions, enum variants, error codes, event schemas, and function signatures.

```rust
let entries = soroban_decompiler::extract_spec(&wasm_bytes).unwrap();
for entry in &entries {
    println!("{:?}", entry);
}
```

**Import resolution** maps WASM import table entries to their semantic Soroban host function names. Each import is resolved against the built-in `env.json` database that ships with the crate.

```rust
let imports = soroban_decompiler::resolve_imports(&wasm_bytes).unwrap();
for import in &imports {
    if let Some(name) = &import.semantic_name {
        println!("{}.{} -> {}", import.module, import.field, name);
    }
}
```

**WASM analysis** parses the binary, traces dispatchers, and simulates function stacks. The `AnalyzedModule` provides access to per-function analysis results including host call sequences with resolved arguments, control flow structure, and memory state.

```rust
let module = soroban_decompiler::analyze(&wasm_bytes).unwrap();
let analyses = module.analyze_all_exports();
for analysis in &analyses {
    println!("{}: {} host calls", analysis.export_name, analysis.host_calls.len());
}
```


## Public modules

The crate exposes four public modules for advanced use cases.

`host_functions` provides the Soroban host function database loaded from the embedded `env.json`. Each entry maps a WASM import (module + field) to a semantic name, argument types, and return type.

`ir` defines the high-level intermediate representation used between the pattern recognizer and code generator. It includes types for statements (let bindings, assignments, if/else, loops, returns), expressions (method chains, binary ops, struct literals, macro calls), and literals.

`wasm_analysis` contains the WASM module analyzer, stack simulator, and control flow tracer. The `AnalyzedModule` type is the main entry point. It provides `analyze_export` for single-function analysis and `analyze_function_stack` for detailed stack-level tracing with memory state.

`wasm_imports` handles resolution of WASM import table entries against the host function database.


## How it works

Soroban contracts compile Rust source through `rustc` targeting `wasm32v1-none`, then the toolchain runs `wasm-opt` for size optimization. The resulting WASM binary contains a dispatch function that maps incoming function name symbols to implementation functions. Each implementation function interacts with the Soroban runtime through host function imports (for storage access, authentication, token operations, etc.).

The decompiler reverses this process. It follows the dispatch chain from exported functions to their implementations, simulates the WASM stack to track how values flow from parameters and constants through locals and memory into host function call arguments, and then maps those host call sequences back to the SDK method chains that produced them. The Soroban Val encoding (64-bit tagged values with type tags in the lower 8 bits) is stripped during analysis, so the output uses native Rust types rather than raw `Val` manipulations.

The compiler frequently splits contract functions into helper functions that write results through pointer parameters into the caller's stack frame. The analyzer propagates these callee memory writes back to the caller, which is essential for resolving struct field values, storage keys, and other compound expressions that pass through helper functions.


## Limitations

The decompiler does not reconstruct `unwrap_or` calls. The WASM compiler merges `has` + `get` + default into a conditional branch, and the decompiler currently flattens these into just the `get` call.

Enum-based storage keys (like `DataKey::Counter(user)`) are rendered as their serialized form (`vec!(&env, sym, user)` or `/* vec from memory */`) rather than reconstructed as enum constructor syntax.

Iterator-based loops (`for x in vec.iter()`) are not traced through the loop body. The loop structure is detected but the body's value flow is not followed.

Functions that exceed the inline analysis depth of 5 nested calls may have unresolved values in their output, shown as `/* unknown */` or `local_N` placeholders.


## License

Apache-2.0
