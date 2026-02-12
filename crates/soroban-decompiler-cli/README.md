# soroban-decompiler-cli

Command-line tool for decompiling Soroban smart contracts from compiled WASM binaries back to readable Rust source code.

This crate provides the `soroban-decompile` binary, which wraps the `soroban-decompiler` library. It supports full decompilation, signature-only extraction, contract spec inspection, host import resolution, WASM analysis, and low-level stack debugging. All output goes to stdout by default so it can be piped into other tools.


## Installation

Build from the workspace root:

```
cargo build --release
```

The binary is at `target/release/soroban-decompile`. You can also run it directly through cargo:

```
cargo run --release -p soroban-decompiler-cli -- <command> [options]
```


## Commands

### decompile

The primary command. Reads a `.wasm` file and outputs reconstructed Rust source code including type definitions, contract struct, and function bodies with storage operations, authentication calls, and cross-contract invocations.

```
soroban-decompile decompile -i contract.wasm
```

Write the output to a file instead of stdout:

```
soroban-decompile decompile -i contract.wasm -o decompiled.rs
```

Extract only type definitions and function signatures, skipping bytecode analysis. This is useful when you need just the contract interface and want it fast.

```
soroban-decompile decompile --signatures-only -i contract.wasm
```

### inspect

Prints the contract specification as formatted JSON. This includes all functions with their parameter names and types, struct definitions, enum variants, error codes, and event schemas. The data comes from the `contractspecv0` WASM custom section that the Soroban SDK embeds during compilation.

```
soroban-decompile inspect -i contract.wasm
```

### imports

Resolves every entry in the WASM import table against the Soroban host function database and prints the results as JSON. Each import is shown with its raw WASM module/field name alongside the resolved semantic name (like `get_contract_data` or `require_auth_for_args`), argument types, and return type.

```
soroban-decompile imports -i contract.wasm
```

### analyze

Traces the Soroban dispatcher chain for each exported function and reports the host function calls found in each implementation, along with metadata about the function's complexity: whether it contains branches, loops, local calls, and how many instructions it has.

```
soroban-decompile analyze -i contract.wasm
```

### debug-stack

A diagnostic command for examining the decompiler's internal analysis of a specific function. It dumps the full stack simulation results: the traced host calls with their resolved arguments, the return expression, the control flow block tree (if/else, loops), and the memory state showing callee writes propagated to the caller. Useful for understanding why a particular function's output has unresolved values.

```
soroban-decompile debug-stack -i contract.wasm -f increment
```


## Examples

The repository includes pre-compiled WASM files in `examples/contracts/` taken from https://github.com/stellar/soroban-examples for quick testing without setting up the Soroban build toolchain.

Decompile the hello_world contract:

```
soroban-decompile decompile -i examples/contracts/soroban_hello_world_contract.wasm
```

Decompile increment and write to a file:

```
soroban-decompile decompile \
  -i examples/contracts/soroban_increment_contract.wasm \
  -o increment.rs
```

Inspect the auth contract's spec:

```
soroban-decompile inspect -i examples/contracts/soroban_auth_contract.wasm
```

Debug the increment function's stack analysis in the custom_types contract:

```
soroban-decompile debug-stack \
  -i examples/contracts/soroban_custom_types_contract.wasm \
  -f increment
```

Decompile all example contracts:

```
for f in examples/contracts/*.wasm; do
  echo "=== $(basename $f) ==="
  soroban-decompile decompile -i "$f"
  echo
done
```

To decompile your own contracts, compile them with `soroban contract build` and point the tool at the `.wasm` file in `target/wasm32v1-none/release/`.


## License

Apache-2.0
