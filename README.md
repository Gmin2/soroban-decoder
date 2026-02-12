# soroban-decompiler

A decompiler for Soroban smart contracts compiled to WASM. It takes a `.wasm` binary produced by the Soroban SDK toolchain and reconstructs readable Rust source code from it, recovering type definitions, function signatures, storage operations, authentication calls, and cross-contract invocations.

Soroban contracts embed a `contractspecv0` custom section in the WASM binary that carries complete type metadata: struct definitions, enum variants, error codes, event schemas, and function signatures with named parameters. The decompiler extracts this metadata and combines it with bytecode-level analysis to produce output that closely resembles the original contract source.

The project is organized as a Rust workspace with two crates. The `soroban-decompiler` library crate implements the full decompilation pipeline and can be embedded in other tools. The `soroban-decompiler-cli` crate provides the `soroban-decompile` command-line binary for direct use.


## Architecture

The decompilation pipeline has four stages that run in sequence.

**Spec extraction** reads the `contractspecv0` custom section from the WASM binary and deserializes it into Stellar XDR types. This recovers all struct definitions, enum variants (including tagged unions), error enums, event schemas, and function signatures with fully typed and named parameters.

**WASM analysis** parses the binary with `walrus`, identifies exported contract functions, traces through Soroban's dispatcher chain (which maps function name symbols to implementation functions), and then simulates each implementation function's stack. The simulator tracks values through locals, memory loads/stores, function calls, and control flow branches. It resolves arguments to host function calls by following the data flow back to their origins: parameters, constants, or results of earlier calls. Callee memory writes are propagated back to the caller so that helper functions that write through pointer parameters have their results visible in the calling function.

**Pattern recognition** takes the flat sequence of host function calls from the analysis stage and maps them to high-level Soroban SDK operations. For example, a sequence of `obj_new_from_linear_memory` followed by `get_contract_data` becomes `env.storage().instance().get(symbol_short!("KEY"))`. It builds method chains, resolves struct field accesses through map unpack operations, detects i128 round-trips, and eliminates dead variables and common subexpressions. The output is a typed intermediate representation.

**Code generation** walks the IR and emits Rust token streams using `syn` and `quote`, then formats the result with `prettyplease`. It reconstructs `#[contracttype]` struct and enum definitions, `#[contracterror]` error enums, `#[contractimpl]` function bodies, and the top-level `#[contract]` struct with appropriate `use` imports.


## Building

Requires Rust 1.70 or later.

```
cargo build --release
```

The compiled binary is at `target/release/soroban-decompile`.


## Quick start

Decompile a contract and print to stdout:

```
cargo run --release -- decompile -i examples/contracts/soroban_hello_world_contract.wasm
```

Write the output to a file:

```
cargo run --release -- decompile \
  -i examples/contracts/soroban_increment_contract.wasm \
  -o increment_decompiled.rs
```

Extract only type definitions and function signatures, without decompiling bodies:

```
cargo run --release -- decompile --signatures-only \
  -i examples/contracts/soroban_custom_types_contract.wasm
```

Inspect the contract specification as JSON:

```
cargo run --release -- inspect -i examples/contracts/soroban_auth_contract.wasm
```


## Example output

Given the `hello_world` contract, the decompiler produces:

```rust
#![no_std]
use soroban_sdk::{contract, contractimpl, Env, String, Vec};

#[contract]
pub struct HelloWorldContract;

#[contractimpl]
impl HelloWorldContract {
    pub fn hello(env: Env, to: String) -> Vec<String> {
        let str_val = String::from_str(&env, "Hello");
        let args = vec!(&env, str_val, to);
        return args;
    }
}
```

The original source for this contract is:

```rust
pub fn hello(env: Env, to: String) -> Vec<String> {
    vec![&env, String::from_str(&env, "Hello"), to]
}
```

The differences are cosmetic: an intermediate binding for the string literal, an explicit `return` instead of an implicit tail expression, and `vec!()` macro syntax instead of `vec![]`. The semantics are identical.

See `DECOMPILER_COMPARISON.md` for a detailed comparison across 10 contracts with quality ratings and delta analysis.


## Example contracts

The `examples/contracts/` directory contains 20 pre-compiled Soroban WASM binaries taken from the official Stellar examples repository at https://github.com/stellar/soroban-examples. These cover a wide range of contract patterns, from trivial single-function contracts to complex multi-function DeFi and cryptography contracts, and can be used to test the decompiler without setting up the Soroban build toolchain.

| File | Description | Size |
|------|-------------|------|
| `soroban_hello_world_contract.wasm` | String construction, vec return | 660 B |
| `soroban_increment_contract.wasm` | Storage get/set, TTL extend | 682 B |
| `soroban_cross_contract_a_contract.wasm` | Cross-contract caller | 527 B |
| `soroban_cross_contract_b_contract.wasm` | Cross-contract callee | 754 B |
| `soroban_errors_contract.wasm` | Custom error enum, Result return | 794 B |
| `soroban_events_contract.wasm` | Event publishing | 977 B |
| `soroban_auth_contract.wasm` | Address auth, persistent storage | 1.1 KB |
| `soroban_custom_types_contract.wasm` | Custom structs, field arithmetic | 1.3 KB |
| `soroban_atomic_swap_contract.wasm` | Atomic token swap, multi-auth | 1.9 KB |
| `soroban_atomic_multiswap_contract.wasm` | Batched atomic swaps | 2.0 KB |
| `soroban_deployer_contract.wasm` | Contract deployer, deep auth | 2.2 KB |
| `soroban_alloc_contract.wasm` | Allocator usage, loops | 2.5 KB |
| `soroban_bls_signature.wasm` | BLS12-381 signature verification | 2.6 KB |
| `soroban_fuzzing_contract.wasm` | Claimable balance, time bounds | 4.1 KB |
| `soroban_account_contract.wasm` | Custom account, multi-sig | 5.3 KB |
| `soroban_groth16_verifier_contract.wasm` | Groth16 ZK proof verifier | 5.1 KB |
| `soroban_eth_abi.wasm` | Ethereum ABI encoding/decoding | 6.7 KB |
| `soroban_liquidity_pool_contract.wasm` | AMM liquidity pool, token math | 11 KB |
| `privacy_pools.wasm` | Privacy pool with ZK proofs | 34 KB |
| `soroban_ark_bn254_contract.wasm` | BN254 curve operations | 59 KB |

To decompile all of them:

```
for f in examples/contracts/*.wasm; do
  echo "=== $(basename $f) ==="
  cargo run --release -- decompile -i "$f"
  echo
done
```

To test against your own contracts, compile them with the Soroban SDK (`soroban contract build`) and point the decompiler at the resulting `.wasm` file in `target/wasm32v1-none/release/`.


## Project layout

```
soroban_decompiler/
  Cargo.toml                    Workspace root
  examples/contracts/           Pre-compiled WASM test fixtures
  crates/
    soroban-decompiler/         Library crate (pipeline implementation)
    soroban-decompiler-cli/     CLI crate (soroban-decompile binary)
```


## License

Apache-2.0
