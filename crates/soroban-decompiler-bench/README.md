# soroban-decompiler-bench

AST-based accuracy benchmark for Soroban decompiler output. Compares original Rust source against decompiled output using structural AST analysis.

## Usage

```bash
# Score a single contract
soroban-bench score -o original.rs -d decompiled.rs

# Score all contracts in a directory
soroban-bench score-all -o examples/decompiled/original/ -d examples/decompiled/

# JSON output
soroban-bench score-all -o original/ -d decompiled/ -f json

# Dump extracted AST
soroban-bench ast -i contract.rs
```

## Library

```rust
use soroban_decompiler_bench::{score_contract, benchmark_contract, BenchReport};

let score = score_contract(original_src, decompiled_src)?;
println!("accuracy: {:.1}%", score.overall * 100.0);
```

## Scoring

Weighted: **types 20%**, **signatures 20%**, **bodies 60%**.

Body comparison uses expression-coverage rather than strict statement alignment — decompiler intermediary let-bindings don't penalize the score.

## License

Apache-2.0
