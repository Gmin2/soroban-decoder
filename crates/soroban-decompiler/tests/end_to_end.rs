//! End-to-end integration tests for the Soroban decompiler.
//!
//! These tests verify the full decompilation pipeline against the 19 example
//! contracts in `examples/contracts/`. Each test loads a pre-compiled WASM
//! binary and asserts properties of the decompiled output.

use std::fs;
use std::path::Path;

use soroban_decompiler::{decompile, extract_spec, DecompileOptions};
use stellar_xdr::curr::ScSpecEntry;

const CONTRACTS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/contracts");

const ALL_CONTRACTS: &[&str] = &[
    "soroban_hello_world_contract",
    "soroban_increment_contract",
    "soroban_auth_contract",
    "soroban_custom_types_contract",
    "soroban_cross_contract_a_contract",
    "soroban_cross_contract_b_contract",
    "soroban_errors_contract",
    "soroban_events_contract",
    "soroban_atomic_swap_contract",
    "soroban_atomic_multiswap_contract",
    "soroban_deployer_contract",
    "soroban_liquidity_pool_contract",
    "soroban_account_contract",
    "soroban_alloc_contract",
    "soroban_fuzzing_contract",
    "soroban_groth16_verifier_contract",
    "soroban_bls_signature",
    "soroban_eth_abi",
    "privacy_pools",
];

fn load_contract(name: &str) -> Vec<u8> {
    let path = Path::new(CONTRACTS_DIR).join(format!("{name}.wasm"));
    fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

fn decompile_full(wasm: &[u8]) -> String {
    decompile(wasm, &DecompileOptions { signatures_only: false })
        .expect("decompilation should not fail")
}

fn decompile_sigs(wasm: &[u8]) -> String {
    decompile(wasm, &DecompileOptions { signatures_only: true })
        .expect("signatures-only decompilation should not fail")
}

fn parse_rust(source: &str) -> syn::File {
    syn::parse_str(source).unwrap_or_else(|e| panic!("decompiled output is not valid Rust: {e}"))
}

fn spec_function_names(entries: &[ScSpecEntry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|e| match e {
            ScSpecEntry::FunctionV0(f) => Some(f.name.to_utf8_string_lossy()),
            _ => None,
        })
        .collect()
}

fn spec_struct_names(entries: &[ScSpecEntry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|e| match e {
            ScSpecEntry::UdtStructV0(s) => Some(s.name.to_utf8_string_lossy()),
            _ => None,
        })
        .collect()
}

fn spec_enum_names(entries: &[ScSpecEntry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|e| match e {
            ScSpecEntry::UdtUnionV0(u) => Some(u.name.to_utf8_string_lossy()),
            ScSpecEntry::UdtEnumV0(e) => Some(e.name.to_utf8_string_lossy()),
            _ => None,
        })
        .collect()
}

fn spec_error_names(entries: &[ScSpecEntry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|e| match e {
            ScSpecEntry::UdtErrorEnumV0(e) => Some(e.name.to_utf8_string_lossy()),
            _ => None,
        })
        .collect()
}

fn rust_function_names(file: &syn::File) -> Vec<String> {
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(imp) => Some(
                imp.items
                    .iter()
                    .filter_map(|i| match i {
                        syn::ImplItem::Fn(m) => Some(m.sig.ident.to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect()
}

fn rust_struct_names(file: &syn::File) -> Vec<String> {
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(s) => Some(s.ident.to_string()),
            _ => None,
        })
        .collect()
}

fn rust_enum_names(file: &syn::File) -> Vec<String> {
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Enum(e) => Some(e.ident.to_string()),
            _ => None,
        })
        .collect()
}

mod decompilation {
    use super::*;

    macro_rules! contract_test {
        ($name:ident) => {
            #[test]
            fn $name() {
                let wasm = load_contract(stringify!($name));
                let source = decompile_full(&wasm);
                assert!(!source.is_empty());
            }
        };
    }

    contract_test!(soroban_hello_world_contract);
    contract_test!(soroban_increment_contract);
    contract_test!(soroban_auth_contract);
    contract_test!(soroban_custom_types_contract);
    contract_test!(soroban_cross_contract_a_contract);
    contract_test!(soroban_cross_contract_b_contract);
    contract_test!(soroban_errors_contract);
    contract_test!(soroban_events_contract);
    contract_test!(soroban_atomic_swap_contract);
    contract_test!(soroban_atomic_multiswap_contract);
    contract_test!(soroban_deployer_contract);
    contract_test!(soroban_liquidity_pool_contract);
    contract_test!(soroban_account_contract);
    contract_test!(soroban_alloc_contract);
    contract_test!(soroban_fuzzing_contract);
    contract_test!(soroban_groth16_verifier_contract);
    contract_test!(soroban_bls_signature);
    contract_test!(soroban_eth_abi);
    contract_test!(privacy_pools);
}

mod syntax {
    use super::*;

    /// Every decompiled contract must be syntactically valid Rust (parseable by `syn`).
    #[test]
    fn all_contracts_parse() {
        let mut failures = Vec::new();
        for name in ALL_CONTRACTS {
            let wasm = load_contract(name);
            let source = decompile_full(&wasm);
            if syn::parse_str::<syn::File>(&source).is_err() {
                failures.push(*name);
            }
        }
        assert!(failures.is_empty(), "invalid Rust syntax: {failures:?}");
    }

    /// No decompiled output should contain `todo!()` placeholders.
    #[test]
    fn no_todo_placeholders() {
        let mut failures = Vec::new();
        for name in ALL_CONTRACTS {
            let wasm = load_contract(name);
            let source = decompile_full(&wasm);
            if source.contains("todo!()") {
                failures.push(*name);
            }
        }
        assert!(failures.is_empty(), "contains todo!(): {failures:?}");
    }

    /// Signatures-only mode should produce valid Rust for every contract.
    #[test]
    fn signatures_only_all_parse() {
        for name in ALL_CONTRACTS {
            let wasm = load_contract(name);
            let source = decompile_sigs(&wasm);
            assert!(!source.is_empty(), "{name}: empty output");
            parse_rust(&source);
        }
    }
}

mod spec_fidelity {
    use super::*;

    /// Every function declared in the contract spec must appear in the decompiled output.
    #[test]
    fn all_functions_present() {
        let mut missing = Vec::new();
        for name in ALL_CONTRACTS {
            let wasm = load_contract(name);
            let entries = extract_spec(&wasm).expect("spec extraction failed");
            let spec_fns = spec_function_names(&entries);

            let source = decompile_full(&wasm);
            let file = parse_rust(&source);
            let rust_fns = rust_function_names(&file);

            for f in &spec_fns {
                if !rust_fns.iter().any(|rf| rf == f) {
                    missing.push(format!("{name}::{f}"));
                }
            }
        }
        assert!(missing.is_empty(), "spec functions missing: {missing:?}");
    }

    /// Every struct and enum in the contract spec must appear in the decompiled output.
    #[test]
    fn all_types_present() {
        let mut missing = Vec::new();
        for name in ALL_CONTRACTS {
            let wasm = load_contract(name);
            let entries = extract_spec(&wasm).expect("spec extraction failed");

            let source = decompile_full(&wasm);
            let file = parse_rust(&source);
            let structs = rust_struct_names(&file);
            let enums = rust_enum_names(&file);

            for s in spec_struct_names(&entries) {
                if !structs.iter().any(|rs| *rs == s) {
                    missing.push(format!("{name}::struct::{s}"));
                }
            }
            for e in spec_enum_names(&entries) {
                if !enums.iter().any(|re| *re == e) {
                    missing.push(format!("{name}::enum::{e}"));
                }
            }
            for e in spec_error_names(&entries) {
                if !enums.iter().any(|re| *re == e) {
                    missing.push(format!("{name}::error::{e}"));
                }
            }
        }
        assert!(missing.is_empty(), "spec types missing: {missing:?}");
    }

    /// Spec extraction itself must succeed for every contract.
    #[test]
    fn extraction_succeeds() {
        for name in ALL_CONTRACTS {
            let wasm = load_contract(name);
            let entries = extract_spec(&wasm)
                .unwrap_or_else(|e| panic!("{name}: spec extraction failed: {e}"));
            assert!(!entries.is_empty(), "{name}: spec has no entries");
        }
    }

    /// Import resolution must succeed for every contract. Contracts that use
    /// host functions should have at least one resolved import.
    #[test]
    fn imports_resolved() {
        // Contracts with no host function imports (pure arithmetic).
        let no_imports = ["soroban_cross_contract_a_contract", "soroban_alloc_contract"];

        for name in ALL_CONTRACTS {
            let wasm = load_contract(name);
            let imports = soroban_decompiler::resolve_imports(&wasm)
                .unwrap_or_else(|e| panic!("{name}: import resolution failed: {e}"));
            if !no_imports.contains(name) {
                let resolved = imports.iter().filter(|i| i.semantic_name.is_some()).count();
                assert!(resolved > 0, "{name}: no imports resolved");
            }
        }
    }
}

mod performance {
    use super::*;

    /// Every contract must decompile in under 10 seconds.
    #[test]
    fn no_timeout() {
        for name in ALL_CONTRACTS {
            let wasm = load_contract(name);
            let start = std::time::Instant::now();
            let _source = decompile_full(&wasm);
            let elapsed = start.elapsed();
            assert!(elapsed.as_secs() < 10, "{name}: took {elapsed:?}");
        }
    }
}

mod structure {
    use super::*;

    /// Core contracts must emit `#[contract]` and `#[contractimpl]` attributes.
    #[test]
    fn contract_attributes_present() {
        let core = [
            "soroban_hello_world_contract",
            "soroban_increment_contract",
            "soroban_auth_contract",
            "soroban_custom_types_contract",
            "soroban_errors_contract",
            "soroban_events_contract",
            "soroban_atomic_swap_contract",
        ];

        for name in &core {
            let wasm = load_contract(name);
            let source = decompile_full(&wasm);
            assert!(source.contains("#[contract]"), "{name}: missing #[contract]");
            assert!(source.contains("#[contractimpl]"), "{name}: missing #[contractimpl]");
        }
    }

    /// Every decompiled contract should include a `#![no_std]` attribute.
    #[test]
    fn no_std_present() {
        for name in ALL_CONTRACTS {
            let wasm = load_contract(name);
            let source = decompile_full(&wasm);
            assert!(source.contains("#![no_std]"), "{name}: missing #![no_std]");
        }
    }
}
