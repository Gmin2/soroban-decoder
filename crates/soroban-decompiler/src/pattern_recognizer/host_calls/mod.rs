//! Host call pattern matching.
//!
//! Maps individual host function calls to high-level IR statements
//! representing idiomatic Soroban SDK operations.

mod storage;
mod auth;
mod context;
mod crypto;
mod collections;
mod types;

use std::collections::HashMap;

use crate::ir::{Expr, Literal, MethodCall, Statement};
use crate::wasm_analysis::TrackedHostCall;

use super::RecognitionContext;
use super::val_decoding::{
    extract_u32_val, resolve_arg,
};

/// Try to recognize a single host call and produce an IR statement.
///
/// `crn` is the call-result-names map, which may be partially built
/// during the first pass.
pub fn recognize_call(
    call: &TrackedHostCall,
    ctx: &RecognitionContext,
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let pn = &ctx.param_names;
    let name = call.host_func.name;

    match name {
        // Storage operations
        "get_contract_data" => {
            storage::recognize_storage_get(call, pn, crn, ctx.all_entries)
        }
        "put_contract_data" => {
            storage::recognize_storage_set(call, pn, crn, ctx.all_entries)
        }
        "has_contract_data" => {
            storage::recognize_storage_has(call, pn, crn, ctx.all_entries)
        }
        "del_contract_data" => {
            storage::recognize_storage_del(call, pn, crn, ctx.all_entries)
        }

        // Authorization
        "require_auth" => {
            auth::recognize_require_auth(call, pn, crn)
        }
        "require_auth_for_args" => {
            auth::recognize_require_auth_for_args(call, pn, crn, ctx)
        }

        // Context
        "get_current_contract_address" => Some(Statement::Let {
            name: "contract_addr".into(),
            mutable: false,
            value: Expr::MethodChain {
                receiver: Box::new(Expr::Var("env".into())),
                calls: vec![MethodCall {
                    name: "current_contract_address".into(),
                    args: vec![],
                }],
            },
        }),

        // Crypto
        "verify_sig_ed25519" => {
            crypto::recognize_ed25519_verify(call, pn, crn)
        }

        // Events
        "contract_event" => context::recognize_event(call, ctx, crn),

        // Map operations
        "map_new" => Some(Statement::Let {
            name: "map".into(),
            mutable: false,
            value: Expr::HostCall {
                module: "Map".into(),
                name: "new".into(),
                args: vec![Expr::Var("&env".into())],
            },
        }),

        // Vec operations
        "vec_new" => Some(Statement::Let {
            name: "vec".into(),
            mutable: false,
            value: Expr::HostCall {
                module: "Vec".into(),
                name: "new".into(),
                args: vec![Expr::Var("&env".into())],
            },
        }),
        "vec_get" => {
            let vec_arg = resolve_arg(call.args.first()?, pn, crn);
            let idx_arg = resolve_arg(call.args.get(1)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "item".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(vec_arg),
                    calls: vec![MethodCall { name: "get".into(), args: vec![idx_arg] }],
                },
            })
        }
        "vec_len" => {
            let vec_arg = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "len".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(vec_arg),
                    calls: vec![MethodCall { name: "len".into(), args: vec![] }],
                },
            })
        }
        "vec_push_back" => {
            let vec_arg = resolve_arg(call.args.first()?, pn, crn);
            let val_arg = resolve_arg(call.args.get(1)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "vec".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(vec_arg),
                    calls: vec![MethodCall { name: "push_back".into(), args: vec![val_arg] }],
                },
            })
        }
        "vec_push_front" => {
            let vec_arg = resolve_arg(call.args.first()?, pn, crn);
            let val_arg = resolve_arg(call.args.get(1)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "vec".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(vec_arg),
                    calls: vec![MethodCall { name: "push_front".into(), args: vec![val_arg] }],
                },
            })
        }
        "vec_pop_back" => {
            let vec_arg = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "vec".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(vec_arg),
                    calls: vec![MethodCall { name: "pop_back".into(), args: vec![] }],
                },
            })
        }
        "vec_pop_front" => {
            let vec_arg = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "vec".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(vec_arg),
                    calls: vec![MethodCall { name: "pop_front".into(), args: vec![] }],
                },
            })
        }
        "vec_put" => {
            let vec_arg = resolve_arg(call.args.first()?, pn, crn);
            let idx_arg = resolve_arg(call.args.get(1)?, pn, crn);
            let val_arg = resolve_arg(call.args.get(2)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "vec".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(vec_arg),
                    calls: vec![MethodCall { name: "set".into(), args: vec![idx_arg, val_arg] }],
                },
            })
        }
        "vec_append" => {
            let vec_a = resolve_arg(call.args.first()?, pn, crn);
            let vec_b = resolve_arg(call.args.get(1)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "vec".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(vec_a),
                    calls: vec![MethodCall { name: "append".into(), args: vec![Expr::Ref(Box::new(vec_b))] }],
                },
            })
        }
        "vec_slice" => {
            let vec_arg = resolve_arg(call.args.first()?, pn, crn);
            let start = resolve_arg(call.args.get(1)?, pn, crn);
            let end = resolve_arg(call.args.get(2)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "vec".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(vec_arg),
                    calls: vec![MethodCall { name: "slice".into(), args: vec![start, end] }],
                },
            })
        }
        "vec_unpack_to_linear_memory" => None,

        // Map operations (beyond map_new)
        "map_get" => {
            let map_arg = resolve_arg(call.args.first()?, pn, crn);
            let key_arg = resolve_arg(call.args.get(1)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "item".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(map_arg),
                    calls: vec![MethodCall { name: "get".into(), args: vec![key_arg] }],
                },
            })
        }
        "map_has" => {
            let map_arg = resolve_arg(call.args.first()?, pn, crn);
            let key_arg = resolve_arg(call.args.get(1)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "has_key".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(map_arg),
                    calls: vec![MethodCall { name: "contains_key".into(), args: vec![key_arg] }],
                },
            })
        }
        "map_put" => {
            let map_arg = resolve_arg(call.args.first()?, pn, crn);
            let key_arg = resolve_arg(call.args.get(1)?, pn, crn);
            let val_arg = resolve_arg(call.args.get(2)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "map".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(map_arg),
                    calls: vec![MethodCall { name: "set".into(), args: vec![key_arg, val_arg] }],
                },
            })
        }
        "map_del" => {
            let map_arg = resolve_arg(call.args.first()?, pn, crn);
            let key_arg = resolve_arg(call.args.get(1)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "map".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(map_arg),
                    calls: vec![MethodCall { name: "remove".into(), args: vec![key_arg] }],
                },
            })
        }
        "map_len" => {
            let map_arg = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "len".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(map_arg),
                    calls: vec![MethodCall { name: "len".into(), args: vec![] }],
                },
            })
        }
        "map_keys" => {
            let map_arg = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "keys".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(map_arg),
                    calls: vec![MethodCall { name: "keys".into(), args: vec![] }],
                },
            })
        }
        "map_values" => {
            let map_arg = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "values".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(map_arg),
                    calls: vec![MethodCall { name: "values".into(), args: vec![] }],
                },
            })
        }

        // Vec/Symbol/Bytes from linear memory
        "vec_new_from_linear_memory" => {
            collections::recognize_vec_new_from_linear_memory(
                call, pn, crn,
                ctx.vec_contents, ctx.all_entries,
                &ctx.memory_strings,
            )
        }
        "map_new_from_linear_memory" => {
            collections::recognize_map_new_from_linear_memory(
                call, pn, crn,
                ctx.map_contents, ctx.all_entries,
                ctx.analyzed,
            )
        }
        "map_unpack_to_linear_memory" => {
            collections::recognize_map_unpack(
                call, pn, crn,
                ctx.all_entries, ctx.analyzed,
                ctx.unpack_field_ids,
            )
        }
        "symbol_new_from_linear_memory" => {
            let value = if let Some(decoded) = ctx.memory_strings.get(&call.call_site_id) {
                Expr::HostCall {
                    module: "Symbol".into(),
                    name: "new".into(),
                    args: vec![
                        Expr::Var("&env".into()),
                        Expr::Literal(Literal::Str(decoded.clone())),
                    ],
                }
            } else {
                Expr::Raw("/* symbol from memory */".into())
            };
            Some(Statement::Let {
                name: "sym".into(),
                mutable: false,
                value,
            })
        }
        "string_new_from_linear_memory" => {
            let value = if let Some(decoded) = ctx.memory_strings.get(&call.call_site_id) {
                Expr::HostCall {
                    module: "String".into(),
                    name: "from_str".into(),
                    args: vec![
                        Expr::Var("&env".into()),
                        Expr::Literal(Literal::Str(decoded.clone())),
                    ],
                }
            } else {
                Expr::Raw("/* string from memory */".into())
            };
            Some(Statement::Let {
                name: "str_val".into(),
                mutable: false,
                value,
            })
        }

        // Symbol / String construction — internal plumbing for type encoding
        "symbol_index_in_linear_memory" => {
            collections::recognize_symbol_index(call, pn, crn, ctx.analyzed)
        }
        "symbol_len" | "symbol_copy_to_linear_memory"
        | "string_len"
        | "string_copy_to_linear_memory" => None,

        // Bytes operations
        "bytes_new" => Some(Statement::Let {
            name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "bytes_val".into()),
            mutable: false,
            value: Expr::HostCall {
                module: "Bytes".into(),
                name: "new".into(),
                args: vec![Expr::Var("&env".into())],
            },
        }),
        "bytes_new_from_linear_memory" => {
            // Try to extract actual byte data from the WASM data section.
            let ptr = call.args.get(0).and_then(extract_u32_val);
            let len = call.args.get(1).and_then(extract_u32_val);
            let byte_data = ptr.and_then(|p| len.and_then(|l| {
                ctx.analyzed.read_linear_memory(p, l)
            }));
            let data_expr = match byte_data {
                Some(bytes) if bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ') => {
                    // ASCII-representable: emit as b"..."
                    let s = String::from_utf8_lossy(&bytes);
                    Expr::Literal(crate::ir::Literal::Str(format!("b\"{}\"", s)))
                }
                Some(bytes) if bytes.len() <= 64 => {
                    // Short binary data: emit as &[0x01, 0x02, ...]
                    let hex: Vec<String> = bytes.iter().map(|b| format!("0x{:02x}", b)).collect();
                    Expr::Raw(format!("&[{}]", hex.join(", ")))
                }
                _ => Expr::Raw("/* memory slice */".into()),
            };
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "bytes_val".into()),
                mutable: false,
                value: Expr::HostCall {
                    module: "Bytes".into(),
                    name: "from_slice".into(),
                    args: vec![Expr::Var("&env".into()), data_expr],
                },
            })
        }
        "bytes_len" => {
            let bytes_arg = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "len".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(bytes_arg),
                    calls: vec![MethodCall { name: "len".into(), args: vec![] }],
                },
            })
        }
        "bytes_get" => {
            let bytes_arg = resolve_arg(call.args.first()?, pn, crn);
            let idx_arg = resolve_arg(call.args.get(1)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "byte_val".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(bytes_arg),
                    calls: vec![MethodCall { name: "get".into(), args: vec![idx_arg] }],
                },
            })
        }
        "bytes_put" => {
            let bytes_arg = resolve_arg(call.args.first()?, pn, crn);
            let idx_arg = resolve_arg(call.args.get(1)?, pn, crn);
            let val_arg = resolve_arg(call.args.get(2)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "bytes_val".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(bytes_arg),
                    calls: vec![MethodCall { name: "set".into(), args: vec![idx_arg, val_arg] }],
                },
            })
        }
        "bytes_push" => {
            let bytes_arg = resolve_arg(call.args.first()?, pn, crn);
            let val_arg = resolve_arg(call.args.get(1)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "bytes_val".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(bytes_arg),
                    calls: vec![MethodCall { name: "push".into(), args: vec![val_arg] }],
                },
            })
        }
        "bytes_pop" => {
            let bytes_arg = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "bytes_val".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(bytes_arg),
                    calls: vec![MethodCall { name: "pop".into(), args: vec![] }],
                },
            })
        }
        "bytes_append" => {
            let bytes_a = resolve_arg(call.args.first()?, pn, crn);
            let bytes_b = resolve_arg(call.args.get(1)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "bytes_val".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(bytes_a),
                    calls: vec![MethodCall { name: "append".into(), args: vec![Expr::Ref(Box::new(bytes_b))] }],
                },
            })
        }
        "bytes_copy_to_linear_memory"
        | "bytes_copy_from_linear_memory" => None,

        // Ledger / context queries
        "get_ledger_sequence" => Some(Statement::Let {
            name: "sequence".into(),
            mutable: false,
            value: Expr::MethodChain {
                receiver: Box::new(Expr::Var("env".into())),
                calls: vec![
                    MethodCall { name: "ledger".into(), args: vec![] },
                    MethodCall { name: "sequence".into(), args: vec![] },
                ],
            },
        }),
        "get_ledger_timestamp" => Some(Statement::Let {
            name: "timestamp".into(),
            mutable: false,
            value: Expr::MethodChain {
                receiver: Box::new(Expr::Var("env".into())),
                calls: vec![
                    MethodCall { name: "ledger".into(), args: vec![] },
                    MethodCall { name: "timestamp".into(), args: vec![] },
                ],
            },
        }),

        // Cross-contract calls
        "call" => context::recognize_cross_contract_call(call, pn, crn),

        // Logging — skip in decompilation
        "log_from_linear_memory" => None,

        // Val conversions — produce named bindings for the important ones
        "obj_from_u64" => {
            let val = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let { name: "u64_val".into(), mutable: false, value: val })
        }
        "obj_from_i64" => {
            let val = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let { name: "i64_val".into(), mutable: false, value: val })
        }
        "obj_to_u64" => {
            let val = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let { name: "u64_val".into(), mutable: false, value: val })
        }
        "obj_to_i64" => {
            let val = resolve_arg(call.args.first()?, pn, crn);
            Some(Statement::Let { name: "i64_val".into(), mutable: false, value: val })
        }
        "obj_from_u128_pieces" => {
            let hi = resolve_arg(call.args.first()?, pn, crn);
            let lo = resolve_arg(call.args.get(1)?, pn, crn);
            // Detect i128 round-trip: obj_from_pieces(obj_to_hi(X), obj_to_lo(X))
            if let Some(source) = collections::detect_128_roundtrip(&hi, &lo) {
                return Some(Statement::Let {
                    name: "u128_val".into(),
                    mutable: false,
                    value: source,
                });
            }
            Some(Statement::Let {
                name: "u128_val".into(),
                mutable: false,
                value: Expr::BinOp {
                    left: Box::new(Expr::BinOp {
                        left: Box::new(hi),
                        op: crate::ir::BinOp::Shl,
                        right: Box::new(Expr::Literal(Literal::I64(64))),
                    }),
                    op: crate::ir::BinOp::BitOr,
                    right: Box::new(lo),
                },
            })
        }
        "obj_from_i128_pieces" => {
            let hi = resolve_arg(call.args.first()?, pn, crn);
            let lo = resolve_arg(call.args.get(1)?, pn, crn);
            // Detect i128 round-trip: obj_from_pieces(obj_to_hi(X), obj_to_lo(X))
            if let Some(source) = collections::detect_128_roundtrip(&hi, &lo) {
                return Some(Statement::Let {
                    name: "i128_val".into(),
                    mutable: false,
                    value: source,
                });
            }
            Some(Statement::Let {
                name: "i128_val".into(),
                mutable: false,
                value: Expr::BinOp {
                    left: Box::new(Expr::BinOp {
                        left: Box::new(hi),
                        op: crate::ir::BinOp::Shl,
                        right: Box::new(Expr::Literal(Literal::I64(64))),
                    }),
                    op: crate::ir::BinOp::BitOr,
                    right: Box::new(lo),
                },
            })
        }
        // i128/u128 fragment accessors — produce named bindings so downstream
        // i128 assembly (obj_from_*128_pieces) can reference them by name.
        "obj_to_u128_lo64" | "obj_to_i128_lo64" => {
            let src = resolve_arg(call.args.first()?, pn, crn);
            let suffix = match &src {
                Expr::Var(name) => format!("{}_lo", name),
                _ => "lo64".into(),
            };
            Some(Statement::Let { name: suffix, mutable: false, value: src })
        }
        "obj_to_u128_hi64" | "obj_to_i128_hi64" => {
            let src = resolve_arg(call.args.first()?, pn, crn);
            let suffix = match &src {
                Expr::Var(name) => format!("{}_hi", name),
                _ => "hi64".into(),
            };
            Some(Statement::Let { name: suffix, mutable: false, value: src })
        }
        // Fragment accessors for 256 — skip (pieces of larger decompositions)
        "obj_from_u256_pieces" | "obj_from_i256_pieces"
        | "obj_to_u256_hi_hi" | "obj_to_u256_hi_lo"
        | "obj_to_u256_lo_hi" | "obj_to_u256_lo_lo" => None,

        // u256/i256 arithmetic
        "i256_add" | "u256_add" => {
            collections::recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Add)
        }
        "i256_sub" | "u256_sub" => {
            collections::recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Sub)
        }
        "i256_mul" | "u256_mul" => {
            collections::recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Mul)
        }
        "i256_div" | "u256_div" => {
            collections::recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Div)
        }
        "i256_rem_euclid" | "u256_rem_euclid" => {
            collections::recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Rem)
        }
        "i256_shl" | "u256_shl" => {
            collections::recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Shl)
        }
        "i256_shr" | "u256_shr" => {
            collections::recognize_u256_binop(call, pn, crn, crate::ir::BinOp::Shr)
        }
        "i256_pow" | "u256_pow" => {
            collections::recognize_u256_pow(call, pn, crn)
        }

        // TTL / bump operations
        "extend_contract_data_ttl" => context::recognize_extend_ttl(call, pn, crn),
        "extend_current_contract_instance_and_code_ttl" => {
            context::recognize_extend_instance_ttl(call, pn, crn)
        }

        // Fail with error
        "fail_with_error" => context::recognize_fail(call, pn, crn),

        // Object comparison
        "obj_cmp" => {
            let a = resolve_arg(call.args.first()?, pn, crn);
            let b = resolve_arg(call.args.get(1)?, pn, crn);
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "cmp_result".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(a),
                    calls: vec![MethodCall { name: "cmp".into(), args: vec![Expr::Ref(Box::new(b))] }],
                },
            })
        }

        // BLS12-381 crypto operations
        "bls12_381_check_g1_is_in_subgroup"
        | "bls12_381_g1_add" | "bls12_381_g1_mul"
        | "bls12_381_g1_msm" | "bls12_381_g1_neg"
        | "bls12_381_check_g2_is_in_subgroup"
        | "bls12_381_g2_add" | "bls12_381_g2_mul"
        | "bls12_381_g2_msm" | "bls12_381_g2_neg"
        | "bls12_381_map_fp_to_g1" | "bls12_381_map_fp2_to_g2"
        | "bls12_381_hash_to_g1" | "bls12_381_hash_to_g2"
        | "bls12_381_multi_pairing_check" => {
            let func_name = name.strip_prefix("bls12_381_").unwrap_or(name);
            let method_args: Vec<Expr> = call.args.iter()
                .map(|a| resolve_arg(a, pn, crn))
                .collect();
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| func_name.replace("_to_", "_").into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(Expr::Var("env".into())),
                    calls: vec![
                        MethodCall { name: "crypto".into(), args: vec![] },
                        MethodCall { name: func_name.into(), args: method_args },
                    ],
                },
            })
        }

        // BN254 crypto operations
        "bn254_check_g1_is_in_subgroup"
        | "bn254_g1_add" | "bn254_g1_mul"
        | "bn254_g1_msm" | "bn254_g1_neg"
        | "bn254_check_g2_is_in_subgroup"
        | "bn254_g2_add" | "bn254_g2_mul"
        | "bn254_g2_msm" | "bn254_g2_neg"
        | "bn254_map_fp_to_g1" | "bn254_map_fp2_to_g2"
        | "bn254_hash_to_g1" | "bn254_hash_to_g2"
        | "bn254_multi_pairing_check" => {
            let func_name = name.strip_prefix("bn254_").unwrap_or(name);
            let method_args: Vec<Expr> = call.args.iter()
                .map(|a| resolve_arg(a, pn, crn))
                .collect();
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| func_name.replace("_to_", "_").into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(Expr::Var("env".into())),
                    calls: vec![
                        MethodCall { name: "crypto".into(), args: vec![] },
                        MethodCall { name: func_name.into(), args: method_args },
                    ],
                },
            })
        }

        // Generic multi_pairing_check (non-prefixed)
        "multi_pairing_check" => {
            let args: Vec<Expr> = call.args.iter()
                .map(|a| resolve_arg(a, pn, crn))
                .collect();
            Some(Statement::Let {
                name: crn.get(&call.call_site_id).cloned().unwrap_or_else(|| "multi_pairing_check".into()),
                mutable: false,
                value: Expr::MethodChain {
                    receiver: Box::new(Expr::Var("env".into())),
                    calls: vec![
                        MethodCall { name: "crypto".into(), args: vec![] },
                        MethodCall { name: "multi_pairing_check".into(), args },
                    ],
                },
            })
        }

        _ => None,
    }
}
