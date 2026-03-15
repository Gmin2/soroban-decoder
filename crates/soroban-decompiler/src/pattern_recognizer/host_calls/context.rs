use std::collections::HashMap;

use walrus::ir::Value;

use crate::ir::{Expr, MethodCall, Statement};
use crate::wasm_analysis::{StackValue, TrackedHostCall};

use super::super::RecognitionContext;
use super::super::val_decoding::{strip_val_boilerplate, try_decode_symbol_small, resolve_arg, as_ref};
use super::storage::extract_storage_tier;

/// Recognize `contract_event(topics, data)` -> event struct publish or raw publish.
///
/// Attempts to match the topics vec against `ScSpecEntry::EventV0` to produce
/// `EventName { field: data }.publish(&env)`. Falls back to raw
/// `env.events().publish(topics, data)`.
pub(super) fn recognize_event(
    call: &TrackedHostCall,
    ctx: &RecognitionContext,
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let pn = &ctx.param_names;

    // Try to decode the event name from the topics vec.
    // topics arg is typically CallResult(id) from a vec_new_from_linear_memory.
    if let Some(StackValue::CallResult(topics_id)) = call.args.first() {
        // Try vec_contents first, then fall back to nearby memory_strings.
        let event_name = if let Some(elements) = ctx.vec_contents.get(topics_id) {
            elements.first().and_then(|first| {
                let first_stripped = strip_val_boilerplate(first);
                match &first_stripped {
                    StackValue::Const(Value::I64(v)) => try_decode_symbol_small(*v),
                    StackValue::CallResult(cid) => ctx.memory_strings.get(cid).cloned(),
                    _ => None,
                }
            })
        } else {
            // Fallback: find the nearest symbol_new_from_linear_memory
            // result before the topics vec call.
            let mut found = None;
            for check_id in (topics_id.saturating_sub(5)..*topics_id).rev() {
                if let Some(s) = ctx.memory_strings.get(&check_id) {
                    found = Some(s.clone());
                    break;
                }
            }
            found
        };

        if let Some(ename) = event_name {
            // Search for matching EventV0 spec entry.
            for entry in ctx.all_entries {
                if let stellar_xdr::curr::ScSpecEntry::EventV0(ev) = entry {
                    if ev.name.to_utf8_string_lossy() == ename {
                        let data_expr = resolve_arg(call.args.get(1)?, pn, crn);
                        let fields: Vec<(String, Expr)> = ev.params.iter()
                            .filter(|p| matches!(
                                p.location,
                                stellar_xdr::curr::ScSpecEventParamLocationV0::Data,
                            ))
                            .map(|p| (p.name.to_utf8_string_lossy(), data_expr.clone()))
                            .collect();
                        let event_struct = if fields.len() == 1 {
                            Expr::StructLiteral { name: ename.clone(), fields }
                        } else {
                            Expr::StructLiteral {
                                name: ename.clone(),
                                fields: vec![("data".into(), data_expr)],
                            }
                        };
                        return Some(Statement::Expr(Expr::MethodChain {
                            receiver: Box::new(event_struct),
                            calls: vec![MethodCall {
                                name: "publish".into(),
                                args: vec![Expr::Var("&env".into())],
                            }],
                        }));
                    }
                }
            }
        }
    }

    // Fallback: raw event publish.
    let topics = resolve_arg(call.args.first()?, pn, crn);
    let data = resolve_arg(call.args.get(1)?, pn, crn);

    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![
            MethodCall { name: "events".into(), args: vec![] },
            MethodCall { name: "publish".into(), args: vec![topics, data] },
        ],
    }))
}

/// Recognize `call(contract, func, args)` -> `env.invoke_contract(&addr, func, args)`
pub(super) fn recognize_cross_contract_call(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
    ctx: &RecognitionContext,
) -> Option<Statement> {
    let addr = as_ref(resolve_arg(call.args.first()?, param_names, crn));
    let func = resolve_arg(call.args.get(1)?, param_names, crn);
    let args_expr = resolve_arg(call.args.get(2)?, param_names, crn);

    // Detect token client calls by checking if the function name is a known
    // token interface method. If so, emit `token::Client::new(&env, &addr).method(args...)`
    // instead of the generic `env.invoke_contract(...)`.
    let token_method = extract_token_method_name(&func);
    if let Some(method_name) = token_method {
        // Resolve the vec contents to get individual arguments.
        let vec_args = extract_vec_call_args(call.args.get(2)?, ctx, param_names, crn);

        let client = Expr::MethodChain {
            receiver: Box::new(Expr::HostCall {
                module: "token::Client".into(),
                name: "new".into(),
                args: vec![Expr::Var("&env".into()), addr],
            }),
            calls: vec![MethodCall {
                name: method_name.into(),
                args: vec_args.iter().map(|a| as_ref(a.clone())).collect(),
            }],
        };

        return Some(Statement::Let {
            name: "result".into(),
            mutable: false,
            value: client,
        });
    }

    // Try to emit as a typed client call: Client::new(&env, &addr).method(&args)
    if let Some(method_name) = extract_symbol_name(&func) {
        let vec_args = extract_vec_call_args(call.args.get(2)?, ctx, param_names, crn);
        let client_call = Expr::MethodChain {
            receiver: Box::new(Expr::HostCall {
                module: "contract_client".into(),
                name: "new".into(),
                args: vec![Expr::Var("&env".into()), addr.clone()],
            }),
            calls: vec![MethodCall {
                name: method_name.clone(),
                args: vec_args.iter().map(|a| as_ref(a.clone())).collect(),
            }],
        };
        return Some(Statement::Let {
            name: "result".into(),
            mutable: false,
            value: client_call,
        });
    }

    Some(Statement::Let {
        name: "result".into(),
        mutable: false,
        value: Expr::MethodChain {
            receiver: Box::new(Expr::Var("env".into())),
            calls: vec![MethodCall {
                name: "invoke_contract".into(),
                args: vec![addr, func, args_expr],
            }],
        },
    })
}

/// Check if an expression is a known token interface method name.
fn extract_token_method_name(func_expr: &Expr) -> Option<&'static str> {
    match func_expr {
        Expr::MacroCall { name, args } if name == "symbol_short" => {
            if let Some(Expr::Literal(crate::ir::Literal::Str(s))) = args.first() {
                match s.as_str() {
                    "transfer" => Some("transfer"),
                    "burn" => Some("burn"),
                    "approve" => Some("approve"),
                    "balance" => Some("balance"),
                    "decimals" => Some("decimals"),
                    "name" => Some("name"),
                    "symbol" => Some("symbol"),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract the string value from a symbol_short!("name") expression.
fn extract_symbol_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MacroCall { name, args } if name == "symbol_short" => {
            if let Some(Expr::Literal(crate::ir::Literal::Str(s))) = args.first() {
                Some(s.clone())
            } else {
                None
            }
        }
        Expr::Literal(crate::ir::Literal::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

/// Extract individual arguments from a vec CallResult for token client calls.
fn extract_vec_call_args(
    vec_sv: &StackValue,
    ctx: &RecognitionContext,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Vec<Expr> {
    // The vec arg is typically a CallResult pointing to a vec_new_from_linear_memory.
    // The vec elements are the user arguments to the token method (from, to,
    // amount, etc.). They never include &env — the SDK compiler uses env for
    // the vec construction machinery but does not store it as an element.
    if let StackValue::CallResult(vec_id) = strip_val_boilerplate(vec_sv) {
        if let Some(elements) = ctx.vec_contents.get(&vec_id) {
            return elements.iter().map(|el| {
                let stripped = strip_val_boilerplate(el);
                resolve_arg(&stripped, param_names, crn)
            }).collect();
        }
    }
    vec![]
}

/// Recognize `extend_contract_data_ttl(key, type, threshold, extend_to)`
/// -> `env.storage().{tier}().extend_ttl(&key, threshold, extend_to)`
pub(super) fn recognize_extend_ttl(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let key_expr = as_ref(resolve_arg(call.args.first()?, param_names, crn));
    let tier = extract_storage_tier(call.args.get(1)?)?;
    let threshold = resolve_arg(call.args.get(2)?, param_names, crn);
    let extend_to = resolve_arg(call.args.get(3)?, param_names, crn);

    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![
            MethodCall { name: "storage".into(), args: vec![] },
            MethodCall { name: tier.into(), args: vec![] },
            MethodCall { name: "extend_ttl".into(), args: vec![key_expr, threshold, extend_to] },
        ],
    }))
}

/// Recognize `extend_current_contract_instance_and_code_ttl(threshold, extend_to)`
/// -> `env.storage().instance().extend_ttl(threshold, extend_to)`
pub(super) fn recognize_extend_instance_ttl(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let threshold = resolve_arg(call.args.first()?, param_names, crn);
    let extend_to = resolve_arg(call.args.get(1)?, param_names, crn);

    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![
            MethodCall { name: "storage".into(), args: vec![] },
            MethodCall { name: "instance".into(), args: vec![] },
            MethodCall { name: "extend_ttl".into(), args: vec![threshold, extend_to] },
        ],
    }))
}

/// Recognize `fail_with_error(error)` -> `panic!("{error}")`
pub(super) fn recognize_fail(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let error = resolve_arg(call.args.first()?, param_names, crn);
    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![MethodCall {
            name: "panic_with_error".into(),
            args: vec![error],
        }],
    }))
}
