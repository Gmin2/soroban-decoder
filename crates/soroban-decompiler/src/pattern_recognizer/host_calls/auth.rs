use std::collections::HashMap;

use crate::ir::{Expr, MethodCall, Statement};
use crate::wasm_analysis::{StackValue, TrackedHostCall};

use super::super::RecognitionContext;
use super::super::val_decoding::{strip_val_boilerplate, resolve_arg};
use super::collections::try_merge_i128_pair;

/// Recognize `require_auth(addr)` -> `{addr}.require_auth()`
pub(super) fn recognize_require_auth(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let addr_expr = resolve_arg(call.args.first()?, param_names, crn);
    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(addr_expr),
        calls: vec![MethodCall { name: "require_auth".into(), args: vec![] }],
    }))
}

/// Recognize `require_auth_for_args(addr, args_vec)` -> `{addr}.require_auth_for_args(args)`
pub(super) fn recognize_require_auth_for_args(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
    ctx: &RecognitionContext,
) -> Option<Statement> {
    let addr_expr = resolve_arg(call.args.first()?, param_names, crn);

    // The second arg is a Vec (CallResult from vec_new_from_linear_memory).
    // Try to resolve it as a tuple of arguments.
    let args_val = call.args.get(1)?;
    let args_expr = if let StackValue::CallResult(vec_id) = args_val {
        if let Some(elements) = ctx.vec_contents.get(vec_id) {
            // Build the args as a tuple expression from vec elements.
            let mut elem_exprs: Vec<Expr> = Vec::new();
            let mut i = 0;
            while i < elements.len() {
                if i + 1 < elements.len() {
                    if let Some(merged) = try_merge_i128_pair(&elements[i], &elements[i + 1]) {
                        let stripped = strip_val_boilerplate(&merged);
                        elem_exprs.push(resolve_arg(&stripped, param_names, crn));
                        i += 2;
                        continue;
                    }
                }
                let stripped = strip_val_boilerplate(&elements[i]);
                elem_exprs.push(resolve_arg(&stripped, param_names, crn));
                i += 1;
            }
            // Render as args tuple.
            Expr::MacroCall {
                name: "vec".into(),
                args: std::iter::once(Expr::Var("&env".into()))
                    .chain(elem_exprs)
                    .collect(),
            }
        } else {
            resolve_arg(args_val, param_names, crn)
        }
    } else {
        resolve_arg(args_val, param_names, crn)
    };

    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(addr_expr),
        calls: vec![MethodCall {
            name: "require_auth_for_args".into(),
            args: vec![args_expr],
        }],
    }))
}
