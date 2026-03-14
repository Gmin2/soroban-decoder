use std::collections::HashMap;

use crate::ir::{Expr, MethodCall, Statement};
use crate::wasm_analysis::TrackedHostCall;

use super::super::val_decoding::{resolve_arg, as_ref};

/// Recognize `verify_sig_ed25519(pk, msg, sig)` -> `env.crypto().ed25519_verify(&pk, &msg, &sig)`
pub(super) fn recognize_ed25519_verify(
    call: &TrackedHostCall,
    param_names: &[String],
    crn: &HashMap<usize, String>,
) -> Option<Statement> {
    let pk = as_ref(resolve_arg(call.args.first()?, param_names, crn));
    let msg = as_ref(resolve_arg(call.args.get(1)?, param_names, crn));
    let sig = as_ref(resolve_arg(call.args.get(2)?, param_names, crn));

    Some(Statement::Expr(Expr::MethodChain {
        receiver: Box::new(Expr::Var("env".into())),
        calls: vec![
            MethodCall { name: "crypto".into(), args: vec![] },
            MethodCall { name: "ed25519_verify".into(), args: vec![pk, msg, sig] },
        ],
    }))
}
