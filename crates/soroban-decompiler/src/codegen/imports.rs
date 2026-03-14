//! Import collection for generated Rust code.
//!
//! Walks spec type trees and IR expression trees to determine which SDK
//! types and macros need to be imported in the generated `use soroban_sdk::{...}`.

use stellar_xdr::curr::ScSpecTypeDef;

use crate::ir;

/// Walks an [`ScSpecTypeDef`] tree and inserts any SDK type names that require an import.
pub(super) fn collect_sdk_types(
    spec: &ScSpecTypeDef,
    types: &mut std::collections::BTreeSet<String>,
) {
    match spec {
        ScSpecTypeDef::Symbol => { types.insert("Symbol".into()); }
        ScSpecTypeDef::Bytes => { types.insert("Bytes".into()); }
        ScSpecTypeDef::Address => { types.insert("Address".into()); }
        ScSpecTypeDef::MuxedAddress => { types.insert("MuxedAddress".into()); }
        ScSpecTypeDef::String => { types.insert("String".into()); }
        ScSpecTypeDef::Timepoint => { types.insert("Timepoint".into()); }
        ScSpecTypeDef::Duration => { types.insert("Duration".into()); }
        ScSpecTypeDef::U256 => { types.insert("U256".into()); }
        ScSpecTypeDef::I256 => { types.insert("I256".into()); }
        ScSpecTypeDef::BytesN(_) => { types.insert("BytesN".into()); }
        ScSpecTypeDef::Vec(v) => {
            types.insert("Vec".into());
            collect_sdk_types(&v.element_type, types);
        }
        ScSpecTypeDef::Map(m) => {
            types.insert("Map".into());
            collect_sdk_types(&m.key_type, types);
            collect_sdk_types(&m.value_type, types);
        }
        ScSpecTypeDef::Option(o) => {
            collect_sdk_types(&o.value_type, types);
        }
        ScSpecTypeDef::Result(r) => {
            collect_sdk_types(&r.ok_type, types);
            collect_sdk_types(&r.error_type, types);
        }
        ScSpecTypeDef::Tuple(t) => {
            for ty in t.value_types.iter() {
                collect_sdk_types(ty, types);
            }
        }
        _ => {}
    }
}

/// Collect UDT (user-defined type) name references from a type definition tree.
///
/// Used to detect external types like `Context` that come from the SDK
/// rather than the contract's own type definitions.
pub(super) fn collect_udt_refs(spec: &ScSpecTypeDef, udts: &mut std::collections::BTreeSet<String>) {
    match spec {
        ScSpecTypeDef::Udt(u) => { udts.insert(u.name.to_utf8_string_lossy()); }
        ScSpecTypeDef::Vec(v) => collect_udt_refs(&v.element_type, udts),
        ScSpecTypeDef::Map(m) => {
            collect_udt_refs(&m.key_type, udts);
            collect_udt_refs(&m.value_type, udts);
        }
        ScSpecTypeDef::Option(o) => collect_udt_refs(&o.value_type, udts),
        ScSpecTypeDef::Result(r) => {
            collect_udt_refs(&r.ok_type, udts);
            collect_udt_refs(&r.error_type, udts);
        }
        ScSpecTypeDef::Tuple(t) => {
            for ty in t.value_types.iter() { collect_udt_refs(ty, udts); }
        }
        _ => {}
    }
}

/// Scan an IR statement for types/macros that need importing.
pub(super) fn collect_ir_imports_stmt(stmt: &ir::Statement, imports: &mut std::collections::BTreeSet<String>) {
    match stmt {
        ir::Statement::Let { value, .. } => collect_ir_imports_expr(value, imports),
        ir::Statement::Assign { target, value } => {
            collect_ir_imports_expr(target, imports);
            collect_ir_imports_expr(value, imports);
        }
        ir::Statement::Expr(e) => collect_ir_imports_expr(e, imports),
        ir::Statement::Return(Some(e)) => collect_ir_imports_expr(e, imports),
        ir::Statement::Return(None) => {}
        ir::Statement::If { condition, then_body, else_body } => {
            collect_ir_imports_expr(condition, imports);
            for s in then_body { collect_ir_imports_stmt(s, imports); }
            for s in else_body { collect_ir_imports_stmt(s, imports); }
        }
        ir::Statement::While { condition, body } => {
            collect_ir_imports_expr(condition, imports);
            for s in body { collect_ir_imports_stmt(s, imports); }
        }
        ir::Statement::Loop { body } => {
            for s in body { collect_ir_imports_stmt(s, imports); }
        }
        ir::Statement::ForEach { collection, body, .. } => {
            collect_ir_imports_expr(collection, imports);
            for s in body { collect_ir_imports_stmt(s, imports); }
        }
        ir::Statement::ForRange { bound, body, .. } => {
            collect_ir_imports_expr(bound, imports);
            for s in body { collect_ir_imports_stmt(s, imports); }
        }
    }
}

/// Scan an IR expression for types/macros that need importing.
pub(super) fn collect_ir_imports_expr(expr: &ir::Expr, imports: &mut std::collections::BTreeSet<String>) {
    match expr {
        ir::Expr::MacroCall { name, args } => {
            if name == "symbol_short" || name == "vec" {
                imports.insert(name.clone());
            }
            for a in args { collect_ir_imports_expr(a, imports); }
        }
        ir::Expr::HostCall { module, args, .. } => {
            match module.as_str() {
                "Symbol" | "String" | "Map" | "Vec" | "Bytes" | "BytesN"
                | "Address" => { imports.insert(module.clone()); }
                _ => {}
            }
            for a in args { collect_ir_imports_expr(a, imports); }
        }
        ir::Expr::MethodChain { receiver, calls } => {
            collect_ir_imports_expr(receiver, imports);
            for c in calls {
                for a in &c.args { collect_ir_imports_expr(a, imports); }
            }
        }
        ir::Expr::BinOp { left, right, .. } => {
            collect_ir_imports_expr(left, imports);
            collect_ir_imports_expr(right, imports);
        }
        ir::Expr::UnOp { operand, .. } => collect_ir_imports_expr(operand, imports),
        ir::Expr::StructLiteral { fields, .. } => {
            for (_, v) in fields { collect_ir_imports_expr(v, imports); }
        }
        ir::Expr::EnumVariant { fields, .. } => {
            for f in fields { collect_ir_imports_expr(f, imports); }
        }
        ir::Expr::Ref(inner) => collect_ir_imports_expr(inner, imports),
        ir::Expr::Literal(_) | ir::Expr::Var(_) | ir::Expr::Raw(_) => {}
    }
}
