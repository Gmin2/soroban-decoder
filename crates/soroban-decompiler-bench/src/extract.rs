use anyhow::{Context, Result};
use serde::Serialize;
use syn::{
    Expr, File, FnArg, GenericArgument, ImplItem, Item, Pat, PathArguments,
    ReturnType, Stmt, Type,
};

/// Extracted AST of a contract source file.
#[derive(Debug, Clone, Serialize)]
pub struct ContractAst {
    pub struct_name: Option<String>,
    pub functions: Vec<FunctionAst>,
    pub structs: Vec<StructDef>,
    pub enums: Vec<EnumDef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionAst {
    pub name: String,
    pub params: Vec<ParamDef>,
    pub return_type: String,
    pub body: Vec<StmtShape>,
    pub body_source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParamDef {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<FieldDef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldDef {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnumDef {
    pub name: String,
    pub variants: Vec<VariantDef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VariantDef {
    pub name: String,
    pub fields: Vec<String>,
}

/// Simplified statement shape for structural comparison.
/// We don't compare exact expressions — we compare the *shape* of the code.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum StmtShape {
    /// `let name = <expr_shape>;`
    Let {
        mutable: bool,
        has_type_annotation: bool,
        value: ExprShape,
    },
    /// Expression statement (method call, function call, etc.)
    Expr(ExprShape),
    /// `return <expr>;` or trailing expression
    Return(Option<ExprShape>),
    /// `if cond { ... } else { ... }`
    If {
        then_count: usize,
        else_count: usize,
    },
    /// `for _ in _ { ... }`
    ForLoop { body_count: usize },
    /// `while cond { ... }`
    WhileLoop { body_count: usize },
    /// `loop { ... }`
    Loop { body_count: usize },
    /// Anything we can't classify
    Other,
}

/// Simplified expression shape.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum ExprShape {
    /// `receiver.method1().method2()...` — the core of Soroban SDK calls
    MethodChain(Vec<String>),
    /// `func(args...)` or `Type::func(args...)`
    FnCall(String),
    /// `Struct { field: val, ... }`
    StructLit(String),
    /// `Enum::Variant(...)` or `Enum::Variant`
    EnumVariant(String),
    /// `macro!(...)` e.g. vec!, symbol_short!
    Macro(String),
    /// Binary operation: `a + b`, `a >= b`
    BinOp(String),
    /// Variable or path reference
    Path(String),
    /// Literal value
    Literal,
    /// `Default::default()` or `todo!()`
    Placeholder,
    /// `x += expr` or `x = expr` — mutation, often folded by compiler
    Assign,
    /// Anything else
    Other,
}

pub fn parse(source: &str) -> Result<ContractAst> {
    let file: File =
        syn::parse_str(source).context("Failed to parse Rust source with syn")?;

    let mut ast = ContractAst {
        struct_name: None,
        functions: Vec::new(),
        structs: Vec::new(),
        enums: Vec::new(),
    };

    for item in &file.items {
        match item {
            Item::Struct(s) => {
                let has_contract_attr = s.attrs.iter().any(|a| {
                    a.path()
                        .segments
                        .last()
                        .map_or(false, |seg| seg.ident == "contract")
                });
                if has_contract_attr {
                    ast.struct_name = Some(s.ident.to_string());
                } else {
                    ast.structs.push(extract_struct(s));
                }
            }
            Item::Enum(e) => {
                ast.enums.push(extract_enum(e));
            }
            Item::Impl(imp) => {
                for item in &imp.items {
                    if let ImplItem::Fn(method) = item {
                        ast.functions.push(extract_function(method));
                    }
                }
            }
            _ => {}
        }
    }

    Ok(ast)
}

fn extract_struct(s: &syn::ItemStruct) -> StructDef {
    let fields = match &s.fields {
        syn::Fields::Named(named) => named
            .named
            .iter()
            .map(|f| FieldDef {
                name: f.ident.as_ref().map_or("_".into(), |i| i.to_string()),
                ty: type_to_string(&f.ty),
            })
            .collect(),
        syn::Fields::Unnamed(unnamed) => unnamed
            .unnamed
            .iter()
            .enumerate()
            .map(|(i, f)| FieldDef {
                name: format!("_{i}"),
                ty: type_to_string(&f.ty),
            })
            .collect(),
        syn::Fields::Unit => vec![],
    };
    StructDef {
        name: s.ident.to_string(),
        fields,
    }
}

fn extract_enum(e: &syn::ItemEnum) -> EnumDef {
    let variants = e
        .variants
        .iter()
        .map(|v| {
            let fields = match &v.fields {
                syn::Fields::Named(named) => named
                    .named
                    .iter()
                    .map(|f| type_to_string(&f.ty))
                    .collect(),
                syn::Fields::Unnamed(unnamed) => unnamed
                    .unnamed
                    .iter()
                    .map(|f| type_to_string(&f.ty))
                    .collect(),
                syn::Fields::Unit => vec![],
            };
            VariantDef {
                name: v.ident.to_string(),
                fields,
            }
        })
        .collect();
    EnumDef {
        name: e.ident.to_string(),
        variants,
    }
}

fn extract_function(method: &syn::ImplItemFn) -> FunctionAst {
    let name = method.sig.ident.to_string();

    let params: Vec<ParamDef> = method
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(pat_type) => {
                let param_name = match pat_type.pat.as_ref() {
                    Pat::Ident(ident) => ident.ident.to_string(),
                    _ => "_".to_string(),
                };
                Some(ParamDef {
                    name: param_name,
                    ty: type_to_string(&pat_type.ty),
                })
            }
            FnArg::Receiver(_) => None,
        })
        .collect();

    let return_type = match &method.sig.output {
        ReturnType::Default => "()".to_string(),
        ReturnType::Type(_, ty) => type_to_string(ty),
    };

    let body: Vec<StmtShape> = method
        .block
        .stmts
        .iter()
        .map(stmt_to_shape)
        .collect();

    let body_source = method
        .block
        .stmts
        .iter()
        .map(|s| quote::quote!(#s).to_string())
        .collect::<Vec<_>>()
        .join("\n");

    FunctionAst {
        name,
        params,
        return_type,
        body,
        body_source,
    }
}

fn stmt_to_shape(stmt: &Stmt) -> StmtShape {
    match stmt {
        Stmt::Local(local) => {
            let mutable = local.pat.clone();
            let is_mut = matches!(&mutable, Pat::Ident(pi) if pi.mutability.is_some());
            let has_type = match &mutable {
                Pat::Type(_) => true,
                Pat::Ident(pi) => pi.subpat.is_some(),
                _ => false,
            };
            let value = local
                .init
                .as_ref()
                .map(|init| expr_to_shape(&init.expr))
                .unwrap_or(ExprShape::Other);
            StmtShape::Let {
                mutable: is_mut,
                has_type_annotation: has_type,
                value,
            }
        }
        Stmt::Expr(expr, _semi) => {
            // Check if this is a trailing expression (no semicolon = implicit return)
            if _semi.is_none() {
                StmtShape::Return(Some(expr_to_shape(expr)))
            } else {
                StmtShape::Expr(expr_to_shape(expr))
            }
        }
        Stmt::Item(_) => StmtShape::Other,
        Stmt::Macro(m) => {
            let name = m
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            StmtShape::Expr(ExprShape::Macro(name))
        }
    }
}

fn expr_to_shape(expr: &Expr) -> ExprShape {
    match expr {
        Expr::MethodCall(_mc) => {
            let mut chain = Vec::new();
            collect_method_chain(expr, &mut chain);
            chain.reverse();
            ExprShape::MethodChain(chain)
        }
        Expr::Call(call) => {
            let name = match call.func.as_ref() {
                Expr::Path(p) => path_to_string(&p.path),
                _ => "?".to_string(),
            };
            // Detect Default::default() and todo!()
            if name == "Default::default" {
                return ExprShape::Placeholder;
            }
            ExprShape::FnCall(name)
        }
        Expr::Struct(s) => ExprShape::StructLit(path_to_string(&s.path)),
        Expr::Path(p) => {
            let path_str = path_to_string(&p.path);
            // Check if it looks like an enum variant (e.g., DataKey::Counter)
            if path_str.contains("::") {
                ExprShape::EnumVariant(path_str)
            } else {
                ExprShape::Path(path_str)
            }
        }
        Expr::Macro(m) => {
            let name = m
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            if name == "todo" {
                ExprShape::Placeholder
            } else {
                ExprShape::Macro(name)
            }
        }
        Expr::Binary(b) => {
            let op = format!("{}", quote::quote!(#b.op));
            // Normalize operator token spacing
            let op = op.trim().to_string();
            ExprShape::BinOp(op)
        }
        Expr::Lit(_) => ExprShape::Literal,
        Expr::If(_) => ExprShape::Other,
        Expr::Block(_) => ExprShape::Other,
        Expr::Paren(p) => expr_to_shape(&p.expr),
        Expr::Reference(r) => expr_to_shape(&r.expr),
        Expr::Tuple(t) => {
            if t.elems.is_empty() {
                ExprShape::Literal // ()
            } else {
                ExprShape::Other
            }
        }
        Expr::Unary(u) => expr_to_shape(&u.expr),
        Expr::Field(f) => {
            // field access like `self.field`
            ExprShape::Path(quote::quote!(#f).to_string())
        }
        Expr::Index(_) => ExprShape::Other,
        Expr::Assign(_) => ExprShape::Assign,
        _ => ExprShape::Other,
    }
}

fn collect_method_chain(expr: &Expr, chain: &mut Vec<String>) {
    match expr {
        Expr::MethodCall(mc) => {
            chain.push(mc.method.to_string());
            collect_method_chain(&mc.receiver, chain);
        }
        Expr::Call(call) => {
            if let Expr::Path(p) = call.func.as_ref() {
                chain.push(path_to_string(&p.path));
            }
        }
        Expr::Path(p) => {
            chain.push(path_to_string(&p.path));
        }
        _ => {}
    }
}

fn type_to_string(ty: &Type) -> String {
    match ty {
        Type::Path(tp) => {
            let mut parts = Vec::new();
            for seg in &tp.path.segments {
                let name = seg.ident.to_string();
                match &seg.arguments {
                    PathArguments::None => parts.push(name),
                    PathArguments::AngleBracketed(args) => {
                        let inner: Vec<String> = args
                            .args
                            .iter()
                            .filter_map(|a| match a {
                                GenericArgument::Type(t) => Some(type_to_string(t)),
                                _ => None,
                            })
                            .collect();
                        if inner.is_empty() {
                            parts.push(name);
                        } else {
                            parts.push(format!("{}<{}>", name, inner.join(", ")));
                        }
                    }
                    PathArguments::Parenthesized(args) => {
                        let inner: Vec<String> =
                            args.inputs.iter().map(type_to_string).collect();
                        parts.push(format!("{}({})", name, inner.join(", ")));
                    }
                }
            }
            parts.join("::")
        }
        Type::Reference(r) => {
            let inner = type_to_string(&r.elem);
            if r.mutability.is_some() {
                format!("&mut {inner}")
            } else {
                format!("&{inner}")
            }
        }
        Type::Tuple(t) => {
            if t.elems.is_empty() {
                "()".to_string()
            } else {
                let inner: Vec<String> = t.elems.iter().map(type_to_string).collect();
                format!("({})", inner.join(", "))
            }
        }
        _ => quote::quote!(#ty).to_string(),
    }
}

fn path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|seg| {
            let name = seg.ident.to_string();
            match &seg.arguments {
                PathArguments::None => name,
                PathArguments::AngleBracketed(args) => {
                    let inner: Vec<String> = args
                        .args
                        .iter()
                        .map(|a| quote::quote!(#a).to_string())
                        .collect();
                    format!("{}<{}>", name, inner.join(", "))
                }
                _ => name,
            }
        })
        .collect::<Vec<_>>()
        .join("::")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hello_world() {
        let source = r#"
#![no_std]
use soroban_sdk::{contract, contractimpl, Env, String, Vec, vec};
#[contract]
pub struct Contract;
#[contractimpl]
impl Contract {
    pub fn hello(env: Env, to: String) -> Vec<String> {
        vec![&env, String::from_str(&env, "Hello"), to]
    }
}
"#;
        let ast = parse(source).unwrap();
        assert_eq!(ast.struct_name, Some("Contract".to_string()));
        assert_eq!(ast.functions.len(), 1);
        assert_eq!(ast.functions[0].name, "hello");
        assert_eq!(ast.functions[0].params.len(), 2);
        assert_eq!(ast.functions[0].params[0].name, "env");
        assert_eq!(ast.functions[0].params[0].ty, "Env");
        assert_eq!(ast.functions[0].return_type, "Vec<String>");
    }

    #[test]
    fn test_parse_enum() {
        let source = r#"
#[contracttype]
pub enum DataKey {
    Counter(Address),
    Admin,
}
"#;
        let ast = parse(source).unwrap();
        assert_eq!(ast.enums.len(), 1);
        assert_eq!(ast.enums[0].name, "DataKey");
        assert_eq!(ast.enums[0].variants.len(), 2);
        assert_eq!(ast.enums[0].variants[0].name, "Counter");
        assert_eq!(ast.enums[0].variants[0].fields, vec!["Address"]);
        assert_eq!(ast.enums[0].variants[1].name, "Admin");
        assert!(ast.enums[0].variants[1].fields.is_empty());
    }

    #[test]
    fn test_method_chain_shape() {
        let source = r#"
#[contract]
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env) -> u32 {
        env.storage().instance().get(&key).unwrap_or_default()
    }
}
"#;
        let ast = parse(source).unwrap();
        let body = &ast.functions[0].body;
        assert_eq!(body.len(), 1);
        match &body[0] {
            StmtShape::Return(Some(ExprShape::MethodChain(chain))) => {
                assert!(chain.contains(&"storage".to_string()));
                assert!(chain.contains(&"instance".to_string()));
                assert!(chain.contains(&"get".to_string()));
                assert!(chain.contains(&"unwrap_or_default".to_string()));
            }
            other => panic!("Expected method chain, got {other:?}"),
        }
    }
}
