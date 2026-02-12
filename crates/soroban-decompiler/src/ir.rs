/// High-level intermediate representation for decompiled Soroban contract functions.
///
/// These types bridge the gap between raw WASM instructions and idiomatic Rust code.
/// The pattern recognizer populates this IR from WASM analysis results, and the
/// code generator emits Rust source from it.

/// A decompiled function body ready for code generation.
#[derive(Debug, Clone)]
pub struct FunctionIR {
    pub name: String,
    pub body: Vec<Statement>,
}

/// A statement in a decompiled function body.
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    /// `let [mut] name = value;`
    Let {
        name: String,
        mutable: bool,
        value: Expr,
    },
    /// `target = value;`
    Assign {
        target: Expr,
        value: Expr,
    },
    /// A bare expression used as a statement.
    Expr(Expr),
    /// `return expr;` or bare `return;`
    Return(Option<Expr>),
    /// `if condition { ... } else { ... }`
    If {
        condition: Expr,
        then_body: Vec<Statement>,
        else_body: Vec<Statement>,
    },
    /// `while condition { ... }`
    While {
        condition: Expr,
        body: Vec<Statement>,
    },
    /// `loop { ... }`
    Loop {
        body: Vec<Statement>,
    },
}

/// An expression in the decompiled IR.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// A constant value.
    Literal(Literal),
    /// A variable reference.
    Var(String),
    /// A resolved host function call (before SDK idiom lifting).
    HostCall {
        module: String,
        name: String,
        args: Vec<Expr>,
    },
    /// A method chain like `env.storage().persistent().set(&key, &val)`.
    MethodChain {
        receiver: Box<Expr>,
        calls: Vec<MethodCall>,
    },
    /// A binary operation.
    BinOp {
        left: Box<Expr>,
        op: BinOp,
        right: Box<Expr>,
    },
    /// A unary operation.
    UnOp {
        op: UnOp,
        operand: Box<Expr>,
    },
    /// A macro invocation like `symbol_short!("name")`.
    MacroCall {
        name: String,
        args: Vec<Expr>,
    },
    /// A struct literal: `StructName { field1: val1, field2: val2 }`.
    StructLiteral {
        name: String,
        fields: Vec<(String, Expr)>,
    },
    /// An enum variant: `EnumName::Variant(val1, val2)` or `EnumName::Variant`.
    EnumVariant {
        enum_name: String,
        variant_name: String,
        fields: Vec<Expr>,
    },
    /// Unrecognized WASM pattern preserved as a description.
    Raw(String),
}

/// A single method call in a chain.
#[derive(Debug, Clone, PartialEq)]
pub struct MethodCall {
    pub name: String,
    pub args: Vec<Expr>,
}

/// A constant literal value.
#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Bool(bool),
    Str(String),
}

/// Binary operations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// Unary operations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnOp {
    Neg,
    Not,
}
