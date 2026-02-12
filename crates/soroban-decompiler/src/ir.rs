//! High-level intermediate representation for decompiled Soroban contracts.
//!
//! These types bridge the gap between raw WASM bytecode and idiomatic Rust
//! source code. The pattern recognizer ([`crate::pattern_recognizer`])
//! populates this IR from WASM analysis results, and the code generator
//! ([`crate::codegen`]) emits formatted Rust source from it.
//!
//! The IR is deliberately simple: a function body is a flat list of
//! [`Statement`]s, each containing [`Expr`] trees. There is no SSA form or
//! phi nodes -- the representation is close to what the final Rust output
//! looks like. Control flow is represented structurally through
//! [`Statement::If`], [`Statement::While`], and [`Statement::Loop`] rather
//! than as a CFG.

/// A decompiled function body ready for code generation.
///
/// Produced by [`crate::pattern_recognizer::recognize`] and consumed by
/// [`crate::codegen::generate_rust`].
#[derive(Debug, Clone)]
pub struct FunctionIR {
    /// The function's export name (e.g. `"increment"`, `"hello"`).
    pub name: String,
    /// Ordered list of statements forming the function body.
    pub body: Vec<Statement>,
}

/// A statement in a decompiled function body.
///
/// Statements are the top-level units of a function body. Each variant maps
/// directly to a Rust syntax construct.
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    /// A local variable binding: `let [mut] name = value;`
    Let {
        /// Variable name (may contain dots for field paths like `state.count`).
        name: String,
        /// Whether the binding is mutable.
        mutable: bool,
        /// The initializer expression.
        value: Expr,
    },
    /// An assignment: `target = value;`
    Assign {
        /// The left-hand side (typically a [`Expr::Var`]).
        target: Expr,
        /// The right-hand side expression.
        value: Expr,
    },
    /// A bare expression used as a statement (e.g. a method call with no
    /// return value like `env.storage().instance().set(...)`).
    Expr(Expr),
    /// An explicit return: `return expr;` or bare `return;`
    Return(Option<Expr>),
    /// A conditional branch: `if condition { ... } else { ... }`
    If {
        /// The boolean condition expression.
        condition: Expr,
        /// Statements executed when the condition is true.
        then_body: Vec<Statement>,
        /// Statements executed when the condition is false (may be empty).
        else_body: Vec<Statement>,
    },
    /// A while loop: `while condition { ... }`
    While {
        /// The loop condition.
        condition: Expr,
        /// The loop body.
        body: Vec<Statement>,
    },
    /// An unconditional loop: `loop { ... }`
    Loop {
        /// The loop body.
        body: Vec<Statement>,
    },
}

/// An expression in the decompiled IR.
///
/// Expressions form trees that represent computations. They are used both as
/// statement initializers (in [`Statement::Let`]) and as sub-expressions
/// within other expressions (e.g. arguments to method calls).
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// A constant value (integer, float, boolean, or string).
    Literal(Literal),
    /// A variable reference by name.
    ///
    /// Names may contain dots (e.g. `"state.count"`) to represent field
    /// access paths, and may be prefixed with `&` to indicate a reference.
    /// The code generator handles both cases.
    Var(String),
    /// A resolved host function call (before SDK idiom lifting).
    ///
    /// These appear when the pattern recognizer cannot map a host call to
    /// a higher-level SDK operation.
    HostCall {
        /// The host function's module name (e.g. `"ledger"`).
        module: String,
        /// The host function's semantic name (e.g. `"get_contract_data"`).
        name: String,
        /// Resolved argument expressions.
        args: Vec<Expr>,
    },
    /// A method chain like `env.storage().persistent().set(&key, &val)`.
    ///
    /// This is the primary representation for recognized Soroban SDK
    /// operations. The receiver is typically `Expr::Var("env")` and the
    /// calls list contains each chained method.
    MethodChain {
        /// The object the chain starts from.
        receiver: Box<Expr>,
        /// Ordered list of method calls in the chain.
        calls: Vec<MethodCall>,
    },
    /// A binary operation like `a + b` or `count == 0`.
    BinOp {
        /// Left operand.
        left: Box<Expr>,
        /// The operator.
        op: BinOp,
        /// Right operand.
        right: Box<Expr>,
    },
    /// A unary operation like `-x` or `!flag`.
    UnOp {
        /// The operator.
        op: UnOp,
        /// The operand.
        operand: Box<Expr>,
    },
    /// A macro invocation like `symbol_short!("name")` or `vec!(&env, a, b)`.
    MacroCall {
        /// Macro name without the trailing `!`.
        name: String,
        /// Arguments to the macro.
        args: Vec<Expr>,
    },
    /// A struct literal: `StructName { field1: val1, field2: val2 }`.
    StructLiteral {
        /// The struct type name.
        name: String,
        /// Field name-value pairs in definition order.
        fields: Vec<(String, Expr)>,
    },
    /// An enum variant: `EnumName::Variant(val)` or `EnumName::Variant`.
    EnumVariant {
        /// The enum type name.
        enum_name: String,
        /// The variant name.
        variant_name: String,
        /// Tuple fields (empty for unit variants).
        fields: Vec<Expr>,
    },
    /// An unrecognized WASM pattern preserved as a descriptive string.
    ///
    /// These render as `todo!("description")` in the generated code and
    /// indicate patterns the decompiler could not resolve.
    Raw(String),
}

/// A single method call in a [`Expr::MethodChain`].
#[derive(Debug, Clone, PartialEq)]
pub struct MethodCall {
    /// The method name (e.g. `"storage"`, `"persistent"`, `"set"`).
    pub name: String,
    /// Arguments passed to the method.
    pub args: Vec<Expr>,
}

/// A constant literal value.
#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    /// A 32-bit signed integer.
    I32(i32),
    /// A 64-bit signed integer.
    I64(i64),
    /// A 32-bit floating-point number.
    F32(f32),
    /// A 64-bit floating-point number.
    F64(f64),
    /// A boolean value.
    Bool(bool),
    /// A string literal (used for symbol names, storage keys, etc.).
    Str(String),
}

/// Binary operators supported in the IR.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinOp {
    /// Addition (`+`).
    Add,
    /// Subtraction (`-`).
    Sub,
    /// Multiplication (`*`).
    Mul,
    /// Division (`/`).
    Div,
    /// Remainder (`%`).
    Rem,
    /// Bitwise AND (`&`).
    BitAnd,
    /// Bitwise OR (`|`).
    BitOr,
    /// Bitwise XOR (`^`).
    BitXor,
    /// Left shift (`<<`).
    Shl,
    /// Right shift (`>>`).
    Shr,
    /// Equality (`==`).
    Eq,
    /// Inequality (`!=`).
    Ne,
    /// Less than (`<`).
    Lt,
    /// Less than or equal (`<=`).
    Le,
    /// Greater than (`>`).
    Gt,
    /// Greater than or equal (`>=`).
    Ge,
}

/// Unary operators supported in the IR.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnOp {
    /// Arithmetic negation (`-x`).
    Neg,
    /// Logical/bitwise NOT (`!x`).
    Not,
}
