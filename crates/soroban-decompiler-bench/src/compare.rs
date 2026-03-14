use serde::Serialize;

use crate::extract::{
    ContractAst, EnumDef, ExprShape, FunctionAst, ParamDef, StmtShape, StructDef,
};

/// Result of comparing two contract ASTs.
#[derive(Debug, Clone, Serialize)]
pub struct ContractComparison {
    pub type_comparisons: Vec<TypeComparison>,
    pub function_comparisons: Vec<FunctionComparison>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeComparison {
    pub name: String,
    pub kind: TypeKind,
    pub found: bool,
    /// 0.0 - 1.0: how similar the type definition is
    pub similarity: f64,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub enum TypeKind {
    Struct,
    Enum,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionComparison {
    pub name: String,
    pub found: bool,
    pub signature_score: SignatureScore,
    pub body_score: BodyScore,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureScore {
    /// 0.0 - 1.0
    pub overall: f64,
    pub param_count_match: bool,
    pub param_types_match: Vec<bool>,
    pub return_type_match: bool,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BodyScore {
    /// 0.0 - 1.0
    pub overall: f64,
    pub statement_count_orig: usize,
    pub statement_count_decomp: usize,
    /// Per-statement alignment results
    pub alignments: Vec<StmtAlignment>,
    pub placeholder_count: usize,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StmtAlignment {
    pub orig_index: Option<usize>,
    pub decomp_index: Option<usize>,
    pub similarity: f64,
    pub description: String,
}

/// Compare two contract ASTs and produce detailed comparison results.
pub fn compare_contracts(original: &ContractAst, decompiled: &ContractAst) -> ContractComparison {
    let type_comparisons = compare_types(original, decompiled);
    let function_comparisons = compare_functions(original, decompiled);

    ContractComparison {
        type_comparisons,
        function_comparisons,
    }
}

fn compare_types(original: &ContractAst, decompiled: &ContractAst) -> Vec<TypeComparison> {
    let mut results = Vec::new();

    // Compare structs
    for orig_struct in &original.structs {
        let decomp = decompiled.structs.iter().find(|s| s.name == orig_struct.name);
        results.push(compare_struct(orig_struct, decomp));
    }
    // Flag extra structs in decompiled that aren't in original
    for decomp_struct in &decompiled.structs {
        if !original.structs.iter().any(|s| s.name == decomp_struct.name) {
            results.push(TypeComparison {
                name: decomp_struct.name.clone(),
                kind: TypeKind::Struct,
                found: false,
                similarity: 0.0,
                details: vec!["Extra struct in decompiled output (not in original)".into()],
            });
        }
    }

    // Compare enums
    for orig_enum in &original.enums {
        let decomp = decompiled.enums.iter().find(|e| e.name == orig_enum.name);
        results.push(compare_enum(orig_enum, decomp));
    }
    for decomp_enum in &decompiled.enums {
        if !original.enums.iter().any(|e| e.name == decomp_enum.name) {
            results.push(TypeComparison {
                name: decomp_enum.name.clone(),
                kind: TypeKind::Enum,
                found: false,
                similarity: 0.0,
                details: vec!["Extra enum in decompiled output (not in original)".into()],
            });
        }
    }

    results
}

fn compare_struct(orig: &StructDef, decomp: Option<&StructDef>) -> TypeComparison {
    let Some(decomp) = decomp else {
        return TypeComparison {
            name: orig.name.clone(),
            kind: TypeKind::Struct,
            found: false,
            similarity: 0.0,
            details: vec!["Struct missing from decompiled output".into()],
        };
    };

    let mut details = Vec::new();
    let mut score_parts: Vec<f64> = Vec::new();

    if orig.fields.len() == decomp.fields.len() {
        score_parts.push(1.0);
    } else {
        score_parts.push(0.5);
        details.push(format!(
            "Field count mismatch: {} vs {}",
            orig.fields.len(),
            decomp.fields.len()
        ));
    }

    let total_fields = orig.fields.len().max(1);
    let mut matched_fields = 0;
    for orig_field in &orig.fields {
        if let Some(decomp_field) = decomp.fields.iter().find(|f| f.name == orig_field.name) {
            if normalize_type(&decomp_field.ty) == normalize_type(&orig_field.ty) {
                matched_fields += 1;
            } else {
                details.push(format!(
                    "Field '{}' type mismatch: {} vs {}",
                    orig_field.name, orig_field.ty, decomp_field.ty
                ));
                matched_fields += 1; // name match is still partial credit
            }
        } else {
            details.push(format!("Field '{}' missing", orig_field.name));
        }
    }

    let field_ratio = matched_fields as f64 / total_fields as f64;
    score_parts.push(field_ratio);

    let similarity = score_parts.iter().sum::<f64>() / score_parts.len() as f64;

    TypeComparison {
        name: orig.name.clone(),
        kind: TypeKind::Struct,
        found: true,
        similarity,
        details,
    }
}

fn compare_enum(orig: &EnumDef, decomp: Option<&EnumDef>) -> TypeComparison {
    let Some(decomp) = decomp else {
        return TypeComparison {
            name: orig.name.clone(),
            kind: TypeKind::Enum,
            found: false,
            similarity: 0.0,
            details: vec!["Enum missing from decompiled output".into()],
        };
    };

    let mut details = Vec::new();
    let total = orig.variants.len().max(1);
    let mut matched = 0;

    for orig_var in &orig.variants {
        if let Some(decomp_var) = decomp.variants.iter().find(|v| v.name == orig_var.name) {
            matched += 1;
            if orig_var.fields.len() != decomp_var.fields.len() {
                details.push(format!(
                    "Variant '{}' field count mismatch: {} vs {}",
                    orig_var.name,
                    orig_var.fields.len(),
                    decomp_var.fields.len()
                ));
            } else {
                // Compare field types
                for (i, (o, d)) in orig_var
                    .fields
                    .iter()
                    .zip(decomp_var.fields.iter())
                    .enumerate()
                {
                    if normalize_type(o) != normalize_type(d) {
                        details.push(format!(
                            "Variant '{}' field {i} type mismatch: {o} vs {d}",
                            orig_var.name
                        ));
                    }
                }
            }
        } else {
            details.push(format!("Variant '{}' missing", orig_var.name));
        }
    }

    let similarity = matched as f64 / total as f64;

    TypeComparison {
        name: orig.name.clone(),
        kind: TypeKind::Enum,
        found: true,
        similarity,
        details,
    }
}

fn compare_functions(
    original: &ContractAst,
    decompiled: &ContractAst,
) -> Vec<FunctionComparison> {
    let mut results = Vec::new();

    for orig_fn in &original.functions {
        let decomp = decompiled.functions.iter().find(|f| f.name == orig_fn.name);
        results.push(compare_function(orig_fn, decomp));
    }

    // Flag extra functions
    for decomp_fn in &decompiled.functions {
        if !original.functions.iter().any(|f| f.name == decomp_fn.name) {
            results.push(FunctionComparison {
                name: decomp_fn.name.clone(),
                found: false,
                signature_score: SignatureScore {
                    overall: 0.0,
                    param_count_match: false,
                    param_types_match: vec![],
                    return_type_match: false,
                    details: vec!["Extra function in decompiled (not in original)".into()],
                },
                body_score: BodyScore {
                    overall: 0.0,
                    statement_count_orig: 0,
                    statement_count_decomp: decomp_fn.body.len(),
                    alignments: vec![],
                    placeholder_count: 0,
                    details: vec![],
                },
            });
        }
    }

    results
}

fn compare_function(orig: &FunctionAst, decomp: Option<&FunctionAst>) -> FunctionComparison {
    let Some(decomp) = decomp else {
        return FunctionComparison {
            name: orig.name.clone(),
            found: false,
            signature_score: SignatureScore {
                overall: 0.0,
                param_count_match: false,
                param_types_match: vec![],
                return_type_match: false,
                details: vec!["Function missing from decompiled output".into()],
            },
            body_score: BodyScore {
                overall: 0.0,
                statement_count_orig: orig.body.len(),
                statement_count_decomp: 0,
                alignments: vec![],
                placeholder_count: 0,
                details: vec!["Function body entirely missing".into()],
            },
        };
    };

    let signature_score = compare_signatures(&orig.params, &orig.return_type, &decomp.params, &decomp.return_type);
    let body_score = compare_bodies(&orig.body, &decomp.body);

    FunctionComparison {
        name: orig.name.clone(),
        found: true,
        signature_score,
        body_score,
    }
}

fn compare_signatures(
    orig_params: &[ParamDef],
    orig_ret: &str,
    decomp_params: &[ParamDef],
    decomp_ret: &str,
) -> SignatureScore {
    let mut details = Vec::new();

    // Normalize params: decompiler always includes `env: Env` even when
    // the original source omits it. Align params by skipping the leading
    // Env param on whichever side has the extra one.
    let (orig_aligned, decomp_aligned) = align_params(orig_params, decomp_params);

    let param_count_match = orig_aligned.len() == decomp_aligned.len();
    if !param_count_match {
        details.push(format!(
            "Param count: {} vs {}",
            orig_aligned.len(),
            decomp_aligned.len()
        ));
    }

    let param_types_match: Vec<bool> = orig_aligned
        .iter()
        .zip(decomp_aligned.iter())
        .map(|(o, d)| {
            let matches = normalize_type(&o.ty) == normalize_type(&d.ty);
            if !matches {
                details.push(format!(
                    "Param '{}' type: {} vs {}",
                    o.name, o.ty, d.ty
                ));
            }
            matches
        })
        .collect();

    let return_type_match = normalize_type(orig_ret) == normalize_type(decomp_ret);
    if !return_type_match {
        details.push(format!("Return type: {orig_ret} vs {decomp_ret}"));
    }

    let mut scores = Vec::new();
    scores.push(if param_count_match { 1.0 } else { 0.0 });
    if !param_types_match.is_empty() {
        let type_ratio =
            param_types_match.iter().filter(|&&b| b).count() as f64 / param_types_match.len() as f64;
        scores.push(type_ratio);
    }
    scores.push(if return_type_match { 1.0 } else { 0.0 });

    let overall = scores.iter().sum::<f64>() / scores.len() as f64;

    SignatureScore {
        overall,
        param_count_match,
        param_types_match,
        return_type_match,
        details,
    }
}

/// Align parameter lists, accounting for the decompiler always including `env: Env`
/// even when the original source omits it.
fn align_params<'a>(orig: &'a [ParamDef], decomp: &'a [ParamDef]) -> (Vec<&'a ParamDef>, Vec<&'a ParamDef>) {
    let orig_has_env = orig.first().map_or(false, |p| normalize_type(&p.ty) == "Env");
    let decomp_has_env = decomp.first().map_or(false, |p| normalize_type(&p.ty) == "Env");

    let orig_skip = if !orig_has_env && decomp_has_env { 0 } else { 0 };
    let decomp_skip = if decomp_has_env && !orig_has_env { 1 } else { 0 };

    let orig_aligned: Vec<_> = orig.iter().skip(orig_skip).collect();
    let decomp_aligned: Vec<_> = decomp.iter().skip(decomp_skip).collect();

    (orig_aligned, decomp_aligned)
}

fn compare_bodies(orig: &[StmtShape], decomp: &[StmtShape]) -> BodyScore {
    let mut details = Vec::new();

    if orig.is_empty() && decomp.is_empty() {
        return BodyScore {
            overall: 1.0,
            statement_count_orig: 0,
            statement_count_decomp: 0,
            alignments: vec![],
            placeholder_count: 0,
            details: vec!["Both bodies empty".into()],
        };
    }

    let placeholder_count = count_placeholders(decomp);
    if placeholder_count > 0 {
        details.push(format!("{placeholder_count} placeholder(s) (Default::default/todo!)"));
    }

    // Extract all meaningful expressions from both sides.
    // Decompilers often split one original expression into multiple let-bindings,
    // so we compare expression *coverage* rather than statement count.
    let orig_exprs = collect_exprs(orig);
    let decomp_exprs = collect_exprs(decomp);

    // For each original expression, find best match in decompiled
    let mut used_decomp = vec![false; decomp_exprs.len()];
    let mut alignments = Vec::new();
    let mut matched_score = 0.0;

    for (oi, orig_expr) in orig_exprs.iter().enumerate() {
        let mut best: Option<(usize, f64)> = None;
        for (di, decomp_expr) in decomp_exprs.iter().enumerate() {
            if used_decomp[di] {
                continue;
            }
            let sim = expr_similarity(orig_expr, decomp_expr);
            if sim > 0.1 {
                if best.map_or(true, |(_, s)| sim > s) {
                    best = Some((di, sim));
                }
            }
        }

        if let Some((di, sim)) = best {
            used_decomp[di] = true;
            matched_score += sim;
            alignments.push(StmtAlignment {
                orig_index: Some(oi),
                decomp_index: Some(di),
                similarity: sim,
                description: format!("Matched ({:.0}%)", sim * 100.0),
            });
        } else {
            alignments.push(StmtAlignment {
                orig_index: Some(oi),
                decomp_index: None,
                similarity: 0.0,
                description: "Missing in decompiled".into(),
            });
        }
    }

    // Count unmatched decompiled exprs that are NOT just intermediary let-bindings
    let extra_meaningful = decomp_exprs.iter().enumerate()
        .filter(|(di, _)| !used_decomp[*di])
        .filter(|(_, e)| !matches!(e, ExprShape::Path(_) | ExprShape::Literal))
        .count();

    let orig_count = orig_exprs.len().max(1);
    // Base score: how many original expressions were covered
    let coverage = matched_score / orig_count as f64;
    // Small penalty for extra meaningful expressions (not intermediaries)
    let extra_penalty = (extra_meaningful as f64 * 0.05).min(0.2);
    // Placeholder penalty
    let ph_penalty = (placeholder_count as f64 * 0.15).min(0.5);

    let overall = (coverage - extra_penalty - ph_penalty).max(0.0).min(1.0);

    if orig.len() != decomp.len() {
        details.push(format!(
            "Statements: {} orig, {} decomp",
            orig.len(),
            decomp.len()
        ));
    }

    BodyScore {
        overall,
        statement_count_orig: orig.len(),
        statement_count_decomp: decomp.len(),
        alignments,
        placeholder_count,
        details,
    }
}

/// Collect all meaningful expressions from a list of statement shapes.
/// Flattens let-bindings and expression statements into a bag of expressions.
/// Skips expressions that don't survive compilation (log!, assert macros, etc).
fn collect_exprs(stmts: &[StmtShape]) -> Vec<ExprShape> {
    let mut exprs = Vec::new();
    for stmt in stmts {
        match stmt {
            StmtShape::Let { value, .. } => {
                if !is_debug_only(value) {
                    exprs.push(value.clone());
                }
            }
            StmtShape::Expr(e) => {
                if !is_debug_only(e) {
                    exprs.push(e.clone());
                }
            }
            StmtShape::Return(Some(e)) => {
                exprs.push(e.clone());
            }
            StmtShape::Return(None) => {}
            StmtShape::If { .. } => {
                exprs.push(ExprShape::Other);
            }
            StmtShape::ForLoop { .. }
            | StmtShape::WhileLoop { .. }
            | StmtShape::Loop { .. } => {
                exprs.push(ExprShape::Other);
            }
            StmtShape::Other => {}
        }
    }
    exprs
}

/// Expressions that get compiled away or represent source-level patterns
/// that don't survive the compilation→decompilation round-trip.
fn is_debug_only(expr: &ExprShape) -> bool {
    match expr {
        // Debug macros are stripped by the compiler
        ExprShape::Macro(name) => matches!(name.as_str(), "log" | "debug_assert" | "assert"),
        // `count += 1` gets folded by the compiler into the return expression
        ExprShape::Assign => true,
        _ => false,
    }
}


/// Compute similarity between two expression shapes (0.0 - 1.0).
fn expr_similarity(a: &ExprShape, b: &ExprShape) -> f64 {
    match (a, b) {
        // Method chains: compare the chain methods
        (ExprShape::MethodChain(ca), ExprShape::MethodChain(cb)) => {
            if ca == cb {
                return 1.0;
            }
            // Compute overlap
            let total = ca.len().max(cb.len()).max(1);
            let common = ca.iter().filter(|m| cb.contains(m)).count();
            common as f64 / total as f64
        }
        // Function calls: compare function name
        (ExprShape::FnCall(a), ExprShape::FnCall(b)) => {
            if a == b {
                1.0
            } else if a.split("::").last() == b.split("::").last() {
                0.7 // same function, different path
            } else {
                0.0
            }
        }
        // Struct literals
        (ExprShape::StructLit(a), ExprShape::StructLit(b)) => {
            if a == b { 1.0 } else { 0.3 }
        }
        // Enum variants
        (ExprShape::EnumVariant(a), ExprShape::EnumVariant(b)) => {
            if a == b { 1.0 } else { 0.3 }
        }
        // Macros
        (ExprShape::Macro(a), ExprShape::Macro(b)) => {
            if a == b { 1.0 } else { 0.0 }
        }
        // BinOps
        (ExprShape::BinOp(a), ExprShape::BinOp(b)) => {
            if a == b { 1.0 } else { 0.3 }
        }
        // Literals
        (ExprShape::Literal, ExprShape::Literal) => 1.0,
        // Paths
        (ExprShape::Path(_), ExprShape::Path(_)) => 0.5, // variable names will differ
        // Placeholders are always 0
        (ExprShape::Placeholder, _) | (_, ExprShape::Placeholder) => 0.0,
        // Cross-type: method chain vs function call (e.g., `String::from_str` vs `.from_str()`)
        (ExprShape::MethodChain(chain), ExprShape::FnCall(name))
        | (ExprShape::FnCall(name), ExprShape::MethodChain(chain)) => {
            let last = name.split("::").last().unwrap_or("");
            if chain.contains(&last.to_string()) {
                0.5
            } else {
                0.0
            }
        }
        // Macro vs method chain (e.g., `vec![...]` vs method chain building a vec)
        (ExprShape::Macro(name), ExprShape::MethodChain(_))
        | (ExprShape::MethodChain(_), ExprShape::Macro(name)) => {
            if name == "vec" {
                0.3
            } else {
                0.0
            }
        }
        // checked_add().expect() vs plain `+` — compiler folds checked arithmetic
        (ExprShape::MethodChain(chain), ExprShape::BinOp(_))
        | (ExprShape::BinOp(_), ExprShape::MethodChain(chain)) => {
            let has_arith = chain.iter().any(|m| {
                matches!(m.as_str(), "checked_add" | "checked_sub" | "checked_mul"
                    | "checked_div" | "saturating_add" | "saturating_sub"
                    | "wrapping_add" | "wrapping_sub")
            });
            if has_arith { 0.7 } else { 0.0 }
        }
        // Macro vs macro with different names (symbol_short! both sides)
        (ExprShape::Macro(a), ExprShape::FnCall(b))
        | (ExprShape::FnCall(b), ExprShape::Macro(a)) => {
            if a == "vec" || b.contains("vec") { 0.3 } else { 0.0 }
        }
        _ => 0.0,
    }
}

fn count_placeholders(stmts: &[StmtShape]) -> usize {
    stmts
        .iter()
        .map(|s| match s {
            StmtShape::Let { value, .. } => {
                if matches!(value, ExprShape::Placeholder) {
                    1
                } else {
                    0
                }
            }
            StmtShape::Expr(ExprShape::Placeholder) => 1,
            StmtShape::Return(Some(ExprShape::Placeholder)) => 1,
            _ => 0,
        })
        .sum()
}

/// Normalize type strings for comparison (strip minor differences).
fn normalize_type(ty: &str) -> String {
    ty.replace(' ', "")
        .replace("&mut", "&")
        .replace("soroban_sdk::", "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::parse;

    #[test]
    fn test_compare_identical() {
        let source = r#"
#![no_std]
#[contract]
pub struct C;
#[contractimpl]
impl C {
    pub fn hello(env: Env, to: String) -> u32 {
        env.storage().instance().get(&key).unwrap_or_default()
    }
}
"#;
        let orig = parse(source).unwrap();
        let decomp = parse(source).unwrap();
        let result = compare_contracts(&orig, &decomp);
        assert_eq!(result.function_comparisons.len(), 1);
        let fc = &result.function_comparisons[0];
        assert!(fc.signature_score.overall > 0.99);
        assert!(fc.body_score.overall > 0.99);
    }

    #[test]
    fn test_method_chain_similarity() {
        let chain_a = ExprShape::MethodChain(vec![
            "env".into(),
            "storage".into(),
            "instance".into(),
            "get".into(),
        ]);
        let chain_b = ExprShape::MethodChain(vec![
            "env".into(),
            "storage".into(),
            "instance".into(),
            "get".into(),
            "unwrap_or_default".into(),
        ]);
        let sim = expr_similarity(&chain_a, &chain_b);
        assert!(sim > 0.7, "Similar chains should score high: {sim}");
    }
}
