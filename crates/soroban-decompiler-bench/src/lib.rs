mod extract;
mod compare;
mod score;
mod report;

pub use extract::{ContractAst, FunctionAst, EnumDef, StructDef, StmtShape};
pub use compare::{compare_contracts, FunctionComparison, TypeComparison};
pub use score::{ContractScore, Weights};
pub use report::{BenchReport, ContractReport};

use anyhow::Result;

/// Parse a Rust source file into a ContractAst for comparison.
pub fn parse_contract(source: &str) -> Result<ContractAst> {
    extract::parse(source)
}

/// Score a single contract: original source vs decompiled source.
/// Returns a ContractScore with type, signature, and body accuracy.
pub fn score_contract(original: &str, decompiled: &str) -> Result<ContractScore> {
    let orig_ast = extract::parse(original)?;
    let decomp_ast = extract::parse(decompiled)?;
    let comparisons = compare::compare_contracts(&orig_ast, &decomp_ast);
    Ok(score::compute(&comparisons, &Weights::default()))
}

/// Score a single contract with custom weights.
pub fn score_contract_weighted(
    original: &str,
    decompiled: &str,
    weights: &Weights,
) -> Result<ContractScore> {
    let orig_ast = extract::parse(original)?;
    let decomp_ast = extract::parse(decompiled)?;
    let comparisons = compare::compare_contracts(&orig_ast, &decomp_ast);
    Ok(score::compute(&comparisons, weights))
}

/// Full benchmark report for a single contract pair.
pub fn benchmark_contract(
    name: &str,
    original: &str,
    decompiled: &str,
) -> Result<ContractReport> {
    let orig_ast = extract::parse(original)?;
    let decomp_ast = extract::parse(decompiled)?;
    let comparisons = compare::compare_contracts(&orig_ast, &decomp_ast);
    let score = score::compute(&comparisons, &Weights::default());
    Ok(ContractReport {
        name: name.to_string(),
        original: orig_ast,
        decompiled: decomp_ast,
        comparisons,
        score,
    })
}
