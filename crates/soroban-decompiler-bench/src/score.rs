use serde::Serialize;

use crate::compare::ContractComparison;

/// Weighting for final score computation.
#[derive(Debug, Clone, Serialize)]
pub struct Weights {
    /// Weight for type definitions (structs + enums)
    pub types: f64,
    /// Weight for function signatures (params + return type)
    pub signatures: f64,
    /// Weight for function bodies (statements, expressions)
    pub bodies: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Weights {
            types: 0.2,
            signatures: 0.2,
            bodies: 0.6,
        }
    }
}

/// Final computed score for a contract.
#[derive(Debug, Clone, Serialize)]
pub struct ContractScore {
    /// 0.0 - 1.0 weighted overall score
    pub overall: f64,
    /// 0.0 - 1.0 type definitions accuracy
    pub types: f64,
    /// 0.0 - 1.0 function signatures accuracy
    pub signatures: f64,
    /// 0.0 - 1.0 function bodies accuracy
    pub bodies: f64,
    /// Weights used for computation
    pub weights: Weights,
    /// Per-function body scores
    pub function_scores: Vec<FunctionScore>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionScore {
    pub name: String,
    pub signature: f64,
    pub body: f64,
}

/// Compute the final score from comparison results.
pub fn compute(comparison: &ContractComparison, weights: &Weights) -> ContractScore {
    // Type score: average similarity of all type comparisons
    let types = if comparison.type_comparisons.is_empty() {
        1.0 // No types to compare = perfect
    } else {
        let found_types: Vec<_> = comparison
            .type_comparisons
            .iter()
            .filter(|t| t.found || t.similarity > 0.0)
            .collect();
        if found_types.is_empty() {
            // All types missing from original (extras in decompiled don't penalize much)
            let originals = comparison
                .type_comparisons
                .iter()
                .filter(|t| !t.found && t.similarity == 0.0)
                .count();
            if originals == 0 {
                1.0
            } else {
                0.0
            }
        } else {
            // Average similarity of types that exist in original
            let orig_types: Vec<_> = comparison
                .type_comparisons
                .iter()
                .filter(|t| t.found)
                .collect();
            if orig_types.is_empty() {
                0.0
            } else {
                orig_types.iter().map(|t| t.similarity).sum::<f64>() / orig_types.len() as f64
            }
        }
    };

    // Function scores
    let mut function_scores = Vec::new();
    let mut sig_total = 0.0;
    let mut body_total = 0.0;
    let mut fn_count = 0;

    for fc in &comparison.function_comparisons {
        // Only count functions from original (not extras in decompiled)
        if fc.found || fc.signature_score.details.iter().any(|d| d.contains("missing")) {
            fn_count += 1;
            sig_total += fc.signature_score.overall;
            body_total += fc.body_score.overall;
            function_scores.push(FunctionScore {
                name: fc.name.clone(),
                signature: fc.signature_score.overall,
                body: fc.body_score.overall,
            });
        }
    }

    let signatures = if fn_count > 0 {
        sig_total / fn_count as f64
    } else {
        1.0
    };

    let bodies = if fn_count > 0 {
        body_total / fn_count as f64
    } else {
        1.0
    };

    let overall = weights.types * types + weights.signatures * signatures + weights.bodies * bodies;

    ContractScore {
        overall,
        types,
        signatures,
        bodies,
        weights: weights.clone(),
        function_scores,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_weights_sum_to_one() {
        let w = Weights::default();
        let sum = w.types + w.signatures + w.bodies;
        assert!((sum - 1.0).abs() < 1e-10);
    }
}
