use serde::Serialize;

use crate::compare::ContractComparison;
use crate::extract::ContractAst;
use crate::score::ContractScore;

/// Full benchmark report for a single contract.
#[derive(Debug, Clone, Serialize)]
pub struct ContractReport {
    pub name: String,
    #[serde(skip)]
    pub original: ContractAst,
    #[serde(skip)]
    pub decompiled: ContractAst,
    pub comparisons: ContractComparison,
    pub score: ContractScore,
}

/// Aggregated report for multiple contracts.
#[derive(Debug, Clone, Serialize)]
pub struct BenchReport {
    pub contracts: Vec<ContractReport>,
    pub summary: BenchSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchSummary {
    pub total_contracts: usize,
    pub average_overall: f64,
    pub average_types: f64,
    pub average_signatures: f64,
    pub average_bodies: f64,
    pub contracts_above_90: usize,
    pub contracts_above_80: usize,
    pub contracts_above_50: usize,
    pub tier_breakdown: Vec<TierEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TierEntry {
    pub tier: String,
    pub contracts: Vec<String>,
}

impl BenchReport {
    pub fn from_reports(contracts: Vec<ContractReport>) -> Self {
        let total = contracts.len();

        let avg_overall =
            contracts.iter().map(|c| c.score.overall).sum::<f64>() / total.max(1) as f64;
        let avg_types =
            contracts.iter().map(|c| c.score.types).sum::<f64>() / total.max(1) as f64;
        let avg_sigs = contracts.iter().map(|c| c.score.signatures).sum::<f64>()
            / total.max(1) as f64;
        let avg_bodies =
            contracts.iter().map(|c| c.score.bodies).sum::<f64>() / total.max(1) as f64;

        let above_90 = contracts
            .iter()
            .filter(|c| c.score.overall >= 0.9)
            .count();
        let above_80 = contracts
            .iter()
            .filter(|c| c.score.overall >= 0.8)
            .count();
        let above_50 = contracts
            .iter()
            .filter(|c| c.score.overall >= 0.5)
            .count();

        // Tier breakdown
        let mut top = Vec::new();
        let mut high = Vec::new();
        let mut mid = Vec::new();
        let mut low = Vec::new();
        let mut minimal = Vec::new();

        for c in &contracts {
            let pct = c.score.overall * 100.0;
            let entry = format!("{} ({:.0}%)", c.name, pct);
            if pct >= 90.0 {
                top.push(entry);
            } else if pct >= 80.0 {
                high.push(entry);
            } else if pct >= 50.0 {
                mid.push(entry);
            } else if pct >= 30.0 {
                low.push(entry);
            } else {
                minimal.push(entry);
            }
        }

        let tier_breakdown = vec![
            TierEntry {
                tier: "Top (>=90%)".into(),
                contracts: top,
            },
            TierEntry {
                tier: "High (80-89%)".into(),
                contracts: high,
            },
            TierEntry {
                tier: "Mid (50-79%)".into(),
                contracts: mid,
            },
            TierEntry {
                tier: "Low (30-49%)".into(),
                contracts: low,
            },
            TierEntry {
                tier: "Minimal (<30%)".into(),
                contracts: minimal,
            },
        ];

        BenchReport {
            contracts,
            summary: BenchSummary {
                total_contracts: total,
                average_overall: avg_overall,
                average_types: avg_types,
                average_signatures: avg_sigs,
                average_bodies: avg_bodies,
                contracts_above_90: above_90,
                contracts_above_80: above_80,
                contracts_above_50: above_50,
                tier_breakdown,
            },
        }
    }
}
