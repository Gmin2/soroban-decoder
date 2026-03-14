use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use soroban_decompiler_bench::{benchmark_contract, BenchReport, ContractReport};

#[derive(Parser)]
#[command(name = "soroban-bench")]
#[command(about = "AST-based accuracy benchmark for Soroban decompiler")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Score a single contract (original vs decompiled)
    Score {
        #[arg(short, long)]
        original: PathBuf,
        #[arg(short, long)]
        decompiled: PathBuf,
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// Score all contracts in a directory pair
    ScoreAll {
        #[arg(short, long)]
        original_dir: PathBuf,
        #[arg(short, long)]
        decompiled_dir: PathBuf,
        #[arg(short, long, default_value = "text")]
        format: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Dump the extracted AST of a source file
    Ast {
        #[arg(short, long)]
        input: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Score { original, decompiled, format } => {
            let orig_src = fs::read_to_string(&original)
                .with_context(|| format!("Reading {}", original.display()))?;
            let decomp_src = fs::read_to_string(&decompiled)
                .with_context(|| format!("Reading {}", decompiled.display()))?;
            let name = original.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".into());
            let report = benchmark_contract(&name, &orig_src, &decomp_src)?;
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_single(&report);
            }
        }
        Commands::ScoreAll { original_dir, decompiled_dir, format, output } => {
            let mut reports = Vec::new();
            let mut entries: Vec<_> = fs::read_dir(&original_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |x| x == "rs"))
                .collect();
            entries.sort_by_key(|e| e.file_name());
            for entry in &entries {
                let fname = entry.file_name();
                let dp = decompiled_dir.join(&fname);
                if !dp.exists() {
                    eprintln!("  skip {}", fname.to_string_lossy());
                    continue;
                }
                let o = fs::read_to_string(entry.path())?;
                let d = fs::read_to_string(&dp)?;
                let n = entry.path().file_stem()
                    .map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                match benchmark_contract(&n, &o, &d) {
                    Ok(r) => reports.push(r),
                    Err(e) => eprintln!("  error {n}: {e}"),
                }
            }
            let bench = BenchReport::from_reports(reports);
            let text = if format == "json" {
                serde_json::to_string_pretty(&bench)?
            } else {
                format_all(&bench)
            };
            if let Some(p) = output {
                fs::write(&p, &text)?;
                eprintln!("  written to {}", p.display());
            } else {
                print!("{text}");
            }
        }
        Commands::Ast { input } => {
            let src = fs::read_to_string(&input)?;
            let ast = soroban_decompiler_bench::parse_contract(&src)?;
            println!("{}", serde_json::to_string_pretty(&ast)?);
        }
    }
    Ok(())
}

fn tier_label(pct: f64) -> &'static str {
    if pct >= 90.0 { "top" }
    else if pct >= 80.0 { "high" }
    else if pct >= 50.0 { "mid" }
    else if pct >= 30.0 { "low" }
    else { "minimal" }
}

fn score_bar(score: f64) -> String {
    let filled = (score * 30.0).round() as usize;
    let empty = 30 - filled;
    format!("\x1b[32m{}\x1b[90m{}\x1b[0m", "█".repeat(filled), "░".repeat(empty))
}

fn colored_pct(pct: f64) -> String {
    let color = if pct >= 90.0 { "32" }      // green
        else if pct >= 80.0 { "33" }          // yellow
        else if pct >= 50.0 { "36" }          // cyan
        else { "31" };                         // red
    format!("\x1b[{color}m{pct:>5.1}%\x1b[0m")
}

fn dim(s: &str) -> String {
    format!("\x1b[90m{s}\x1b[0m")
}

fn bold(s: &str) -> String {
    format!("\x1b[1m{s}\x1b[0m")
}

fn print_single(r: &ContractReport) {
    let s = &r.score;
    let pct = s.overall * 100.0;

    println!();
    println!("  {} {}", bold(&r.name), dim(&format!("[{}]", tier_label(pct))));
    println!();
    println!("  overall    {}  {}", colored_pct(pct), score_bar(s.overall));
    println!("  types      {}  {}", colored_pct(s.types * 100.0), dim("weight 20%"));
    println!("  signatures {}  {}", colored_pct(s.signatures * 100.0), dim("weight 20%"));
    println!("  bodies     {}  {}", colored_pct(s.bodies * 100.0), dim("weight 60%"));
    println!();

    if !s.function_scores.is_empty() {
        println!("  {}", dim("functions"));
        for fs in &s.function_scores {
            println!(
                "    {:<24} sig {} body {}",
                fs.name,
                colored_pct(fs.signature * 100.0),
                colored_pct(fs.body * 100.0),
            );
        }
        println!();
    }

    let has_details = r.comparisons.type_comparisons.iter().any(|t| !t.details.is_empty())
        || r.comparisons.function_comparisons.iter().any(|f|
            !f.signature_score.details.is_empty() || !f.body_score.details.is_empty());

    if has_details {
        println!("  {}", dim("details"));
        for tc in &r.comparisons.type_comparisons {
            for d in &tc.details {
                println!("    {} {}", dim(&format!("type:{}", tc.name)), d);
            }
        }
        for fc in &r.comparisons.function_comparisons {
            for d in &fc.signature_score.details {
                println!("    {} {}", dim(&format!("sig:{}", fc.name)), d);
            }
            for d in &fc.body_score.details {
                println!("    {} {}", dim(&format!("body:{}", fc.name)), d);
            }
        }
        println!();
    }
}

fn format_all(bench: &BenchReport) -> String {
    let mut out = String::new();
    let s = &bench.summary;

    out.push_str(&format!("\n  {}\n\n", bold("Soroban Decompiler Accuracy Benchmark")));

    out.push_str(&format!(
        "  contracts  {}\n",
        bold(&s.total_contracts.to_string()),
    ));
    out.push_str(&format!(
        "  average    {}\n",
        colored_pct(s.average_overall * 100.0),
    ));
    out.push_str(&format!(
        "  breakdown  types {} {} signatures {} {} bodies {}\n\n",
        colored_pct(s.average_types * 100.0),
        dim("|"),
        colored_pct(s.average_signatures * 100.0),
        dim("|"),
        colored_pct(s.average_bodies * 100.0),
    ));

    out.push_str(&format!(
        "  thresholds {} at 90%+ {} {} at 80%+ {} {} at 50%+\n\n",
        bold(&s.contracts_above_90.to_string()),
        dim("|"),
        bold(&s.contracts_above_80.to_string()),
        dim("|"),
        bold(&s.contracts_above_50.to_string()),
    ));

    // Sort by score descending
    let mut sorted: Vec<_> = bench.contracts.iter().collect();
    sorted.sort_by(|a, b| {
        b.score.overall.partial_cmp(&a.score.overall).unwrap_or(std::cmp::Ordering::Equal)
    });

    for c in &sorted {
        let pct = c.score.overall * 100.0;
        out.push_str(&format!(
            "  {} {} {:<36} {}\n",
            colored_pct(pct),
            score_bar(c.score.overall),
            c.name,
            dim(tier_label(pct)),
        ));
    }

    // Tier summary
    out.push('\n');
    for t in &s.tier_breakdown {
        if !t.contracts.is_empty() {
            out.push_str(&format!("  {} {}\n", dim(&t.tier), dim(&format!("({})", t.contracts.len()))));
            for c in &t.contracts {
                out.push_str(&format!("    {c}\n"));
            }
        }
    }
    out.push('\n');

    out
}
