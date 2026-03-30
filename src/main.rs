use clap::Parser;
use foxguard::cli::{Cli, OutputFormat};
use foxguard::engine::scan_directory;
use foxguard::rules::RuleRegistry;

fn main() {
    let cli = Cli::parse();
    let registry = RuleRegistry::new();

    let mut findings = scan_directory(&cli.path, &registry);

    // Filter by severity if specified
    if let Some(ref min_severity) = cli.severity {
        let min = min_severity.to_severity();
        findings.retain(|f| f.severity >= min);
    }

    match cli.format {
        OutputFormat::Terminal => foxguard::report::terminal::print_findings(&findings),
        OutputFormat::Json => foxguard::report::json::print_json(&findings),
        OutputFormat::Sarif => foxguard::report::sarif::print_sarif(&findings),
    }

    // Exit with non-zero code if findings exist
    if !findings.is_empty() {
        std::process::exit(1);
    }
}
