use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::{Parser, Subcommand};
use lw_core::{
    auth::AuthBoundaryDetector,
    attack::{
        build_client,
        idor::{IdorScanConfig, IdorScanner, attempts_to_findings},
        race::{RaceConfig, RaceTester, result_to_findings},
        sequence::{SequenceBreaker, results_to_findings},
        severity::SeverityScorer,
    },
    report::{
        generator::ReportGenerator,
        redact::{RedactConfig, RedactEngine},
        ReportFormat,
    },
    create_session, export_session, find_session_by_name, get_session_stats,
    list_sessions, open_main_db,
    deps::DependencyTracker,
    differ::FlowDiffer,
    graph::FlowGraph,
    save_dependency_edges, save_auth_findings,
    Normalizer, Syncer,
};

// ── CLI structure ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "lw", about = "WebWeaver — Web2 bug-bounty capture & analysis CLI", version)]
struct Cli {
    /// Path to the main WebWeaver SQLite database.
    #[arg(long, short, global = true, default_value = "webweaver.db")]
    db: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage capture sessions.
    #[command(subcommand)]
    Session(SessionCmd),

    /// Merge staged proxy traffic into the main database.
    Sync(SyncArgs),

    /// Analyse request-response dependency chains for a session.
    AnalyzeDeps(AnalyzeDepsArgs),

    /// Build and export the state graph for a session.
    BuildGraph(BuildGraphArgs),

    /// Diff two sessions and surface IDOR candidates.
    DiffSessions(DiffSessionsArgs),

    /// Detect auth boundary violations across sessions.
    CheckAuth(CheckAuthArgs),

    // ── Phase 3 attack commands ───────────────────────────────────────────────

    /// IDOR scanner: substitute session B's object IDs into session A's requests.
    ScanIdor(ScanIdorArgs),

    /// Sequence breaker: skip / reorder / replay each step and flag weak enforcement.
    BreakSequence(BreakSequenceArgs),

    /// Race condition tester: fire one request N times concurrently.
    RaceTest(RaceTestArgs),

    /// Run all attack modules and output a ranked findings report.
    RunAll(RunAllArgs),

    /// Generate a formatted bug-bounty report from attack findings.
    GenerateReport(GenerateReportArgs),
}

// ── session ───────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum SessionCmd {
    /// Create a new capture session.
    New {
        #[arg(long, short)]
        name: String,
        #[arg(long, short, default_value = "default")]
        role: String,
    },
    /// List all sessions.
    List,
    /// Show request/response/entity counts.
    Stats { name: Option<String> },
    /// Export a session to JSON.
    Export {
        name: String,
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

// ── sync ──────────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct SyncArgs {
    #[arg(long, default_value = "webweaver_staging.db")]
    staging: PathBuf,
    #[arg(long, default_value = "filter_rules.toml")]
    filter: PathBuf,
    /// Keep polling every 500 ms until Ctrl-C.
    #[arg(long, short)]
    watch: bool,
}

// ── analyze-deps ──────────────────────────────────────────────────────────────

#[derive(Parser)]
struct AnalyzeDepsArgs {
    #[arg(long, short)]
    session: String,
    #[arg(long)]
    save: bool,
    #[arg(long, short)]
    output: Option<PathBuf>,
}

// ── build-graph ───────────────────────────────────────────────────────────────

#[derive(Parser)]
struct BuildGraphArgs {
    #[arg(long, short)]
    session: String,
    #[arg(long)]
    dot: Option<PathBuf>,
    #[arg(long)]
    json: Option<PathBuf>,
}

// ── diff-sessions ─────────────────────────────────────────────────────────────

#[derive(Parser)]
struct DiffSessionsArgs {
    #[arg(long)]
    privileged: String,
    #[arg(long)]
    target: String,
    #[arg(long, short)]
    output: Option<PathBuf>,
}

// ── check-auth ────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct CheckAuthArgs {
    #[arg(long, short)]
    session: Option<String>,
    #[arg(long)]
    save: bool,
    #[arg(long, short)]
    output: Option<PathBuf>,
}

// ── scan-idor ─────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct ScanIdorArgs {
    /// Privileged / reference session (owns the objects being tested).
    #[arg(long)]
    session_a: String,
    /// Target session under test (should NOT be able to access A's objects).
    #[arg(long)]
    session_b: String,
    /// Log what would be tested without sending any requests.
    #[arg(long)]
    dry_run: bool,
    /// Maximum number of HTTP tests to execute (0 = unlimited).
    #[arg(long, default_value = "100")]
    max_tests: usize,
    /// Accept invalid TLS certificates.
    #[arg(long)]
    insecure: bool,
    /// HTTP proxy URL (e.g. http://127.0.0.1:8080).
    #[arg(long)]
    proxy: Option<String>,
    /// Write results to a JSON file.
    #[arg(long, short)]
    output: Option<PathBuf>,
}

// ── break-sequence ────────────────────────────────────────────────────────────

#[derive(Parser)]
struct BreakSequenceArgs {
    #[arg(long, short)]
    session: String,
    /// Number of steps to test (0 = all).
    #[arg(long, default_value = "20")]
    max_steps: usize,
    #[arg(long)]
    insecure: bool,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long, short)]
    output: Option<PathBuf>,
}

// ── race-test ─────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct RaceTestArgs {
    #[arg(long, short)]
    session: String,
    /// DB request ID to race.
    #[arg(long)]
    request_id: i64,
    /// Number of concurrent requests (default 10).
    #[arg(long, default_value = "10")]
    concurrency: usize,
    /// Per-request timeout in milliseconds.
    #[arg(long, default_value = "10000")]
    timeout_ms: u64,
    #[arg(long)]
    insecure: bool,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long, short)]
    output: Option<PathBuf>,
}

// ── run-all ───────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct RunAllArgs {
    /// Session A (privileged / reference).
    #[arg(long)]
    session_a: String,
    /// Session B (target under test).
    #[arg(long)]
    session_b: String,
    /// Concurrency for race tests.
    #[arg(long, default_value = "10")]
    race_concurrency: usize,
    /// Maximum number of write-method requests to race test.
    #[arg(long, default_value = "3")]
    race_limit: usize,
    /// Steps to test in the sequence breaker (0 = all).
    #[arg(long, default_value = "20")]
    seq_max_steps: usize,
    /// Maximum IDOR tests.
    #[arg(long, default_value = "100")]
    idor_max_tests: usize,
    #[arg(long)]
    insecure: bool,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long, short)]
    output: Option<PathBuf>,
}

// ── generate-report ───────────────────────────────────────────────────────────

#[derive(Parser)]
struct GenerateReportArgs {
    /// Session A (privileged / reference).
    #[arg(long)]
    session_a: String,
    /// Session B (target under test).
    #[arg(long)]
    session_b: String,
    /// Report format: markdown | hackerone | bugcrowd  (default: markdown)
    #[arg(long, default_value = "markdown")]
    format: String,
    /// Output file path.  Defaults to report.md.
    #[arg(long, short, default_value = "report.md")]
    output: PathBuf,
    /// Path to a TOML file with additional redaction rules.
    #[arg(long)]
    redact_config: Option<PathBuf>,
    /// Concurrency for race tests.
    #[arg(long, default_value = "10")]
    race_concurrency: usize,
    /// Maximum number of write-method requests to race test.
    #[arg(long, default_value = "3")]
    race_limit: usize,
    /// Steps to test in the sequence breaker (0 = all).
    #[arg(long, default_value = "20")]
    seq_max_steps: usize,
    /// Maximum IDOR tests.
    #[arg(long, default_value = "100")]
    idor_max_tests: usize,
    #[arg(long)]
    insecure: bool,
    #[arg(long)]
    proxy: Option<String>,
    /// Skip analyst checkpoint (accept all findings without prompting).
    #[arg(long)]
    no_confirm: bool,
}

// ── entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Session(cmd)         => run_session(cli.db, cmd),
        Commands::Sync(args)           => run_sync(cli.db, args),
        Commands::AnalyzeDeps(args)    => run_analyze_deps(cli.db, args),
        Commands::BuildGraph(args)     => run_build_graph(cli.db, args),
        Commands::DiffSessions(args)   => run_diff_sessions(cli.db, args),
        Commands::CheckAuth(args)      => run_check_auth(cli.db, args),
        Commands::ScanIdor(args)        => run_scan_idor(cli.db, args).await,
        Commands::BreakSequence(args)   => run_break_sequence(cli.db, args).await,
        Commands::RaceTest(args)        => run_race_test(cli.db, args).await,
        Commands::RunAll(args)          => run_all(cli.db, args).await,
        Commands::GenerateReport(args)  => run_generate_report(cli.db, args).await,
    }
}

// ── Phase 1/2 sync handlers ───────────────────────────────────────────────────

fn run_session(db: PathBuf, cmd: SessionCmd) -> anyhow::Result<()> {
    let conn = open_main_db(&db)
        .with_context(|| format!("Cannot open database at {}", db.display()))?;

    match cmd {
        SessionCmd::New { name, role } => {
            let s = create_session(&conn, &name, &role)
                .with_context(|| format!("Failed to create session '{name}'"))?;
            println!("Session created  id={}  name='{}'  role='{}'", s.id, s.name, s.user_role);
        }

        SessionCmd::List => {
            let sessions = list_sessions(&conn)?;
            if sessions.is_empty() {
                println!("No sessions.  Run `lw session new --name <name>` to start one.");
                return Ok(());
            }
            println!("{:<6} {:<30} {:<20} CREATED", "ID", "NAME", "ROLE");
            println!("{}", "-".repeat(72));
            for s in sessions {
                println!(
                    "{:<6} {:<30} {:<20} {}",
                    s.id,
                    s.name,
                    s.user_role,
                    s.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
        }

        SessionCmd::Stats { name } => match name {
            Some(n) => {
                match get_session_stats(&conn, &n)? {
                    Some(st) => print_stats(&st),
                    None     => eprintln!("Session '{n}' not found."),
                }
            }
            None => {
                let sessions = list_sessions(&conn)?;
                if sessions.is_empty() {
                    println!("No sessions.");
                    return Ok(());
                }
                println!("{:<6} {:<30} {:>10} {:>10} {:>10}",
                    "ID", "NAME", "REQUESTS", "RESPONSES", "ENTITIES");
                println!("{}", "-".repeat(72));
                for s in sessions {
                    if let Some(st) = get_session_stats(&conn, &s.name)? {
                        println!(
                            "{:<6} {:<30} {:>10} {:>10} {:>10}",
                            st.session.id, st.session.name,
                            st.request_count, st.response_count, st.entity_count
                        );
                    }
                }
            }
        },

        SessionCmd::Export { name, output } => {
            let export = export_session(&conn, &name)
                .with_context(|| format!("Failed to export session '{name}'"))?;
            let json = serde_json::to_string_pretty(&export)
                .context("Failed to serialise export")?;
            match output {
                Some(path) => {
                    std::fs::write(&path, &json)
                        .with_context(|| format!("Failed to write {}", path.display()))?;
                    println!("Exported {} request(s) to {}", export.total_requests, path.display());
                }
                None => println!("{json}"),
            }
        }
    }
    Ok(())
}

fn run_sync(db: PathBuf, args: SyncArgs) -> anyhow::Result<()> {
    let normalizer = Arc::new(Normalizer::from_file_or_defaults(&args.filter));
    let syncer     = Syncer::new(&args.staging, &db, normalizer);

    if args.watch {
        println!(
            "Watching {} → {} (Ctrl-C to stop)",
            args.staging.display(), db.display()
        );
        let _handle = syncer.run_background();
        loop { std::thread::sleep(std::time::Duration::from_secs(3600)); }
    } else {
        let n = syncer.sync_once().context("Sync failed")?;
        println!("Merged {n} request(s).");
    }
    Ok(())
}

fn run_analyze_deps(db: PathBuf, args: AnalyzeDepsArgs) -> anyhow::Result<()> {
    let conn    = open_main_db(&db)?;
    let session = find_session_by_name(&conn, &args.session)?
        .ok_or_else(|| anyhow::anyhow!("Session '{}' not found", args.session))?;

    let tracker = DependencyTracker::new();
    let edges   = tracker.analyze_session(&conn, session.id)?;

    println!(
        "Found {} dependency edge(s) in session '{}':",
        edges.len(), args.session
    );
    for e in &edges {
        println!(
            "  [{}] {}#{} → req#{} field='{}' type={}",
            e.source_type.as_str(),
            e.source_type.as_str(),
            e.source_id,
            e.target_request_id,
            e.field_name,
            e.edge_type.as_str(),
        );
    }

    if args.save && !edges.is_empty() {
        let saved = save_dependency_edges(&conn, session.id, &edges)?;
        println!("Saved {saved} edge(s) to database.");
    }

    if let Some(path) = args.output {
        let json = serde_json::to_string_pretty(&edges)?;
        std::fs::write(&path, &json)?;
        println!("Edges written to {}", path.display());
    }
    Ok(())
}

fn run_build_graph(db: PathBuf, args: BuildGraphArgs) -> anyhow::Result<()> {
    let conn    = open_main_db(&db)?;
    let session = find_session_by_name(&conn, &args.session)?
        .ok_or_else(|| anyhow::anyhow!("Session '{}' not found", args.session))?;

    let graph = FlowGraph::build(&conn, session.id)?;
    println!(
        "Graph for '{}': {} node(s), {} edge(s)",
        args.session, graph.node_count(), graph.edge_count()
    );

    let wrote_something = args.dot.is_some() || args.json.is_some();
    if let Some(dot_path) = args.dot {
        let dot_str = graph.to_dot();
        std::fs::write(&dot_path, &dot_str)?;
        println!("DOT → {}", dot_path.display());
    }
    if let Some(json_path) = args.json {
        let json_str = graph.to_json()?;
        std::fs::write(&json_path, &json_str)?;
        println!("JSON → {}", json_path.display());
    }
    if !wrote_something {
        println!("{}", graph.to_dot());
    }
    Ok(())
}

fn run_diff_sessions(db: PathBuf, args: DiffSessionsArgs) -> anyhow::Result<()> {
    let conn   = open_main_db(&db)?;
    let result = FlowDiffer::new().diff(&conn, &args.privileged, &args.target)?;

    println!(
        "Diff: '{}' vs '{}' — {} aligned pair(s), {} IDOR candidate(s)",
        result.session_a, result.session_b,
        result.aligned_count, result.idor_candidates.len(),
    );

    if !result.only_in_a.is_empty() {
        println!("\nOnly in '{}' ({}):", result.session_a, result.only_in_a.len());
        for p in &result.only_in_a { println!("  {p}"); }
    }
    if !result.only_in_b.is_empty() {
        println!("\nOnly in '{}' ({}):", result.session_b, result.only_in_b.len());
        for p in &result.only_in_b { println!("  {p}"); }
    }
    if !result.idor_candidates.is_empty() {
        println!("\n⚠  IDOR candidates:");
        for c in &result.idor_candidates {
            println!(
                "  [{:.0}% confidence] {} {} — leaked value '{}' at '{}'  (req#{})",
                c.confidence * 100.0,
                c.method, c.url_pattern,
                c.leaked_value, c.field_path, c.request_id_b,
            );
        }
    }
    if let Some(path) = args.output {
        let json = serde_json::to_string_pretty(&result)?;
        std::fs::write(&path, &json)?;
        println!("\nFull diff written to {}", path.display());
    }
    Ok(())
}

fn run_check_auth(db: PathBuf, args: CheckAuthArgs) -> anyhow::Result<()> {
    let conn     = open_main_db(&db)?;
    let detector = AuthBoundaryDetector::new();

    let findings = if let Some(ref name) = args.session {
        detector.analyze_session(&conn, name)?
    } else {
        detector.analyze_all_sessions(&conn)?
    };

    if findings.is_empty() {
        println!("No auth boundary findings.");
        return Ok(());
    }

    println!("{} finding(s):", findings.len());
    println!("{:<10} {:<24} {:<8} PATTERN", "SEVERITY", "TYPE", "METHOD");
    println!("{}", "-".repeat(80));
    for f in &findings {
        println!(
            "{:<10} {:<24} {:<8} {}",
            f.severity.as_str().to_uppercase(),
            f.finding_type.as_str(),
            f.method,
            f.url_pattern,
        );
        println!("           {}", f.details);
    }

    if args.save {
        let saved = save_auth_findings(&conn, &findings)?;
        println!("\nSaved {saved} finding(s) to database.");
    }
    if let Some(path) = args.output {
        let json = serde_json::to_string_pretty(&findings)?;
        std::fs::write(&path, &json)?;
        println!("Findings written to {}", path.display());
    }
    Ok(())
}

// ── Phase 3 async handlers ────────────────────────────────────────────────────

async fn run_scan_idor(db: PathBuf, args: ScanIdorArgs) -> anyhow::Result<()> {
    let conn   = open_main_db(&db)?;
    let client = build_client(args.insecure, args.proxy.as_deref())?;

    let config = IdorScanConfig {
        dry_run:   args.dry_run,
        max_tests: args.max_tests,
    };

    println!(
        "Scanning IDOR: '{}' vs '{}' (max_tests={}, dry_run={})…",
        args.session_a, args.session_b, args.max_tests, args.dry_run
    );

    let scanner  = IdorScanner::new(client);
    let attempts = scanner.scan(&conn, &args.session_a, &args.session_b, &config).await?;

    let total  = attempts.len();
    let confirmed: Vec<_> = attempts.iter().filter(|a| a.is_idor).collect();
    println!("{total} attempt(s), {} confirmed IDOR finding(s).", confirmed.len());

    for a in &confirmed {
        println!(
            "  [conf={:.0}%] {} {} — '{}' → '{}' @ '{}' (req#{})",
            a.confidence * 100.0,
            a.method, a.url_pattern,
            a.value_a, a.value_b, a.field_name,
            a.request_id_a,
        );
        println!("     {}", a.details);
    }

    if let Some(path) = args.output {
        let json = serde_json::to_string_pretty(&attempts)?;
        std::fs::write(&path, &json)?;
        println!("Results written to {}", path.display());
    }
    Ok(())
}

async fn run_break_sequence(db: PathBuf, args: BreakSequenceArgs) -> anyhow::Result<()> {
    let conn   = open_main_db(&db)?;
    let client = build_client(args.insecure, args.proxy.as_deref())?;

    println!(
        "Breaking sequence for '{}' (max_steps={})…",
        args.session, args.max_steps
    );

    let breaker = SequenceBreaker::new(client);
    let results = breaker.break_sequence(&conn, &args.session, args.max_steps).await?;

    let findings: Vec<_> = results.iter().filter(|r| !r.rejected).collect();
    println!("{} mutation(s) tested, {} finding(s).", results.len(), findings.len());

    for r in &findings {
        println!(
            "  [{sev}] {mtype} @ step {idx}",
            sev   = r.severity.as_str().to_uppercase(),
            mtype = r.mutation.mutation_type.as_str(),
            idx   = r.mutation.step_index,
        );
        if let Some(ref f) = r.finding {
            println!("     {f}");
        }
    }

    if let Some(path) = args.output {
        let json = serde_json::to_string_pretty(&results)?;
        std::fs::write(&path, &json)?;
        println!("Results written to {}", path.display());
    }
    Ok(())
}

async fn run_race_test(db: PathBuf, args: RaceTestArgs) -> anyhow::Result<()> {
    let conn   = open_main_db(&db)?;
    let client = build_client(args.insecure, args.proxy.as_deref())?;

    let config = RaceConfig {
        concurrency: args.concurrency,
        timeout_ms:  args.timeout_ms,
    };

    println!(
        "Race testing request #{} in '{}' (concurrency={})…",
        args.request_id, args.session, args.concurrency
    );

    let tester = RaceTester::new(client);
    let result = tester.test(&conn, &args.session, args.request_id, &config).await?;

    println!(
        "{} response(s) received, {} finding(s).",
        result.responses.len(), result.findings.len()
    );

    // Print response summary.
    for r in &result.responses {
        println!(
            "  [{}] HTTP {} — {}ms",
            r.attempt_index, r.status_code, r.elapsed_ms
        );
    }

    for f in &result.findings {
        println!("\n  ⚠  [{}] {}", f.severity.as_str().to_uppercase(), f.anomaly_type);
        println!("     {}", f.details);
    }

    if let Some(path) = args.output {
        let json = serde_json::to_string_pretty(&result)?;
        std::fs::write(&path, &json)?;
        println!("Results written to {}", path.display());
    }
    Ok(())
}

async fn run_all(db: PathBuf, args: RunAllArgs) -> anyhow::Result<()> {
    let conn   = open_main_db(&db)?;
    let client = build_client(args.insecure, args.proxy.as_deref())?;

    println!("=== WebWeaver run-all ===");
    println!("  session-a : {}", args.session_a);
    println!("  session-b : {}", args.session_b);
    println!();

    let mut all_findings = Vec::new();

    // ── 1. IDOR scan ──────────────────────────────────────────────────────────
    println!("[1/3] IDOR scan…");
    let idor_cfg = IdorScanConfig {
        dry_run:   false,
        max_tests: args.idor_max_tests,
    };
    match IdorScanner::new(client.clone())
        .scan(&conn, &args.session_a, &args.session_b, &idor_cfg)
        .await
    {
        Ok(attempts) => {
            let n = attempts.iter().filter(|a| a.is_idor).count();
            println!("    → {} attempt(s), {n} IDOR finding(s)", attempts.len());
            all_findings.extend(attempts_to_findings(&attempts));
        }
        Err(e) => eprintln!("    IDOR scan error: {e}"),
    }

    // ── 2. Sequence breaker ───────────────────────────────────────────────────
    println!("[2/3] Sequence break for '{}'…", args.session_a);
    match SequenceBreaker::new(client.clone())
        .break_sequence(&conn, &args.session_a, args.seq_max_steps)
        .await
    {
        Ok(results) => {
            let n = results.iter().filter(|r| !r.rejected).count();
            println!("    → {} mutation(s), {n} finding(s)", results.len());
            all_findings.extend(results_to_findings(&results));
        }
        Err(e) => eprintln!("    Sequence break error: {e}"),
    }

    // ── 3. Race tests ─────────────────────────────────────────────────────────
    println!("[3/3] Race tests for '{}'…", args.session_a);
    let race_cfg = RaceConfig {
        concurrency: args.race_concurrency,
        timeout_ms:  10_000,
    };
    let targets = RaceTester::suggest_targets(&conn, &args.session_a)
        .unwrap_or_default();
    let limit   = if args.race_limit == 0 { targets.len() } else { args.race_limit.min(targets.len()) };
    let mut race_findings_count = 0usize;
    for &req_id in targets.iter().take(limit) {
        match RaceTester::new(client.clone())
            .test(&conn, &args.session_a, req_id, &race_cfg)
            .await
        {
            Ok(result) => {
                race_findings_count += result.findings.len();
                all_findings.extend(result_to_findings(&result));
            }
            Err(e) => eprintln!("    Race test error for req#{req_id}: {e}"),
        }
    }
    println!("    → {limit} target(s) tested, {race_findings_count} finding(s)");

    // ── Score and rank ────────────────────────────────────────────────────────
    println!();
    let scored = SeverityScorer::new().rank(all_findings);
    println!(
        "┌─ Ranked findings ({} total) ──────────────────────────────────────────",
        scored.len()
    );
    for (i, sf) in scored.iter().enumerate() {
        println!(
            "│ #{:<3} [{score:>5.1}] [{sev:<8}] [{src}] {title}",
            i + 1,
            score = sf.final_score,
            sev   = sf.finding.severity.as_str().to_uppercase(),
            src   = sf.finding.source.as_str(),
            title = sf.finding.title,
        );
        println!("│      {}", sf.finding.details);
    }
    println!("└──────────────────────────────────────────────────────────────────────");

    if let Some(path) = args.output {
        let json = serde_json::to_string_pretty(&scored)?;
        std::fs::write(&path, &json)?;
        println!("Full report written to {}", path.display());
    }
    Ok(())
}

// ── generate-report handler ───────────────────────────────────────────────────

async fn run_generate_report(db: PathBuf, args: GenerateReportArgs) -> anyhow::Result<()> {
    let conn   = open_main_db(&db)?;
    let client = build_client(args.insecure, args.proxy.as_deref())?;

    println!("=== WebWeaver generate-report ===");
    println!("  session-a : {}", args.session_a);
    println!("  session-b : {}", args.session_b);
    println!("  format    : {}", args.format);
    println!();

    // ── 1. Run all three attack modules (same as run-all) ─────────────────────
    let mut all_findings = Vec::new();

    println!("[1/3] IDOR scan...");
    let idor_cfg = IdorScanConfig { dry_run: false, max_tests: args.idor_max_tests };
    match IdorScanner::new(client.clone())
        .scan(&conn, &args.session_a, &args.session_b, &idor_cfg)
        .await
    {
        Ok(attempts) => {
            let n = attempts.iter().filter(|a| a.is_idor).count();
            println!("    -> {} attempt(s), {n} IDOR finding(s)", attempts.len());
            all_findings.extend(attempts_to_findings(&attempts));
        }
        Err(e) => eprintln!("    IDOR scan error: {e}"),
    }

    println!("[2/3] Sequence break for '{}'...", args.session_a);
    match SequenceBreaker::new(client.clone())
        .break_sequence(&conn, &args.session_a, args.seq_max_steps)
        .await
    {
        Ok(results) => {
            let n = results.iter().filter(|r| !r.rejected).count();
            println!("    -> {} mutation(s), {n} finding(s)", results.len());
            all_findings.extend(results_to_findings(&results));
        }
        Err(e) => eprintln!("    Sequence break error: {e}"),
    }

    println!("[3/3] Race tests for '{}'...", args.session_a);
    let race_cfg   = RaceConfig { concurrency: args.race_concurrency, timeout_ms: 10_000 };
    let targets    = RaceTester::suggest_targets(&conn, &args.session_a).unwrap_or_default();
    let race_limit = if args.race_limit == 0 { targets.len() } else { args.race_limit.min(targets.len()) };
    for &req_id in targets.iter().take(race_limit) {
        match RaceTester::new(client.clone())
            .test(&conn, &args.session_a, req_id, &race_cfg)
            .await
        {
            Ok(result) => all_findings.extend(result_to_findings(&result)),
            Err(e) => eprintln!("    Race test error for req#{req_id}: {e}"),
        }
    }

    // ── 2. Score and rank ─────────────────────────────────────────────────────
    let scored = SeverityScorer::new().rank(all_findings);

    if scored.is_empty() {
        println!("No findings to report.");
        return Ok(());
    }

    // ── 3. Analyst checkpoint ─────────────────────────────────────────────────
    let summary = ReportGenerator::draft_summary(&scored);
    println!("{summary}");

    let included_indices: Vec<usize> = if args.no_confirm {
        (0..scored.len()).collect()
    } else {
        println!("Enter finding NUMBERS to EXCLUDE (comma-separated), or press ENTER to include all:");
        print!("> ");
        // Flush stdout so the prompt appears before blocking on stdin.
        use std::io::Write as _;
        std::io::stdout().flush().ok();

        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let trimmed = line.trim();

        let excluded: std::collections::HashSet<usize> = if trimmed.is_empty() {
            std::collections::HashSet::new()
        } else {
            trimmed
                .split(',')
                .filter_map(|s| s.trim().parse::<usize>().ok())
                .collect()
        };

        let included: Vec<usize> = (1..=scored.len())
            .filter(|i| !excluded.contains(i))
            .map(|i| i - 1)
            .collect();

        if !excluded.is_empty() {
            println!(
                "Excluding {} finding(s). {} finding(s) will appear in the report.",
                excluded.len(),
                included.len()
            );
        }
        included
    };

    let selected: Vec<_> = included_indices.iter().map(|&i| scored[i].clone()).collect();

    if selected.is_empty() {
        println!("All findings excluded — no report generated.");
        return Ok(());
    }

    // ── 4. Build redaction engine ─────────────────────────────────────────────
    let redact_cfg = args.redact_config
        .as_deref()
        .map(RedactConfig::from_file)
        .unwrap_or_default();
    let redact = RedactEngine::new(&redact_cfg)?;

    // ── 5. Build enriched findings and render ─────────────────────────────────
    println!("\nGenerating report ({} finding(s))...", selected.len());
    let report_findings = ReportGenerator::build_report_findings(&conn, &selected, &redact)?;

    let format = ReportFormat::from_str(&args.format);
    let date   = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let report = ReportGenerator::render(&report_findings, &format, &date)?;

    std::fs::write(&args.output, &report)
        .with_context(|| format!("Failed to write report to {}", args.output.display()))?;

    println!("Report written to {}", args.output.display());
    Ok(())
}

// ── display helpers ───────────────────────────────────────────────────────────

fn print_stats(st: &lw_core::SessionStats) {
    println!("Session  : {} (id={})", st.session.name, st.session.id);
    println!("Role     : {}", st.session.user_role);
    println!("Created  : {}", st.session.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("──────────────────────────────");
    println!("Requests  : {}", st.request_count);
    println!("Responses : {}", st.response_count);
    println!("Entities  : {}", st.entity_count);
}
