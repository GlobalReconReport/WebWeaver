pub mod attack;
pub mod auth;
pub mod report;
pub mod db;
pub mod deps;
pub mod differ;
pub mod entities;
pub mod graph;
pub mod graphql;
pub mod models;
pub mod normalize;
pub mod replay;
pub mod sync;

pub use attack::{
    build_client, AttackFinding, FindingSource,
    idor::{IdorAttempt, IdorScanConfig, IdorScanner, attempts_to_findings as idor_findings},
    race::{RaceConfig, RaceFinding, RaceResult, RaceTester, result_to_findings as race_findings},
    sequence::{MutationType, SequenceBreakResult, SequenceMutation, SequenceBreaker,
               results_to_findings as sequence_findings},
    severity::{ScoreComponent, ScoredFinding, SeverityScorer},
};
pub use auth::{AuthBoundaryDetector, AuthEvidence, AuthFinding, AuthFindingType, Severity};
pub use db::{
    create_session, export_session, find_main_id_for_staging, find_or_create_session,
    find_session_by_name, get_last_synced_rowid, get_pairs_for_session,
    get_requests_for_session, get_response_for_request, get_session_stats,
    insert_correlation, insert_entity, insert_request, insert_response, list_sessions,
    load_auth_findings, load_dependency_edges, open_main_db, open_staging_db,
    save_auth_findings, save_dependency_edges, set_last_synced_rowid,
};
pub use deps::{DependencyEdge, DependencyEdgeType, DependencySourceType, DependencyTracker};
pub use differ::{DiffResult, FlowDiffer, IdorCandidate};
pub use entities::{EntityExtractor, ExtractedEntity};
pub use graph::{FlowGraph, normalize_url};
pub use graphql::{GraphqlDetector, GraphqlInfo};
pub use models::*;
pub use normalize::{FilterConfig, Normalizer};
pub use replay::{HttpResponse, ReplayableRequest, RequestReconstructor, extract_auth_context};
pub use sync::Syncer;
pub use report::{
    ReportFormat, ReportFinding,
    generator::ReportGenerator,
    redact::{RedactConfig, RedactEngine},
};
pub use db::get_request_by_id;
