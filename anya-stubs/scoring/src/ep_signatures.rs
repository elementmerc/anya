// Public stub of the entry-point signature matcher module.
//
// The real implementation lives in the private scoring crate. This
// stub exposes the same type shape and function signature so the
// engine compiles against either crate without feature-gating call
// sites. It always returns an empty match vector, so no detections
// fire on public builds.

use crate::types::ConfidenceLevel;

/// A match result from `match_ep_bytes`.
#[derive(Debug, Clone)]
pub struct MatchedEpSignature {
    pub name: String,
    pub family: String,
    pub confidence: ConfidenceLevel,
}

/// Stub entry-point byte-pattern matcher. The public build returns
/// no matches; the real implementation lives privately.
pub fn match_ep_bytes(_bytes: &[u8]) -> Vec<MatchedEpSignature> {
    Vec::new()
}
