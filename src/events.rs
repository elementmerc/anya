// Ányá - Malware Analysis Platform
// Copyright (C) 2026 Daniel Iwugo
// Licensed under AGPL-3.0-or-later
//
// Analysis lifecycle events.
// Events are emitted at key points during analysis. Listeners subscribe to
// events they care about and receive contextual data.

use std::path::PathBuf;

/// Events emitted during the analysis lifecycle.
///
/// Each event carries the minimal data a listener would need to react.
#[derive(Debug, Clone)]
pub enum AnalysisEvent {
    // ── File-level events ────────────────────────────────────────────────
    /// Analysis is about to start.
    AnalysisStarting {
        path: PathBuf,
        size_bytes: u64,
        mime_type: Option<String>,
    },

    /// File format has been identified (PE, ELF, JavaScript, etc.)
    FormatDetected {
        format_label: String,
        extension: String,
    },

    /// A format-specific parser is about to run.
    ParserStarting { parser_name: &'static str },

    /// A format-specific parser completed (with or without findings).
    ParserCompleted {
        parser_name: &'static str,
        had_findings: bool,
    },

    /// A finding was detected during analysis.
    FindingDetected {
        title: String,
        confidence: String,
        mitre_id: Option<String>,
    },

    /// Scoring engine has computed the verdict.
    VerdictComputed {
        verdict: String,
        risk_score: i64,
        finding_count: usize,
    },

    /// Analysis is complete. Final result is available.
    AnalysisComplete {
        path: PathBuf,
        verdict: String,
        duration_ms: u64,
    },

    // ── Batch-level events ───────────────────────────────────────────────
    /// Batch analysis is starting.
    BatchStarting {
        directory: PathBuf,
        file_count: usize,
    },

    /// A file in a batch completed analysis.
    BatchFileComplete {
        index: usize,
        path: PathBuf,
        verdict: String,
    },

    /// Entire batch analysis is complete.
    BatchComplete {
        total: usize,
        analysed: usize,
        failed: usize,
        duration_secs: f64,
    },

    // ── System events ────────────────────────────────────────────────────
    /// KSD database was loaded or reloaded.
    KsdLoaded {
        sample_count: usize,
        family_count: usize,
    },

    /// A YARA rule file was loaded (V2+).
    YaraRulesLoaded { rule_count: usize, source: String },

    /// Configuration was loaded or changed.
    ConfigLoaded { config_version: String },
}

/// Trait for receiving analysis events.
///
/// The default implementation does nothing — listeners override only the
/// events they care about.
pub trait EventListener: Send + Sync {
    /// Called for every analysis event. Return `true` to continue processing,
    /// `false` to request cancellation (best-effort, not guaranteed).
    fn on_event(&self, event: &AnalysisEvent) -> bool {
        let _ = event;
        true // continue by default
    }
}

/// Event bus — collects listeners and dispatches events.
pub struct EventBus {
    listeners: Vec<Box<dyn EventListener>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
        }
    }

    /// Register a listener.
    pub fn subscribe<L: EventListener + 'static>(&mut self, listener: L) {
        self.listeners.push(Box::new(listener));
    }

    /// Emit an event to all listeners. Returns false if any listener requested cancellation.
    pub fn emit(&self, event: &AnalysisEvent) -> bool {
        self.listeners.iter().all(|l| l.on_event(event))
    }

    /// Number of registered listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingListener {
        count: Arc<AtomicUsize>,
    }

    impl EventListener for CountingListener {
        fn on_event(&self, _event: &AnalysisEvent) -> bool {
            self.count.fetch_add(1, Ordering::Relaxed);
            true
        }
    }

    #[test]
    fn event_bus_dispatches_to_listeners() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut bus = EventBus::new();
        bus.subscribe(CountingListener {
            count: counter.clone(),
        });

        let event = AnalysisEvent::FormatDetected {
            format_label: "Windows PE".into(),
            extension: "exe".into(),
        };

        bus.emit(&event);
        bus.emit(&event);

        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn empty_bus_emits_without_panic() {
        let bus = EventBus::new();
        let event = AnalysisEvent::AnalysisComplete {
            path: PathBuf::from("test.exe"),
            verdict: "CLEAN".into(),
            duration_ms: 42,
        };
        assert!(bus.emit(&event));
    }

    #[test]
    fn listener_can_request_cancellation() {
        struct CancelListener;
        impl EventListener for CancelListener {
            fn on_event(&self, _event: &AnalysisEvent) -> bool {
                false // cancel
            }
        }

        let mut bus = EventBus::new();
        bus.subscribe(CancelListener);

        let event = AnalysisEvent::ParserStarting {
            parser_name: "test",
        };
        assert!(!bus.emit(&event));
    }
}
