//! Shared integration-test helpers.

use core::ffi::c_int;

use corus_core::corus_syscall::linux::EPERM;

/// Classification of a dump attempt used by test skip logic.
pub(crate) enum DumpFailure {
    /// The dump succeeded.
    Success,
    /// The dump failed because ptrace permission is denied or probably denied.
    PtraceDenied(String),
    /// The dump failed for a reason that should fail the test.
    Unexpected(String),
}

/// Result-like values produced by dump API tests.
pub(crate) trait DumpOutcome {
    /// Classify this outcome for ptrace skip handling.
    fn classify(self) -> DumpFailure;
}

impl DumpOutcome for c_int {
    fn classify(self) -> DumpFailure {
        if self == 0 {
            DumpFailure::Success
        } else {
            DumpFailure::PtraceDenied(format!("C ABI returned {self}"))
        }
    }
}

impl DumpOutcome for Result<(), corus::Error> {
    fn classify(self) -> DumpFailure {
        match self {
            Ok(()) => DumpFailure::Success,
            Err(corus::Error::Core(corus_core::CoreDumpError::ThreadList(EPERM))) => {
                DumpFailure::PtraceDenied("EPERM".to_string())
            }
            Err(error) => DumpFailure::Unexpected(format!("{error:?}")),
        }
    }
}

/// Return true when a dump failed because ptrace is unavailable in the test environment.
pub(crate) fn ptrace_denied(outcome: impl DumpOutcome, context: &str) -> bool {
    match outcome.classify() {
        DumpFailure::Success => false,
        DumpFailure::PtraceDenied(detail) => {
            eprintln!("skipping: {context} failed ({detail}; ptrace permission)");
            true
        }
        DumpFailure::Unexpected(detail) => panic!("{context} failed unexpectedly: {detail}"),
    }
}
