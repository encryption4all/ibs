//! `CLAUDE.md` is orientation, and nothing may refill it.
//!
//! The file was 2,969 B of migrated agent notes before #698 cut it: a CI job
//! list, the `curve25519-dalek` pin's grip on the RustCrypto stack, and the rand
//! 0.10 migration facts. All of it was either derivable from `README.md` and
//! `.github/workflows/`, or a durable check that belongs in the rule bundle the
//! host lands in a container at `~/dobby-rules.md`. Those are the two homes; this
//! file is the gate that keeps them from being ignored.
//!
//! 4,000 B is not cosmetic. It is the threshold that decides whether a container
//! working this repo gets its cwd pointed at the clone (dobby-code#482); above it
//! the checkout becomes a sibling directory instead. Raising the cap should be a
//! decision, not a reflex.

use std::fs;
use std::path::PathBuf;

const MAX_BYTES: u64 = 4_000;

fn claude_md() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("CLAUDE.md")
}

#[test]
fn claude_md_stays_orientation_sized() {
    let path = claude_md();
    // Measured on LF-normalised content: the Test job also runs on windows-latest,
    // where the checkout is CRLF and every line would otherwise cost an extra byte.
    let bytes = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
        .replace("\r\n", "\n")
        .len() as u64;

    assert!(
        bytes <= MAX_BYTES,
        "CLAUDE.md is {bytes} B, over the {MAX_BYTES} B cap. This file is ORIENTATION: what this \
         crate is, its position under PostGuard, and the sibling repos to weigh before changing \
         it. Documentation belongs at docs.postguard.eu/repos/ibs; a durable check belongs in the \
         rule bundle, not here."
    );
}

/// The corpus arrived under these headings in #25, so the regression is named
/// rather than left to the byte count alone: every one of them fits well inside
/// 4,000 B, so the size cap on its own would let any of them back in.
const CUT_SECTIONS: [&str; 5] = [
    "Agent notes (migrated from the dobby memory repo)",
    "Overview",
    "Release process",
    "CI",
    "RustCrypto 2025/26 + rand 0.10 API migration facts",
];

#[test]
fn claude_md_has_no_heading_from_the_cut_corpus() {
    let path = claude_md();
    let body =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    let headings: Vec<&str> = body
        .lines()
        .filter(|line| line.starts_with('#'))
        .map(|line| line.trim_start_matches('#'))
        .map(str::trim)
        .collect();

    for section in CUT_SECTIONS {
        assert!(
            !headings.contains(&section),
            "CLAUDE.md has a \"{section}\" heading again, at some level. That section went with the \
             agent-notes corpus (#698); it is documentation on docs.postguard.eu, a binding rule, or \
             history at a5bd441 now, not this file."
        );
    }
}

/// The pointer is the whole preservation mechanism: the corpus is not migrated
/// and not reconstructed, so a reader who needs it has only the revision this
/// file names. Dropping the line would satisfy both checks above.
#[test]
fn claude_md_still_names_the_revision_holding_the_corpus() {
    let path = claude_md();
    let body =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    assert!(
        body.contains("git show a5bd441:CLAUDE.md"),
        "CLAUDE.md no longer says where the cut corpus went. It lives only in git history at \
         a5bd441; without that line a reader cannot recover it."
    );
}
