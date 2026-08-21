//! Cross-platform filesystem helpers.
//!
//! `sync_directory` durably persists directory entries on platforms where the
//! operating system supports it (Unix `fsync` on a directory file descriptor).
//! On Windows there is no supported way to flush a directory handle
//! (`FlushFileBuffers` requires a file, and opening a directory for `File::open`
//! yields `PermissionDenied`), so this is a no-op there — NTFS journals
//! metadata changes so a rename is durable once the containing file has been
//! `sync_all`'d.

use std::io;
use std::path::Path;

/// Round-36 F1: return just the file name of `path` as a `&str`,
/// suitable for `path = %basename(&path)` in tracing macros.
///
/// The concern is downstream OTLP export. Every `tracing::warn!(path
/// = %path.display(), ...)` in this workspace flows through
/// `tracing_opentelemetry::layer` when the `otel` feature is on, so
/// absolute deployment paths (`/var/lib/agentvisor-ai/spool/...`,
/// custom outbox layouts, quarantine locations) land in whatever SIEM
/// ingests OTLP — same class of leak round-27 F6 closed on the
/// dashboard and round-35 F1/F2 closed on `%error` on `reqwest::Error`,
/// with a different producer / same sink. `basename` keeps enough
/// context for operator triage (the file name usually encodes the
/// session id or offset) without leaking the deployment topology.
/// Non-UTF-8 file names or paths that end in `..` fall back to `?`;
/// callers who need the full path server-side may still route it
/// through a separate operator-only log channel.
pub fn basename(path: &Path) -> &str {
    path.file_name().and_then(|name| name.to_str()).unwrap_or("?")
}

/// Fsync a directory so its rename/create entries are durable after a crash.
///
/// On Unix this opens the directory and calls `sync_all` on the descriptor.
/// On Windows it is a no-op (see module docs).
pub fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Create `path` and any missing ancestors, then fsync the parent of every
/// directory that was newly created so the dirents naming them survive a
/// crash. A bare `create_dir_all` + `sync_directory(leaf)` leaves newly
/// created *ancestor* entries volatile: a power loss can drop the whole
/// subtree even though the leaf's own contents were fsynced.
pub fn create_dir_all_synced(path: &Path) -> io::Result<()> {
    let mut missing: Vec<std::path::PathBuf> = Vec::new();
    let mut current = Some(path);
    while let Some(dir) = current {
        if dir.as_os_str().is_empty() || dir.exists() {
            break;
        }
        missing.push(dir.to_path_buf());
        current = dir.parent();
    }
    std::fs::create_dir_all(path)?;
    // Highest new ancestor first, so each synced parent already exists.
    for dir in missing.iter().rev() {
        if let Some(parent) = dir.parent() {
            if !parent.as_os_str().is_empty() {
                sync_directory(parent)?;
            }
        }
    }
    Ok(())
}

/// Receipts JCS-canonicalize to a few hundred bytes; even a huge
/// tool-call summary stays well under 16 MiB. Shared between the CLI
/// (`avctl receipt-verify`) and the harness reconciler (round-17 F3).
pub const MAX_RECEIPT_BYTES: u64 = 16 * 1024 * 1024;

/// ATIF trajectories can carry long transcripts; 64 MiB is generous
/// (a 200k-token GPT-4 context in ASCII fits in ~800 KiB).
pub const MAX_ATIF_BYTES: u64 = 64 * 1024 * 1024;

/// Small-file caps for control-plane files (config sidecars, journal
/// metadata, marker files, ack files). 1 MiB is well above any real
/// legitimate content but small enough that a hostile plant cannot
/// materialize an OOM before the parser complains.
pub const MAX_CONTROL_BYTES: u64 = 1024 * 1024;

/// Read a file into memory subject to a hard byte cap, refusing
/// non-regular files. The size check runs on the OPEN handle (not
/// the path — closes the TOCTOU race where a symlink target is
/// swapped between `metadata()` and `read()`), and the read itself
/// uses `Read::take` so a target that grows after the metadata
/// check still cannot exceed the cap.
///
/// Shared between the CLI (round-16 F5) and the harness reconciler
/// (round-17 F3) so both audit tools and the long-running server
/// enforce identical resource bounds against on-disk tampering.
pub fn read_capped(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        // Round-6 (hunt4 F13): error messages must not embed the full
        // absolute path — they surface into logs (defeating the round-36
        // basename discipline) and into HTTP close/promote error bodies.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a regular file (type: {:?})",
                basename(path),
                metadata.file_type()
            ),
        ));
    }
    if metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is {} bytes; refusing to load more than {max_bytes}",
                basename(path),
                metadata.len()
            ),
        ));
    }
    let mut buf: Vec<u8> = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} grew past {max_bytes} bytes during read; refusing",
                basename(path)
            ),
        ));
    }
    Ok(buf)
}

/// UTF-8 variant of [`read_capped`]. Used by the CLI for
/// operator-supplied config / manifest / bearer token files where
/// content is textual (round-17 F6).
pub fn read_capped_string(path: &Path, max_bytes: u64) -> io::Result<String> {
    let bytes = read_capped(path, max_bytes)?;
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Durably write `bytes` to `path` via create-tmp + fsync + rename + parent fsync.
///
/// The temporary file uses a UUIDv7-derived suffix to avoid collision with any
/// concurrent writer targeting the same final path, and is opened with
/// `create_new` so a stale suffix collision fails safely instead of clobbering.
/// Callers that already hold the parent directory pass any `Path`; missing
/// parents are created before the temp file is opened.
///
/// If any step between temp creation and rename fails, the temp file is
/// unlinked via an RAII guard so we never leak zero-byte `.tmp` files into
/// the spool. A repeatedly-failing writer would otherwise fill the inode
/// table on ext4/xfs long before the disk is full — an operational silent
/// death.
///
/// **Semantics of `Ok(())` vs `Err(...)` after `rename`:** once the tmp file
/// has been atomically renamed onto `path`, the caller can consider the
/// data durably visible. A post-rename `sync_directory` failure means the
/// dirent may not survive an *immediate* power loss on POSIX-conformant
/// filesystems (xfs, btrfs, ext4 with `data=ordered`), but the file is
/// present and readable for every observer running now. Historically this
/// function still returned `Err` in that case (round-12 F5), which
/// misled callers whose retry logic assumes "Err → not present": they
/// would either double-write (harmless but wasted IO) or, worse, treat
/// the write as failed and skip session-state advancement while the
/// file was in fact readable — producing a hard split between on-disk
/// state and in-registry accounting.
///
/// Fix: post-rename `sync_directory` failure now becomes a
/// `tracing::warn!` (best-effort) and `Ok(())` is returned. Callers
/// that need a stronger guarantee should call `sync_directory` again
/// after their own operation completes. A dedicated counter is not
/// registered here because the metrics `Registry` is instance-scoped
/// (there is no global registry) and this free function holds no
/// registry handle; harness-level callers can wrap
/// this with their own counter if needed.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    // `Path::new("file.json").parent()` is `Some("")`, not `None` — the
    // empty path fails `sync_directory` (and is not a valid directory for
    // `create_dir_all` on all platforms). Normalize to `.` so relative
    // leaf paths behave like `./file.json`.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Round-23 F1 (av-core fsutil): use `create_dir_all_synced` (not
    // `create_dir_all`) so the FIRST write into a new spool subtree
    // (`spool/outbox/`, `spool/receipts/`, `spool/tool-executions/`,
    // …) also fsyncs the newly-created ancestor entries. A bare
    // `create_dir_all` followed by fsyncing only the leaf on
    // line 206 left the ancestor dirents volatile — a power loss
    // between the initial `mkdir` and any ambient dirent sync
    // could drop the entire subtree, losing the marker even though
    // its bytes were fsynced. This is the durability gap round-21
    // flagged and deferred; the helper's fast path (skip when the
    // directory already exists) means the cost is only paid on
    // FIRST writes into a fresh directory tree.
    create_dir_all_synced(parent)?;
    let temporary = path.with_extension(format!("{}.tmp", crate::new_event_uid()));
    let mut guard = TempPathGuard::new(temporary.clone());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    guard.disarm();
    if let Err(error) = sync_directory(parent) {
        // Best-effort — the rename already succeeded so `path` is
        // observable. Log the failure so operators can investigate
        // filesystem or disk issues; do NOT return Err, which would
        // wrongly steer callers into "the file is not there" retry
        // logic.
        tracing::warn!(
            path = %basename(path),
            error = %error,
            "post-rename directory fsync failed; file is visible but its dirent may not survive an immediate power loss"
        );
    }
    Ok(())
}

/// RAII guard that unlinks a temp path unless [`disarm`](Self::disarm) is
/// called. Used to prevent orphan `.tmp` files when an intermediate step
/// between `File::create` and `rename` fails.
///
/// Public so callers with their own atomic-rename recipes (harness
/// `install_seed_exclusive`, per-crate tmp files) can reuse the same
/// unlink-on-drop discipline as [`write_atomic`].
pub struct TempPathGuard {
    path: Option<std::path::PathBuf>,
}

impl TempPathGuard {
    /// Arm the guard: `path` will be unlinked when the guard drops
    /// unless [`disarm`](Self::disarm) is called first.
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Consume the guard without unlinking (call once the temp has been
    /// successfully renamed into its final path).
    pub fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Round-36 F1: `basename` is a canonical name for the fix to
    /// the "path.display() in tracing → OTLP → SIEM leak" class.
    /// Assert the property callers rely on: never returns the
    /// parent directory, always the last segment.
    #[test]
    fn basename_returns_only_the_last_segment() {
        assert_eq!(
            basename(Path::new("/var/lib/agentvisor-ai/spool/foo.json")),
            "foo.json"
        );
        assert_eq!(basename(Path::new("foo.json")), "foo.json");
        assert_eq!(basename(Path::new("/tmp/")), "tmp");
        // Empty path / root is meaningless in the caller context —
        // fall back to `?` rather than panic.
        assert_eq!(basename(Path::new("/")), "?");
        // Non-UTF-8 path names fall back to `?` (safe default; the
        // full path could be smuggled if we tried lossy conversion).
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt as _;
            let raw = std::path::PathBuf::from(OsStr::from_bytes(b"/x/\xff\xfe"));
            assert_eq!(basename(&raw), "?");
        }
    }

    #[test]
    fn write_atomic_creates_parent_and_writes_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("nested/dir/output.bin");
        write_atomic(&target, b"hello").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
    }

    #[test]
    fn write_atomic_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("output.bin");
        std::fs::write(&target, b"old").unwrap();
        write_atomic(&target, b"new").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }

    #[test]
    fn write_atomic_leaves_no_temp_files_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("output.bin");
        for _ in 0..8 {
            write_atomic(&target, b"payload").unwrap();
        }
        let residual: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(residual.is_empty(), "stale temp files: {residual:?}");
    }

    /// The RAII guard must unlink the tmp file when a step after
    /// creation panics (simulating `write_all`/`sync_all`/`rename`
    /// failure). Without the guard, a spool directory can accumulate
    /// millions of zero-byte `.tmp` files after a bad disk day and
    /// blow through the ext4 inode table long before disk-full
    /// triggers any alert.
    #[test]
    fn temp_path_guard_unlinks_when_dropped_armed() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("aborted.tmp");
        std::fs::write(&tmp, b"partial").unwrap();
        {
            let _guard = TempPathGuard::new(tmp.clone());
            // simulate an early return: guard drops without disarm
        }
        assert!(!tmp.exists(), "guard failed to unlink tmp on drop");
    }

    #[test]
    fn temp_path_guard_leaves_file_alone_when_disarmed() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("kept.tmp");
        std::fs::write(&tmp, b"kept").unwrap();
        {
            let mut guard = TempPathGuard::new(tmp.clone());
            guard.disarm();
        }
        assert!(tmp.exists(), "disarmed guard must not touch the file");
    }
}

#[cfg(test)]
mod read_capped_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// Mutation-run hardening (round 12): `read_capped -> Ok(vec![])`
    /// survived — nothing asserted the reader actually returns the file
    /// bytes or enforces its cap at the exact boundary.
    #[test]
    fn read_capped_roundtrips_and_enforces_the_exact_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        let content = b"agentvisor-read-capped-fixture".to_vec();
        std::fs::write(&path, &content).unwrap();
        // Content comes back verbatim…
        assert_eq!(read_capped(&path, MAX_CONTROL_BYTES).unwrap(), content);
        // …a cap of exactly the length succeeds…
        assert_eq!(read_capped(&path, content.len() as u64).unwrap(), content);
        // …and one byte under the length is refused, not truncated.
        let under = read_capped(&path, content.len() as u64 - 1);
        assert!(under.is_err(), "under-cap read must refuse, got {under:?}");
        // Non-regular files are refused (directory).
        assert!(read_capped(dir.path(), MAX_CONTROL_BYTES).is_err());
    }

    /// The workspace-wide byte caps are load-bearing resource bounds;
    /// pin their values so arithmetic mutants can't silently shrink or
    /// inflate them.
    #[test]
    fn byte_caps_are_pinned() {
        assert_eq!(MAX_RECEIPT_BYTES, 16 * 1024 * 1024);
        assert_eq!(MAX_ATIF_BYTES, 64 * 1024 * 1024);
        assert_eq!(MAX_CONTROL_BYTES, 1024 * 1024);
    }
}
