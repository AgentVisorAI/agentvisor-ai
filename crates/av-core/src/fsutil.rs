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

/// POSIX `O_NOFOLLOW` open-flag value for the target platform. Used
/// alongside `std::os::unix::fs::OpenOptionsExt::custom_flags` to
/// refuse to follow a symlink at the file path being opened —
/// closes the symlink-plant confused-deputy class where a co-tenant
/// with write access to a spool directory pre-plants a symlink at
/// a deterministic file path so the harness's authenticated append
/// (running as the harness UID) is redirected to a file the
/// attacker can then read or overwrite.
///
/// Rather than pull in a `libc` / `rustix` dependency for one
/// constant this returns the POSIX-defined value directly; the
/// values are stable ABI and are drawn from the libc crate's
/// `constant.O_NOFOLLOW` documentation. On unknown Unix-like
/// platforms we fall back to the Linux value (a conservative
/// choice: a mismatch would surface as an `ELOOP`/`ENOTDIR`/`EACCES`
/// at first symlink attempt, not silent success).
#[cfg(unix)]
pub const fn unix_o_nofollow() -> i32 {
    #[cfg(target_os = "linux")]
    {
        0x20000
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        0x100
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        0x20000
    }
}

/// Return just the file name of `path` as a `&str`,
/// suitable for `path = %basename(&path)` in tracing macros.
///
/// The concern is downstream OTLP export. Every `tracing::warn!(path
/// = %path.display(), ...)` in this workspace flows through
/// `tracing_opentelemetry::layer` when the `otel` feature is on, so
/// absolute deployment paths (`/var/lib/agentvisor-ai/spool/...`,
/// custom outbox layouts, quarantine locations) land in whatever SIEM
/// ingests OTLP — the same path-leak class already closed on the
/// dashboard and on `%error` formatting of `reqwest::Error`,
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
        // `is_dir` (not `exists`): a regular FILE squatting on the path
        // must fall through to `create_dir_all`, which reports the
        // collision as an error — the existing-directory fast path below must
        // only skip the mkdir when the path truly is a directory.
        if dir.as_os_str().is_empty() || dir.is_dir() {
            break;
        }
        missing.push(dir.to_path_buf());
        current = dir.parent();
    }
    // Steady state is "every directory already exists" —
    // the walk above proved it with one stat, so skip the mkdir
    // entirely. `create_dir_all` on an existing path still issues an
    // mkdir syscall that returns EEXIST; at 5 call sites per request
    // that was ~500 pointless mkdirs/s at 100 req/s, a measurable slice
    // of the per-request metadata-op bill on network filesystems.
    if missing.is_empty() {
        return Ok(());
    }
    // Same posture as `write_atomic`: pin the directory bit to 0700
    // on Unix so the spool tree's confidentiality doesn't ride on
    // the operator's umask. All spool contents (ATIF trajectories,
    // receipts, journal envelopes) are already 0o600, but a 0755
    // parent lets a co-tenant enumerate the deterministic
    // `sha256(session-id)[..32]` file stems for probing / brute
    // force even when they cannot read the contents.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)?;
    }
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
/// (`avctl receipt-verify`) and the harness reconciler.
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
/// Shared between the CLI and the harness reconciler
/// so both audit tools and the long-running server
/// enforce identical resource bounds against on-disk tampering.
pub fn read_capped(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
    // Pre-open type check: `File::open` on a FIFO blocks until a writer
    // appears, so a special-file path hung the caller forever before
    // the post-open handle check below could refuse it (observed:
    // `avctl receipt-verify <fifo>` hanging indefinitely). `stat` does
    // not open the file, so it cannot block; the post-open handle check
    // remains the TOCTOU-safe authority.
    let pre = std::fs::metadata(path)?;
    if !pre.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a regular file (type: {:?})",
                basename(path),
                pre.file_type()
            ),
        ));
    }
    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        // Error messages must not embed the full
        // absolute path — they surface into logs (defeating the
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
/// content is textual.
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
/// function still returned `Err` in that case, which
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
    // Use `create_dir_all_synced` (not
    // `create_dir_all`) so the FIRST write into a new spool subtree
    // (`spool/outbox/`, `spool/receipts/`, `spool/tool-executions/`,
    // …) also fsyncs the newly-created ancestor entries. A bare
    // `create_dir_all` followed by fsyncing only the leaf on
    // line 206 left the ancestor dirents volatile — a power loss
    // between the initial `mkdir` and any ambient dirent sync
    // could drop the entire subtree, losing the marker even though
    // its bytes were fsynced. This durability gap was known and
    // deferred; the helper's fast path (skip when the
    // directory already exists) means the cost is only paid on
    // FIRST writes into a fresh directory tree.
    create_dir_all_synced(parent)?;
    let temporary = path.with_extension(format!("{}.tmp", crate::new_event_uid()));
    let mut guard = TempPathGuard::new(temporary.clone());
    // The temp file is `create_new` (exclusive create — refuses a
    // pre-planted symlink, per the audit-integrity contract this
    // module documents). Pair that with an EXPLICIT 0o600 mode on
    // Unix so the file's confidentiality does not depend on the
    // caller's umask. ATIF trajectories carry full prompt/response
    // transcripts; receipts carry identity, cost, and instance_uid;
    // `.session.json` sidecars carry auth session state. On a host
    // where umask is the default 0022, a bare `create_new` produces
    // 0644 — world-readable by any co-tenant with `execute` on the
    // spool directory. The 0o600 mode closes that surface uniformly
    // for every spool site that uses this helper.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
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

/// Remove crash-orphaned `*.tmp` files under `root`, recursively.
///
/// The RAII unlink in [`write_atomic`]/[`TempPathGuard`] cannot run when
/// the process is SIGKILLed between `create_new` and `rename`, so crash
/// loops accumulate orphaned temp files linearly forever (empirically:
/// 16 stranded temps across a 19-SIGKILL stress run, surviving every
/// recovery pass) — the exact inode-exhaustion class the module doc
/// promises to prevent. Callers MUST invoke this only at boot, before
/// any concurrent writer exists, because a live writer's in-flight temp
/// is indistinguishable from an orphan. UUIDv7 suffixes guarantee a
/// name deleted here can never be re-created by a later writer.
///
/// Returns the number of files removed. Errors on individual entries
/// are skipped (a temp that cannot be removed is the pre-existing
/// condition, not a boot failure); only the root read errors surface.
pub fn sweep_orphaned_tmp(root: &Path) -> io::Result<u64> {
    const MAX_SWEEP_DEPTH: usize = 8;
    fn walk(dir: &Path, depth: usize, removed: &mut u64) {
        if depth > MAX_SWEEP_DEPTH {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                walk(&path, depth + 1, removed);
            } else if file_type.is_file()
                && path
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|name| name.ends_with(".tmp"))
                && std::fs::remove_file(&path).is_ok()
            {
                *removed += 1;
            }
        }
    }
    match std::fs::metadata(root) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    }
    let mut removed = 0u64;
    walk(root, 0, &mut removed);
    Ok(removed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Mutation-run hardening: `read_capped_string` (the manifest /
    /// watermark / key-file read used at every control-plane trust
    /// boundary) had no direct test — mutants returning a fixed string
    /// survived. Pin content round-trip and the over-cap refusal.
    #[test]
    fn read_capped_string_round_trips_and_refuses_over_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("value.txt");
        std::fs::write(&path, "expected-content").unwrap();
        assert_eq!(
            read_capped_string(&path, MAX_CONTROL_BYTES).unwrap(),
            "expected-content"
        );
        assert!(read_capped_string(&path, 4).is_err(), "over-cap read must refuse");
    }

    /// R18: spool files created via `write_atomic` MUST be 0o600 on
    /// Unix. ATIF trajectories carry full user transcripts, receipts
    /// carry identity + cost, journal metadata carries session
    /// state. Any co-tenant with `execute` on the spool directory
    /// used to be able to `cat` these files under the default 0022
    /// umask; the explicit mode bit closes that surface uniformly.
    #[test]
    #[cfg(unix)]
    fn write_atomic_produces_owner_only_files() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        // A subdirectory that doesn't yet exist forces
        // `create_dir_all_synced` to run too.
        let path = dir.path().join("nested").join("payload.bin");
        write_atomic(&path, b"secret").unwrap();
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            file_mode, 0o600,
            "spool files must be owner-only; got {file_mode:o}"
        );
        // And the newly-created ancestor dir must be 0o700 too, so a
        // co-tenant with a permissive umask on the harness process
        // still can't enumerate the deterministic
        // sha256-of-session-id filename stems.
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "spool subdirectories must be owner-only; got {dir_mode:o}"
        );
    }

    /// R18: `write_atomic` MUST refuse to follow a symlink placed
    /// at the destination path (the symlink-plant confused-deputy
    /// class). The exclusive-create on the temp closes the temp
    /// side; the destination side is closed because `rename` on
    /// Unix REPLACES the target atomically (never follows). Verify
    /// end-to-end: a symlink at `path` gets replaced by the new
    /// file, and the symlink target is UNCHANGED.
    #[test]
    #[cfg(unix)]
    fn write_atomic_replaces_symlink_without_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim-should-be-untouched");
        std::fs::write(&victim, b"original-target-contents").unwrap();
        let spool_target = dir.path().join("payload.bin");
        std::os::unix::fs::symlink(&victim, &spool_target).unwrap();
        write_atomic(&spool_target, b"fresh").unwrap();
        // The symlink was replaced (not followed).
        assert_eq!(std::fs::read(&spool_target).unwrap(), b"fresh");
        // The symlink's original target is untouched.
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"original-target-contents",
            "write_atomic must not follow the symlink — it replaces at rename time"
        );
    }

    /// R18: `unix_o_nofollow()` returns the platform's actual
    /// `O_NOFOLLOW` value — verify by using it as a flag on
    /// `OpenOptions::custom_flags` and confirming that a symlink
    /// open FAILS while a regular file open succeeds. A wrong-value
    /// constant would either silently follow symlinks (bug) or
    /// error on regular files (also bug); this test catches both.
    #[test]
    #[cfg(unix)]
    fn unix_o_nofollow_flag_refuses_symlinks_but_permits_regular_files() {
        use std::os::unix::fs::OpenOptionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        // Regular file with the flag: opens fine.
        let regular = dir.path().join("regular");
        std::fs::write(&regular, b"hi").unwrap();
        let ok = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(unix_o_nofollow())
            .open(&regular);
        assert!(ok.is_ok(), "O_NOFOLLOW must permit regular files: {ok:?}");
        // Symlink with the flag: MUST fail (ELOOP on most Unix).
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"target").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let err = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(unix_o_nofollow())
            .open(&link);
        assert!(
            err.is_err(),
            "O_NOFOLLOW must refuse symlinks (guards the confused-deputy \
             class); constant value {:#x} may be wrong for this platform",
            unix_o_nofollow()
        );
    }

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

    /// Fast path: an existing directory short-circuits
    /// before the mkdir, and — the regression the `is_dir` check
    /// guards — a regular FILE squatting on the path must still
    /// surface as an error, not silently "succeed".
    #[test]
    fn create_dir_all_synced_existing_dir_is_ok_but_file_collision_errors() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a/b");
        create_dir_all_synced(&target).unwrap();
        // Second call: the steady-state fast path.
        create_dir_all_synced(&target).unwrap();
        assert!(target.is_dir());

        let file = dir.path().join("occupied");
        std::fs::write(&file, b"x").unwrap();
        assert!(
            create_dir_all_synced(&file).is_err(),
            "a file squatting on the directory path must error"
        );
        assert!(
            create_dir_all_synced(&file.join("child")).is_err(),
            "a file squatting on an ANCESTOR must error"
        );
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

    /// Mutation-run hardening: `read_capped -> Ok(vec![])`
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

    #[test]
    fn sweep_orphaned_tmp_removes_only_tmp_files_recursively() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("receipts").join("deep");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(dir.path().join("a.json.0198.tmp"), b"orphan").unwrap();
        std::fs::write(nested.join("b.receipt.0199.tmp"), b"").unwrap();
        std::fs::write(dir.path().join("keep.json"), b"real").unwrap();
        std::fs::write(nested.join("keep.ndjson"), b"real").unwrap();
        let removed = sweep_orphaned_tmp(dir.path()).unwrap();
        assert_eq!(removed, 2, "exactly the two .tmp orphans");
        assert!(dir.path().join("keep.json").exists());
        assert!(nested.join("keep.ndjson").exists());
        assert!(!dir.path().join("a.json.0198.tmp").exists());
        assert!(!nested.join("b.receipt.0199.tmp").exists());
        // Missing root is a clean no-op (fresh install).
        assert_eq!(sweep_orphaned_tmp(&dir.path().join("absent")).unwrap(), 0);
    }

    /// Mutation-run hardening (round 8): the MAX_SWEEP_DEPTH guard had
    /// surviving `>` boundary and `depth + 1` arithmetic mutants — no
    /// test placed orphans at the depth edge. The contract: an orphan
    /// 8 directories down is still swept; 9 down is left alone (the
    /// bound exists so a symlink-cycle-shaped tree cannot walk
    /// forever).
    #[test]
    fn sweep_depth_bound_is_exact() {
        let dir = tempfile::tempdir().unwrap();
        let mut at_bound = dir.path().to_path_buf();
        for i in 0..8 {
            at_bound.push(format!("d{i}"));
        }
        std::fs::create_dir_all(&at_bound).unwrap();
        std::fs::write(at_bound.join("edge.0200.tmp"), b"").unwrap();
        let mut past_bound = at_bound.clone();
        past_bound.push("d8");
        std::fs::create_dir_all(&past_bound).unwrap();
        std::fs::write(past_bound.join("deep.0201.tmp"), b"").unwrap();

        let removed = sweep_orphaned_tmp(dir.path()).unwrap();
        assert_eq!(removed, 1, "exactly the at-bound orphan");
        assert!(
            !at_bound.join("edge.0200.tmp").exists(),
            "an orphan at depth 8 (the bound) must be swept"
        );
        assert!(
            past_bound.join("deep.0201.tmp").exists(),
            "an orphan at depth 9 (past the bound) must be left alone"
        );
    }

    /// Mutation-run hardening (round 8): only NotFound may downgrade to
    /// the Ok(0) no-op — a mutant widening the guard to every metadata
    /// error silently swallowed permission faults, hiding a broken
    /// spool from the boot sequence that relies on this sweep.
    #[cfg(unix)]
    #[test]
    fn sweep_surfaces_non_notfound_root_errors() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("locked");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o000)).unwrap();
        let denied = std::fs::metadata(root.join("probe")).is_err() && std::fs::read_dir(&root).is_err();
        if denied {
            // metadata(root) itself succeeds (the parent is traversable);
            // the sweep must not mask the unreadable directory as Ok —
            // walk() skips unreadable dirs by design, so assert only the
            // NotFound arm stays narrow: a root whose metadata errors
            // with EACCES must surface. Build that shape: a child of the
            // locked dir is unstattable.
            let unreachable_root = root.join("inner");
            assert!(
                sweep_orphaned_tmp(&unreachable_root).is_err(),
                "an EACCES root must surface as an error, not a silent Ok(0)"
            );
        }
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}
