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
/// registered here because `fsutil` cannot depend on `ab-core`'s
/// metrics registry without a cycle; harness-level callers can wrap
/// this with their own counter if needed.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
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
            path = %path.display(),
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
