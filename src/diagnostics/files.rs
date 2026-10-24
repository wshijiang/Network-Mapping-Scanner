use super::protocol::*;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub fn digest(bytes: &[u8]) -> String {
    crate::modules::package::hex(&Sha256::digest(bytes))
}

pub struct LogDirectory {
    directory: PathBuf,
    root: File,
}

impl LogDirectory {
    pub fn open(directory: &Path) -> io::Result<Self> {
        let directory = directory.canonicalize()?;
        let root = File::open(&directory)?;
        if !root.metadata()?.is_dir() {
            return Err(io::Error::other("invalid_log_directory"));
        }
        Ok(Self { directory, root })
    }

    fn open_log(&self, name: &str) -> io::Result<File> {
        if !valid_log_name(name) {
            return Err(io::Error::other("invalid_log_name"));
        }
        #[cfg(unix)]
        let file = {
            use std::os::fd::{AsRawFd, FromRawFd};
            let name = std::ffi::CString::new(name).map_err(io::Error::other)?;
            // SAFETY: root is a live directory fd and name is a validated NUL-terminated basename.
            let fd = unsafe {
                libc::openat(
                    self.root.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful openat returns a new fd, owned only by this File.
            unsafe { File::from_raw_fd(fd) }
        };
        #[cfg(not(unix))]
        let file = {
            let path = self.directory.join(name);
            if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
                return Err(io::Error::other("log_symlink_rejected"));
            }
            File::open(path)?
        };
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("log_not_regular_file"));
        }
        Ok(file)
    }

    fn describe(&self, name: &str, file: &File) -> io::Result<SourceFile> {
        let meta = file.metadata()?;
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            format!(
                "{name}:{}:{}:{:?}",
                meta.dev(),
                meta.ino(),
                meta.created().ok()
            )
        };
        #[cfg(not(unix))]
        let identity = format!("{name}:{:?}", meta.created().ok());
        Ok(SourceFile {
            source_file_id: digest(identity.as_bytes()),
            name: name.to_owned(),
            size_bytes: meta.len(),
            modified_at: DateTime::from(meta.modified()?),
            active: name == format!("scanner.log.{}", Utc::now().format("%Y-%m-%d")),
        })
    }

    pub fn list(&self) -> io::Result<Vec<SourceFile>> {
        let mut names: Vec<_> = std::fs::read_dir(&self.directory)?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| valid_log_name(name))
            .collect();
        names.sort();
        let mut sources = Vec::new();
        for name in names.into_iter().rev().take(128) {
            if let Ok(file) = self.open_log(&name) {
                sources.push(self.describe(&name, &file)?);
            }
        }
        sources.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(sources)
    }

    pub fn snapshot(
        &self,
        source: &SourceFile,
        path: &Path,
        file_id: uuid::Uuid,
    ) -> io::Result<Snapshot> {
        let mut file = self.open_log(&source.name)?;
        let current = self.describe(&source.name, &file)?;
        if current.source_file_id != source.source_file_id {
            return Err(io::Error::other("log_file_changed"));
        }
        if current.size_bytes > MAX_FILE_BYTES {
            return Err(io::Error::other("log_file_too_large"));
        }
        let captured_at = Utc::now();
        let size = complete_prefix(&mut file, current.size_bytes)?;
        file.seek(SeekFrom::Start(0))?;
        let temporary = path.with_extension("tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&temporary)?;
        let mut remaining = size;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        while remaining > 0 {
            let limit = (remaining as usize).min(buffer.len());
            let read = file.read(&mut buffer[..limit])?;
            if read == 0 {
                return Err(io::Error::other("log_file_changed"));
            }
            hasher.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
            remaining -= read as u64;
        }
        // Re-reading metadata detects truncation, but normal appends are allowed.
        if file.metadata()?.len() < current.size_bytes {
            return Err(io::Error::other("log_file_changed"));
        }
        output.sync_all()?;
        std::fs::rename(temporary, path)?;
        Ok(Snapshot {
            file_id,
            source: current.clone(),
            captured_at,
            size_bytes: size,
            excluded_tail_bytes: current.size_bytes - size,
            sha256: crate::modules::package::hex(&hasher.finalize()),
        })
    }
}

fn complete_prefix(file: &mut File, length: u64) -> io::Result<u64> {
    // Search backwards in bounded blocks. Never hold an entire large line in memory.
    let mut end = length;
    let mut buffer = [0_u8; 8192];
    while end > 0 {
        let start = end.saturating_sub(buffer.len() as u64);
        file.seek(SeekFrom::Start(start))?;
        let size = (end - start) as usize;
        file.read_exact(&mut buffer[..size])?;
        if let Some(index) = buffer[..size].iter().rposition(|b| *b == b'\n') {
            return Ok(start + index as u64 + 1);
        }
        end = start;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_preserves_standard_sha256_vectors() {
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn snapshot_excludes_half_line_and_preserves_original_after_append() {
        let root =
            std::env::temp_dir().join(format!("scanner-diagnostics-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("scanner.log.2026-10-01");
        std::fs::write(&source, b"{}\n{half").unwrap();
        std::fs::write(root.join("config.toml"), b"secret").unwrap();
        let dir = LogDirectory::open(&root).unwrap();
        let sources = dir.list().unwrap();
        assert_eq!(sources.len(), 1);
        let snapshot_path = root.join("snapshot");
        let snapshot = dir
            .snapshot(&sources[0], &snapshot_path, uuid::Uuid::now_v7())
            .unwrap();
        assert_eq!(snapshot.size_bytes, 3);
        assert_eq!(snapshot.excluded_tail_bytes, 5);
        assert_eq!(snapshot.sha256, digest(b"{}\n"));
        OpenOptions::new()
            .append(true)
            .open(&source)
            .unwrap()
            .write_all(b"}\n")
            .unwrap();
        assert_eq!(std::fs::read(snapshot_path).unwrap(), b"{}\n");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn directory_rejects_symlinks_and_replaced_files() {
        let root =
            std::env::temp_dir().join(format!("scanner-diagnostics-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("scanner.log.2026-10-01");
        std::fs::write(&path, b"{}\n").unwrap();
        let dir = LogDirectory::open(&root).unwrap();
        let source = dir.list().unwrap().remove(0);
        std::fs::rename(&path, root.join("old")).unwrap();
        std::os::unix::fs::symlink(root.join("old"), &path).unwrap();
        assert!(dir.list().unwrap().is_empty());
        assert!(
            dir.snapshot(&source, &root.join("snapshot"), uuid::Uuid::now_v7())
                .is_err()
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"{}\n").unwrap();
        assert!(
            dir.snapshot(&source, &root.join("snapshot"), uuid::Uuid::now_v7())
                .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
