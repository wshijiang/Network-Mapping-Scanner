use std::{fs::File, io};

pub(crate) struct ExclusiveFileLock(File);

impl ExclusiveFileLock {
    pub(crate) fn acquire(file: File) -> io::Result<Self> {
        fs2::FileExt::try_lock_exclusive(&file)?;
        Ok(Self(file))
    }

    #[cfg(test)]
    pub(crate) fn try_clone_file(&self) -> io::Result<File> {
        self.0.try_clone()
    }
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        // Closing our descriptor alone can leave the lock held by a concurrent
        // fork until that child execs. Release it when its actual owner is done.
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    #[test]
    fn owner_releases_lock_even_while_a_duplicate_descriptor_remains_open() {
        let path = std::env::temp_dir().join(format!("file-lock-{}", uuid::Uuid::now_v7()));
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let duplicate = file.try_clone().unwrap();
        let owner = ExclusiveFileLock::acquire(file).unwrap();
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(fs2::FileExt::try_lock_exclusive(&contender).is_err());
        drop(owner);
        let next_owner = ExclusiveFileLock::acquire(contender).unwrap();
        drop(next_owner);
        drop(duplicate);
        std::fs::remove_file(path).unwrap();
    }
}
