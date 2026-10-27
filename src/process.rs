use std::io;
use tokio::process::{Child, Command};
use tokio::time::{Duration, sleep};

const BUSY_RETRIES: usize = 5;
const BUSY_RETRY_DELAY: Duration = Duration::from_millis(50);

pub(crate) async fn spawn(command: &mut Command) -> io::Result<Child> {
    let mut retries = 0;
    loop {
        match command.spawn() {
            Ok(child) => return Ok(child),
            // A freshly written executable can still have a writable descriptor
            // inherited by another concurrently spawning process until it execs.
            // Retry only this pre-exec failure; no child has started successfully.
            Err(error)
                if error.kind() == io::ErrorKind::ExecutableFileBusy && retries < BUSY_RETRIES =>
            {
                retries += 1;
                sleep(BUSY_RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn other_spawn_errors_are_returned_without_retry() {
        let missing = std::env::temp_dir().join(format!("missing-child-{}", uuid::Uuid::now_v7()));
        let started = tokio::time::Instant::now();
        let error = spawn(&mut Command::new(missing)).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }
}
