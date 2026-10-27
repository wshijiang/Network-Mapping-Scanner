//! Bounded recovery for transient executable write handles during concurrent fork/exec.
use std::io;
use tokio::{
    process::{Child, Command},
    time::{Duration, Instant, sleep},
};

pub(crate) async fn spawn(command: &mut Command) -> io::Result<Child> {
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match command.spawn() {
            Err(error)
                if error.kind() == io::ErrorKind::ExecutableFileBusy
                    && Instant::now() < deadline =>
            {
                sleep(Duration::from_millis(5)).await;
            }
            result => return result,
        }
    }
}
