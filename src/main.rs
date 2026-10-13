#[tokio::main]
async fn main() -> std::process::ExitCode {
    scanner_rs::agent_main().await
}
