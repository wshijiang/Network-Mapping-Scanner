use super::protocol::*;
use crate::{
    error::ScannerError,
    journal::{CheckpointSink, ScanJournal},
    scan::{
        ScanObservation,
        engines::{dns, masscan, nuclei, zgrab2},
        plan::ScanStageKind,
    },
};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};
use uuid::Uuid;

struct Writer {
    sequence: u64,
    id: Uuid,
    output: io::Stdout,
}
impl Writer {
    fn send(&mut self, body: EventBody) -> Result<u64, ScannerError> {
        let sequence = self.sequence;
        write_sync(
            &mut self.output,
            &Event {
                id: self.id,
                sequence,
                body,
            },
        )?;
        self.sequence += 1;
        Ok(sequence)
    }
}

struct RemoteJournal<'a> {
    writer: &'a Mutex<Writer>,
    acks: Mutex<mpsc::Receiver<(Uuid, u64)>>,
}
impl RemoteJournal<'_> {
    fn acknowledged(&self, body: EventBody) -> Result<(), ScannerError> {
        let (id, sequence) = {
            let mut writer = self.writer.lock().unwrap();
            (writer.id, writer.send(body)?)
        };
        let ack = self
            .acks
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(60))
            .map_err(|_| ScannerError::Scan("agent did not acknowledge checkpoint".into()))?;
        if ack != (id, sequence) {
            return Err(ScannerError::Scan(
                "invalid checkpoint acknowledgement".into(),
            ));
        }
        Ok(())
    }
}
impl CheckpointSink for RemoteJournal<'_> {
    fn save(
        &self,
        stage: usize,
        chunk: usize,
        elapsed_ms: u64,
        observations: Option<&[ScanObservation]>,
    ) -> Result<(), ScannerError> {
        if let Some(part) = observations {
            for observation in part {
                self.writer
                    .lock()
                    .unwrap()
                    .send(EventBody::CheckpointPart {
                        observation: Box::new(observation.clone()),
                    })?;
            }
        }
        self.acknowledged(EventBody::CheckpointSave {
            stage,
            chunk,
            elapsed_ms,
            has_part: observations.is_some(),
        })
    }
    fn start_block(&self) -> Result<(), ScannerError> {
        self.acknowledged(EventBody::BlockStarted)
    }
}

/// A one-request worker, with a dedicated control reader so cancellation and ACKs
/// are processed while the engine is running. No identity or database is loaded.
pub async fn worker_main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_ansi(false)
        .init();
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("worker: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), ScannerError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 || args[0] != "--stage" {
        return Err(ScannerError::Config(
            "usage: scanner-worker --stage <stage> [--preflight]".into(),
        ));
    }
    let stage: ScanStageKind = serde_json::from_value(serde_json::Value::String(args[1].clone()))?;
    if args.len() > 3 || (args.len() == 3 && args[2] != "--preflight") {
        return Err(ScannerError::Config("invalid worker options".into()));
    }
    let writer = Mutex::new(Writer {
        sequence: 0,
        id: Uuid::nil(),
        output: io::stdout(),
    });
    writer.lock().unwrap().send(EventBody::Hello {
        ipc_version: IPC_VERSION,
        stage,
        version: env!("CARGO_PKG_VERSION").into(),
    })?;
    if args.len() == 3 {
        return Ok(());
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let reader_cancel = cancel.clone();
    let (ready_tx, mut ready_rx) = tokio::sync::mpsc::channel(1);
    let (ack_tx, ack_rx) = mpsc::sync_channel(1);
    // stdio is read on its own OS thread, including while synchronous journal
    // callbacks are waiting for a durable ACK from the agent.
    std::thread::spawn(move || {
        let result = (|| -> Result<(), ScannerError> {
            let mut input = io::stdin();
            let mut request = match read_sync(&mut input)? {
                Command::Execute { request } => request,
                _ => return Err(ScannerError::Scan("expected execute".into())),
            };
            if request.stage != stage || request.id.is_nil() {
                return Err(ScannerError::Scan("worker stage/request mismatch".into()));
            }
            let id = request.id;
            let mut observations = Vec::new();
            let mut bytes = 0usize;
            loop {
                match read_sync(&mut input)? {
                    Command::Input {
                        id: actual,
                        observation,
                    } if actual == id => {
                        bytes = bytes.saturating_add(serde_json::to_vec(&observation)?.len());
                        observations.push(*observation);
                    }
                    Command::Resume {
                        id: actual,
                        observation,
                    } if actual == id => {
                        bytes = bytes.saturating_add(serde_json::to_vec(&observation)?.len());
                        request.checkpoint.observations.push(*observation);
                    }
                    Command::InputEnd { id: actual } if actual == id => break,
                    Command::Cancel { id: actual } if actual == id => {
                        reader_cancel.store(true, Ordering::Relaxed);
                        return Ok(());
                    }
                    _ => return Err(ScannerError::Scan("unexpected worker input".into())),
                }
                if bytes > MAX_RESULTS {
                    return Err(ScannerError::Scan("worker input limit exceeded".into()));
                }
            }
            ready_tx
                .blocking_send(Ok((request, observations)))
                .map_err(|_| ScannerError::Scan("executor closed".into()))?;
            loop {
                match read_sync(&mut input)? {
                    Command::Cancel { id: actual } if actual == id => {
                        reader_cancel.store(true, Ordering::Relaxed)
                    }
                    Command::Ack {
                        id: actual,
                        sequence,
                    } if actual == id => {
                        ack_tx.try_send((actual, sequence)).map_err(|_| {
                            ScannerError::Scan("unexpected duplicate acknowledgement".into())
                        })?;
                    }
                    _ => return Err(ScannerError::Scan("invalid control message".into())),
                }
            }
        })();
        reader_cancel.store(true, Ordering::Relaxed);
        if let Err(error) = result {
            let _ = ready_tx.try_send(Err(error));
        }
    });
    let (request, input) = ready_rx
        .recv()
        .await
        .ok_or_else(|| ScannerError::Scan("worker input closed".into()))??;
    writer.lock().unwrap().id = request.id;
    let remote = RemoteJournal {
        writer: &writer,
        acks: Mutex::new(ack_rx),
    };
    let mut journal = ScanJournal::remote(&remote, request.checkpoint.clone());
    let ports: Vec<_> = input
        .iter()
        .filter_map(|o| {
            if let ScanObservation::Port(p) = o {
                Some(p.clone())
            } else {
                None
            }
        })
        .collect();
    let services: Vec<_> = input
        .iter()
        .filter_map(|o| {
            if let ScanObservation::Service(s) = o {
                Some(s.clone())
            } else {
                None
            }
        })
        .collect();
    let result = execute(&request, &ports, &services, &cancel, &mut journal).await;
    let (outcome, results, error) = match result {
        Ok(value) => value,
        Err(error) => (Outcome::Failed, Vec::new(), Some(error.to_string())),
    };
    let mut bytes = 0usize;
    for observation in results {
        bytes = bytes.saturating_add(serde_json::to_vec(&observation)?.len());
        if bytes > MAX_RESULTS {
            return Err(ScannerError::Scan("worker output limit exceeded".into()));
        }
        writer.lock().unwrap().send(EventBody::Observation {
            observation: Box::new(observation),
        })?;
    }
    writer
        .lock()
        .unwrap()
        .send(EventBody::Finished { outcome, error })?;
    Ok(())
}

async fn execute(
    request: &Request,
    ports: &[crate::scan::PortObservation],
    services: &[crate::scan::ServiceObservation],
    cancel: &AtomicBool,
    journal: &mut ScanJournal<'_>,
) -> Result<(Outcome, Vec<ScanObservation>, Option<String>), ScannerError> {
    let cancelled = (Outcome::Cancelled, Vec::new(), None);
    let complete = |results| (Outcome::Completed, results, None);
    Ok(match request.stage {
        ScanStageKind::PortDiscovery => {
            match masscan::run(
                &request.engine_path,
                &request.masscan,
                &request.target,
                cancel,
            )
            .await?
            {
                masscan::EngineOutcome::Completed(p) => {
                    complete(p.into_iter().map(ScanObservation::Port).collect())
                }
                masscan::EngineOutcome::Cancelled => cancelled,
            }
        }
        ScanStageKind::ServiceDetection => match zgrab2::run_with_journal(
            &request.service,
            ports,
            &request.target.address_family,
            cancel,
            Some(journal),
        )
        .await?
        {
            zgrab2::EngineOutcome::Completed(s) => {
                complete(s.into_iter().map(ScanObservation::Service).collect())
            }
            zgrab2::EngineOutcome::Partial(s, e) => (
                Outcome::Partial,
                s.into_iter().map(ScanObservation::Service).collect(),
                Some(e),
            ),
            zgrab2::EngineOutcome::Cancelled => cancelled,
        },
        ScanStageKind::DnsLookup => {
            match dns::run(&request.dns, &request.target, &request.resolvers, cancel).await? {
                Some(d) => complete(
                    d.observations
                        .into_iter()
                        .map(ScanObservation::Dns)
                        .collect(),
                ),
                None => cancelled,
            }
        }
        ScanStageKind::VulnerabilityDetection => {
            match nuclei::run(&request.nuclei, ports, services, cancel).await? {
                nuclei::EngineOutcome::Completed(v) => {
                    complete(v.into_iter().map(ScanObservation::Vulnerability).collect())
                }
                nuclei::EngineOutcome::Cancelled => cancelled,
            }
        }
    })
}
