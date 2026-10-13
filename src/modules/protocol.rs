use crate::{
    error::ScannerError,
    journal::Checkpoint,
    scan::{ScanObservation, plan::ScanStageKind},
    types::{
        DnsConfig, DnsResolver, MasscanConfig, NucleiConfig, ServiceDetectionConfig, TargetParams,
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{Read, Write};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub(crate) const IPC_VERSION: u16 = 1;
pub(crate) const MAX_FRAME: usize = 8 * 1024 * 1024;
pub(crate) const MAX_RESULTS: usize = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Request {
    pub(crate) id: Uuid,
    pub(crate) stage: ScanStageKind,
    pub(crate) target: TargetParams,
    pub(crate) engine_path: String,
    #[serde(default)]
    pub(crate) masscan: MasscanConfig,
    pub(crate) service: ServiceDetectionConfig,
    pub(crate) dns: DnsConfig,
    pub(crate) nuclei: NucleiConfig,
    pub(crate) resolvers: Vec<DnsResolver>,
    pub(crate) checkpoint: Checkpoint,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Command {
    Execute {
        request: Box<Request>,
    },
    Input {
        id: Uuid,
        observation: Box<ScanObservation>,
    },
    Resume {
        id: Uuid,
        observation: Box<ScanObservation>,
    },
    InputEnd {
        id: Uuid,
    },
    Ack {
        id: Uuid,
        sequence: u64,
    },
    Cancel {
        id: Uuid,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Event {
    pub(crate) id: Uuid,
    pub(crate) sequence: u64,
    #[serde(flatten)]
    pub(crate) body: EventBody,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum EventBody {
    Hello {
        ipc_version: u16,
        stage: ScanStageKind,
        version: String,
    },
    Observation {
        observation: Box<ScanObservation>,
    },
    CheckpointPart {
        observation: Box<ScanObservation>,
    },
    CheckpointSave {
        stage: usize,
        chunk: usize,
        elapsed_ms: u64,
        has_part: bool,
    },
    BlockStarted,
    Finished {
        outcome: Outcome,
        error: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Completed,
    Partial,
    Cancelled,
    Failed,
}

pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ScannerError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(ScannerError::Scan("worker frame exceeds limit".into()));
    }
    Ok(bytes)
}

fn frame_size(bytes: [u8; 4]) -> Result<usize, ScannerError> {
    let size = u32::from_be_bytes(bytes) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(ScannerError::Scan("invalid worker frame length".into()));
    }
    Ok(size)
}

pub(crate) fn write_sync<T: Serialize>(
    writer: &mut impl Write,
    value: &T,
) -> Result<(), ScannerError> {
    let bytes = encode(value)?;
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

pub(crate) fn read_sync<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, ScannerError> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let mut bytes = vec![0; frame_size(header)?];
    reader.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) async fn write_frame<T: Serialize>(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> Result<(), ScannerError> {
    let bytes = encode(value)?;
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn read_frame<T: DeserializeOwned>(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<T, ScannerError> {
    let mut header = [0; 4];
    reader.read_exact(&mut header).await?;
    let mut bytes = vec![0; frame_size(header)?];
    reader.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_length_before_allocating_and_truncated_frames() {
        assert!(read_sync::<Command>(&mut &u32::MAX.to_be_bytes()[..]).is_err());
        assert!(read_sync::<Command>(&mut &[0, 0, 0, 0][..]).is_err());
        assert!(read_sync::<Command>(&mut &[0, 0, 0, 4, b'{'][..]).is_err());
    }
    #[test]
    fn cancel_round_trips() {
        let id = Uuid::now_v7();
        let mut bytes = Vec::new();
        write_sync(&mut bytes, &Command::Cancel { id }).unwrap();
        assert!(
            matches!(read_sync::<Command>(&mut &bytes[..]).unwrap(), Command::Cancel { id: actual } if actual == id)
        );
    }
}
