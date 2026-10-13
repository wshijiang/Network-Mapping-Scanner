use crate::{error::ScannerError, scan::ScanObservation, storage::StateStore};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct Checkpoint {
    pub(crate) stage: usize,
    pub(crate) chunk: usize,
    pub(crate) elapsed_ms: u64,
    pub(crate) observations: Vec<ScanObservation>,
}

/// One immutable task/configuration snapshot; only completed blocks are reusable.
pub(crate) struct ScanJournal<'a> {
    backend: Backend<'a>,
    pub(crate) origin: &'a str,
    pub(crate) key: String,
    pub(crate) state: Checkpoint,
}

pub(crate) trait CheckpointSink {
    fn save(
        &self,
        stage: usize,
        chunk: usize,
        elapsed_ms: u64,
        observations: Option<&[ScanObservation]>,
    ) -> Result<(), ScannerError>;
    fn start_block(&self) -> Result<(), ScannerError>;
}

enum Backend<'a> {
    Local(&'a StateStore),
    Remote(&'a dyn CheckpointSink),
}

impl<'a> ScanJournal<'a> {
    pub(crate) fn open(
        store: &'a StateStore,
        origin: &'a str,
        key: String,
    ) -> Result<Self, ScannerError> {
        let state = store.load_checkpoint(origin, &key)?.unwrap_or_default();
        Ok(Self {
            backend: Backend::Local(store),
            origin,
            key,
            state,
        })
    }

    pub(crate) fn remote(sink: &'a dyn CheckpointSink, state: Checkpoint) -> Self {
        Self {
            backend: Backend::Remote(sink),
            origin: "",
            key: String::new(),
            state,
        }
    }

    pub(crate) fn start_block(&self) -> Result<(), ScannerError> {
        match self.backend {
            Backend::Local(store) => store.start_checkpoint_block(self.origin),
            Backend::Remote(sink) => sink.start_block(),
        }
    }

    pub(crate) fn save(
        &mut self,
        stage: usize,
        chunk: usize,
        elapsed_ms: u64,
        observations: Option<&[ScanObservation]>,
    ) -> Result<(), ScannerError> {
        match self.backend {
            Backend::Local(store) => store.save_checkpoint(
                self.origin,
                &self.key,
                stage,
                chunk,
                elapsed_ms,
                observations,
            )?,
            Backend::Remote(sink) => sink.save(stage, chunk, elapsed_ms, observations)?,
        }
        self.state.stage = stage;
        self.state.chunk = chunk;
        self.state.elapsed_ms = elapsed_ms;
        Ok(())
    }
}
