use crate::error::ScannerError;
use crate::scan::ScanObservation;
use crate::types::{CacheManager, ScannerResultBatchUpload};
use std::collections::HashSet;
use uuid::Uuid;

pub(crate) const UPLOAD_BATCH_SIZE: usize = 500;
pub(crate) const UPLOAD_BATCH_MAX_BYTES: usize = 8 * 1024 * 1024;
const RESULT_PROTOCOL_VERSION: u16 = 3;

impl CacheManager {
    #[cfg(test)]
    pub(crate) fn begin_task(&mut self, task_id: Uuid) -> Result<(), ScannerError> {
        if self.task_id.is_some() || !self.observations.is_empty() {
            return Err(ScannerError::Scan(
                "cannot start a new task while results are pending".into(),
            ));
        }
        self.task_id = Some(task_id);
        let upload_id = Uuid::now_v7();
        if let Some(store) = self.store.as_mut() {
            store.begin_upload(
                &self.server_origin,
                &self.scanner_id,
                task_id,
                upload_id,
                &[],
            )?;
        }
        self.upload_id = Some(upload_id);
        self.next_batch_index = 0;
        Ok(())
    }

    pub(crate) fn begin_task_with_observations(
        &mut self,
        task_id: Uuid,
        observations: &[ScanObservation],
    ) -> Result<(), ScannerError> {
        if self.task_id.is_some() || !self.observations.is_empty() {
            return Err(ScannerError::Scan(
                "cannot start a new task while results are pending".into(),
            ));
        }
        let mut identities = HashSet::new();
        let observations: Vec<_> = observations
            .iter()
            .filter(|item| identities.insert(item.identity()))
            .cloned()
            .collect();
        let upload_id = Uuid::now_v7();
        if let Some(store) = self.store.as_mut() {
            store.begin_upload(
                &self.server_origin,
                &self.scanner_id,
                task_id,
                upload_id,
                &observations,
            )?;
        }
        self.task_id = Some(task_id);
        self.upload_id = Some(upload_id);
        self.next_batch_index = 0;
        self.identities = identities;
        self.observations = observations;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn insert(&mut self, observation: &ScanObservation) -> Result<(), ScannerError> {
        if self.task_id.is_none() || self.upload_id.is_none() {
            return Err(ScannerError::Scan(
                "cannot cache an observation without task context".into(),
            ));
        }
        let identity = observation.identity();
        if self.identities.contains(&identity) {
            return Ok(());
        }
        if let Some(store) = self.store.as_ref()
            && !store.append_observation(
                &self.server_origin,
                self.observations.len(),
                observation,
            )?
        {
            return Ok(());
        }
        self.identities.insert(identity);
        self.observations.push(observation.clone());
        Ok(())
    }

    pub(crate) fn has_pending_task(&self) -> bool {
        self.task_id.is_some()
    }

    pub(crate) fn upload_ranges(
        &self,
        scanner_id: Uuid,
    ) -> Result<Vec<std::ops::Range<usize>>, ScannerError> {
        let task_id = self
            .task_id
            .ok_or_else(|| ScannerError::Upload("missing task identity".into()))?;
        let upload_id = self
            .upload_id
            .ok_or_else(|| ScannerError::Upload("missing upload identity".into()))?;
        if self.observations.is_empty() {
            return Ok(std::iter::once(0..0).collect());
        }
        upload_batch_ranges(&self.observations, scanner_id, task_id, upload_id)
    }

    pub(crate) fn batch_at(
        &self,
        scanner_id: Uuid,
        ranges: &[std::ops::Range<usize>],
        index: u32,
    ) -> Result<Option<ScannerResultBatchUpload<&[ScanObservation]>>, ScannerError> {
        let Some(range) = ranges.get(index as usize) else {
            return Ok(None);
        };
        Ok(Some(ScannerResultBatchUpload {
            protocol_version: RESULT_PROTOCOL_VERSION,
            scanner_id,
            task_id: self
                .task_id
                .ok_or_else(|| ScannerError::Upload("missing task identity".into()))?,
            upload_id: self
                .upload_id
                .ok_or_else(|| ScannerError::Upload("missing upload identity".into()))?,
            batch_index: index,
            is_final: index as usize + 1 == ranges.len(),
            observations: &self.observations[range.clone()],
        }))
    }

    pub(crate) fn archive(&mut self, reason: &str) -> Result<(), ScannerError> {
        if let Some(store) = self.store.as_mut() {
            store.archive_upload(&self.server_origin, reason)?;
        }
        self.clear()
    }

    #[cfg(test)]
    pub(crate) fn upload_batches(
        &self,
        scanner_id: Uuid,
    ) -> Result<Vec<ScannerResultBatchUpload>, ScannerError> {
        let task_id = self.task_id.ok_or_else(|| {
            ScannerError::Upload("missing task context for cached results".into())
        })?;
        let upload_id = self.upload_id.ok_or_else(|| {
            ScannerError::Upload("missing upload identity for cached results".into())
        })?;

        if self.observations.is_empty() {
            let batch = ScannerResultBatchUpload {
                protocol_version: RESULT_PROTOCOL_VERSION,
                scanner_id,
                task_id,
                upload_id,
                batch_index: 0,
                is_final: true,
                observations: Vec::new(),
            };
            return Ok(if self.next_batch_index == 0 {
                vec![batch]
            } else {
                Vec::new()
            });
        }

        let ranges = upload_batch_ranges(&self.observations, scanner_id, task_id, upload_id)?;
        let batch_count = ranges.len();
        let batches = ranges
            .into_iter()
            .enumerate()
            .skip(self.next_batch_index as usize)
            .map(|(index, range)| ScannerResultBatchUpload {
                protocol_version: RESULT_PROTOCOL_VERSION,
                scanner_id,
                task_id,
                upload_id,
                batch_index: u32::try_from(index).expect("observation batch index fits in u32"),
                is_final: index + 1 == batch_count,
                observations: self.observations[range].to_vec(),
            })
            .collect();
        Ok(batches)
    }

    pub(crate) fn mark_batch_uploaded(&mut self, batch_index: u32) -> Result<(), ScannerError> {
        if batch_index != self.next_batch_index {
            return Err(ScannerError::Upload(format!(
                "cannot acknowledge batch {batch_index}; expected {}",
                self.next_batch_index
            )));
        }
        let next_batch_index = self.next_batch_index.checked_add(1).ok_or_else(|| {
            ScannerError::Upload("uploaded batch index exceeded protocol limit".into())
        })?;
        if let Some(store) = self.store.as_ref() {
            store.set_next_batch_index(&self.server_origin, next_batch_index)?;
        }
        self.next_batch_index = next_batch_index;
        Ok(())
    }

    #[cfg(test)]
    fn observation_identities(&self) -> HashSet<String> {
        self.observations
            .iter()
            .map(ScanObservation::identity)
            .collect()
    }
}

fn upload_batch_ranges(
    observations: &[ScanObservation],
    scanner_id: Uuid,
    task_id: Uuid,
    upload_id: Uuid,
) -> Result<Vec<std::ops::Range<usize>>, ScannerError> {
    let observation_sizes = observations
        .iter()
        .map(|observation| {
            serde_json::to_vec(observation)
                .map(|json| json.len())
                .map_err(|error| {
                    ScannerError::Upload(format!(
                        "failed to measure serialized observation: {error}"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut ranges = Vec::new();
    let mut start = 0usize;

    while start < observations.len() {
        let batch_index = u32::try_from(ranges.len())
            .map_err(|_| ScannerError::Upload("observation batch index exceeded u32".into()))?;
        // `false` is one byte longer than `true`, so this is also a safe estimate
        // for the final batch after its marker changes.
        let empty_batch: ScannerResultBatchUpload = ScannerResultBatchUpload {
            protocol_version: RESULT_PROTOCOL_VERSION,
            scanner_id,
            task_id,
            upload_id,
            batch_index,
            is_final: false,
            observations: Vec::new(),
        };
        let mut serialized_bytes = serde_json::to_vec(&empty_batch)
            .map_err(|error| {
                ScannerError::Upload(format!("failed to measure upload batch: {error}"))
            })?
            .len();
        let mut end = start;

        while end < observations.len() && end - start < UPLOAD_BATCH_SIZE {
            let separator_bytes = usize::from(end > start);
            let candidate_bytes = serialized_bytes
                .saturating_add(separator_bytes)
                .saturating_add(observation_sizes[end]);
            if candidate_bytes > UPLOAD_BATCH_MAX_BYTES {
                if end == start {
                    return Err(ScannerError::Upload(format!(
                        "serialized observation at index {start} exceeds the {} byte upload limit",
                        UPLOAD_BATCH_MAX_BYTES
                    )));
                }
                break;
            }
            serialized_bytes = candidate_bytes;
            end += 1;
        }

        ranges.push(start..end);
        start = end;
    }

    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{PortObservation, ServiceObservation};

    fn uuid(value: &str) -> Uuid {
        Uuid::parse_str(value).expect("valid test UUID")
    }

    #[test]
    fn borrowed_batches_preserve_wire_bytes_and_resume_boundaries() {
        let scanner_id = Uuid::nil();
        let mut cache = CacheManager::default();
        cache.begin_task(Uuid::now_v7()).unwrap();
        for port in 1..=1001 {
            cache
                .insert(&ScanObservation::Port(PortObservation {
                    ip: "192.0.2.1".into(),
                    port,
                    protocol: "tcp".into(),
                    state: "open".into(),
                    source: "masscan".into(),
                    observed_at: 1,
                }))
                .unwrap();
        }
        let ranges = cache.upload_ranges(scanner_id).unwrap();
        let owned = cache.upload_batches(scanner_id).unwrap();
        for (index, expected) in owned.iter().enumerate() {
            let actual = cache
                .batch_at(scanner_id, &ranges, index as u32)
                .unwrap()
                .unwrap();
            assert_eq!(
                actual.observations.as_ptr(),
                cache.observations[ranges[index].clone()].as_ptr()
            );
            assert_eq!(
                serde_json::to_vec(&actual).unwrap(),
                serde_json::to_vec(expected).unwrap()
            );
        }
        cache.mark_batch_uploaded(0).unwrap();
        assert_eq!(
            cache
                .batch_at(scanner_id, &ranges, cache.next_batch_index)
                .unwrap()
                .unwrap()
                .batch_index,
            1
        );
        assert!(cache.batch_at(scanner_id, &ranges, 3).unwrap().is_none());
        cache.clear().unwrap();
        cache.begin_task(Uuid::now_v7()).unwrap();
        let ranges = cache.upload_ranges(scanner_id).unwrap();
        let empty = cache.batch_at(scanner_id, &ranges, 0).unwrap().unwrap();
        assert!(empty.observations.is_empty() && empty.is_final);
    }

    #[test]
    #[ignore = "manual upload preparation benchmark; no network traffic"]
    fn benchmark_upload_preparation() {
        let scanner_id = Uuid::nil();
        let mut cache = CacheManager::default();
        cache.begin_task(Uuid::now_v7()).unwrap();
        for port in 1..=500 {
            cache
                .insert(&ScanObservation::Service(ServiceObservation {
                    ip: "192.0.2.1".into(),
                    port,
                    protocol: "tcp".into(),
                    service: Some("https".into()),
                    banner: None,
                    source: "zgrab2".into(),
                    data: Some(serde_json::json!({"body": "x".repeat(12000)})),
                    observed_at: 1,
                }))
                .unwrap();
        }
        let ranges = cache.upload_ranges(scanner_id).unwrap();
        for borrowed in [false, true] {
            let mut samples = Vec::new();
            for _ in 0..21 {
                let start = std::time::Instant::now();
                let batch = cache.batch_at(scanner_id, &ranges, 0).unwrap().unwrap();
                let bytes = if borrowed {
                    serde_json::to_vec(&batch).unwrap()
                } else {
                    let owned = ScannerResultBatchUpload {
                        observations: batch.observations.to_vec(),
                        protocol_version: batch.protocol_version,
                        scanner_id: batch.scanner_id,
                        task_id: batch.task_id,
                        upload_id: batch.upload_id,
                        batch_index: batch.batch_index,
                        is_final: batch.is_final,
                    };
                    serde_json::to_vec(&owned).unwrap()
                };
                std::hint::black_box(bytes);
                samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }
            samples.sort_by(f64::total_cmp);
            println!(
                "UPLOAD_PREP_BENCH borrowed={borrowed} observations=500 body_bytes=12000 median_ms={:.3}",
                samples[10]
            );
        }
    }

    #[test]
    fn batches_keep_stable_upload_identity_and_final_marker() {
        let scanner_id = uuid("019c0000-0000-7000-8000-000000000001");
        let task_id = uuid("019c0000-0000-7000-8000-000000000002");
        let mut cache = CacheManager::default();
        cache.begin_task(task_id).unwrap();
        cache
            .insert(&ScanObservation::Port(PortObservation {
                ip: "192.0.2.1".into(),
                port: 443,
                protocol: "tcp".into(),
                state: "open".into(),
                source: "masscan".into(),
                observed_at: 1,
            }))
            .unwrap();
        cache
            .insert(&ScanObservation::Service(ServiceObservation {
                ip: "192.0.2.1".into(),
                port: 443,
                protocol: "tcp".into(),
                service: Some("https".into()),
                banner: None,
                source: "zgrab2".into(),
                data: None,
                observed_at: 2,
            }))
            .unwrap();

        let first = cache.upload_batches(scanner_id).unwrap();
        let retry = cache.upload_batches(scanner_id).unwrap();
        assert_eq!(first.len(), 1);
        assert!(first[0].is_final);
        assert_eq!(first[0].upload_id, retry[0].upload_id);
        assert_eq!(first[0].observations.len(), 2);
        assert_eq!(cache.observation_identities().len(), 2);
        let json = serde_json::to_value(&first[0]).unwrap();
        assert_eq!(json["protocol_version"], 3);
        assert_eq!(json["observations"][0]["kind"], "port");
        assert_eq!(json["observations"][1]["kind"], "service");
    }

    #[test]
    fn empty_task_still_produces_a_final_batch() {
        let mut cache = CacheManager::default();
        cache.begin_task(Uuid::now_v7()).unwrap();
        let batches = cache.upload_batches(Uuid::now_v7()).unwrap();
        assert_eq!(batches.len(), 1);
        assert!(batches[0].is_final);
        assert!(batches[0].observations.is_empty());
    }

    #[test]
    fn large_tasks_are_split_at_the_protocol_limit() {
        let mut cache = CacheManager::default();
        cache.begin_task(Uuid::now_v7()).unwrap();
        for port in 1..=501 {
            cache
                .insert(&ScanObservation::Port(PortObservation {
                    ip: "192.0.2.1".into(),
                    port,
                    protocol: "tcp".into(),
                    state: "open".into(),
                    source: "masscan".into(),
                    observed_at: 1,
                }))
                .unwrap();
        }
        let batches = cache.upload_batches(Uuid::now_v7()).unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].observations.len(), UPLOAD_BATCH_SIZE);
        assert!(!batches[0].is_final);
        assert_eq!(batches[1].observations.len(), 1);
        assert!(batches[1].is_final);
        assert_eq!(batches[0].upload_id, batches[1].upload_id);
        cache.mark_batch_uploaded(0).unwrap();
        let remaining = cache.upload_batches(Uuid::now_v7()).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].batch_index, 1);
    }

    #[test]
    fn large_observations_are_split_at_the_serialized_byte_limit() {
        let mut cache = CacheManager::default();
        cache.begin_task(Uuid::now_v7()).unwrap();
        for port in [443, 8443] {
            cache
                .insert(&ScanObservation::Service(ServiceObservation {
                    ip: "192.0.2.1".into(),
                    port,
                    protocol: "tcp".into(),
                    service: Some("https".into()),
                    banner: None,
                    source: "zgrab2".into(),
                    data: Some(serde_json::json!({
                        "evidence": [{"result": "x".repeat(5 * 1024 * 1024)}]
                    })),
                    observed_at: 1,
                }))
                .unwrap();
        }

        let batches = cache.upload_batches(Uuid::now_v7()).unwrap();
        assert_eq!(batches.len(), 2);
        assert!(batches.iter().all(|batch| batch.observations.len() == 1));
        assert!(
            batches.iter().all(|batch| {
                serde_json::to_vec(batch).unwrap().len() <= UPLOAD_BATCH_MAX_BYTES
            })
        );
    }

    #[test]
    fn single_observation_larger_than_upload_limit_is_rejected() {
        let mut cache = CacheManager::default();
        cache.begin_task(Uuid::now_v7()).unwrap();
        cache
            .insert(&ScanObservation::Service(ServiceObservation {
                ip: "192.0.2.1".into(),
                port: 443,
                protocol: "tcp".into(),
                service: Some("https".into()),
                banner: None,
                source: "zgrab2".into(),
                data: Some(serde_json::json!({
                    "evidence": [{"result": "x".repeat(UPLOAD_BATCH_MAX_BYTES)}]
                })),
                observed_at: 1,
            }))
            .unwrap();

        let error = cache.upload_batches(Uuid::now_v7()).unwrap_err();
        assert!(error.to_string().contains("exceeds"));
    }
}
