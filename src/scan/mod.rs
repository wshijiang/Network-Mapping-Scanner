mod detection;
pub(crate) mod engines;
mod observation;
mod orchestrator;
pub(crate) mod plan;

pub(crate) use engines::masscan::validate_scanner_binary;
pub(crate) use engines::nuclei::validate_binary as validate_nuclei_binary;
pub(crate) use engines::nuclei::validate_templates as validate_nuclei_templates;
pub(crate) use engines::zgrab2::validate_binary as validate_zgrab_binary;
pub(crate) use observation::{
    DnsAnswer, DnsObservation, DnsQuestion, PortObservation, ScanObservation, ServiceObservation,
    VulnerabilityObservation,
};
pub(crate) use orchestrator::{ScanOutcome, ScanRuntimeConfig, run_scan};
pub(crate) use plan::{ScanCapabilities, ScanPlan};

#[cfg(test)]
pub(crate) use orchestrator::process_worker_result;
