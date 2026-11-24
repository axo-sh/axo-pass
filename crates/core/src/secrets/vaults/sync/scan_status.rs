//! Result of the latest peer scan of each synced vault, for the sync status
//! sheet.
//!
//! One map per process. The manager thread writes it and the sync report
//! reads it. It resets at restart.

use std::collections::BTreeMap;
use std::sync::Mutex;

use jiff::Timestamp;
use uuid::Uuid;

static STATUS: Mutex<BTreeMap<Uuid, ScanStatus>> = Mutex::new(BTreeMap::new());

/// How the latest scan of a vault ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanOutcome {
    /// The scan listed the peer files and joined each change that was local.
    Synced,
    /// Peer state files are not downloaded yet. A download is requested.
    Waiting { files: u32 },
    /// The scan or the join failed. `message` is fixed text.
    Failed { message: String },
}

/// Latest scan of one vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanStatus {
    /// Unix seconds of the scan.
    pub at: i64,
    pub outcome: ScanOutcome,
}

/// Record the result of a scan of vault `vault_id` now.
pub fn record(vault_id: Uuid, outcome: ScanOutcome) {
    let status = ScanStatus {
        at: Timestamp::now().as_second(),
        outcome,
    };
    STATUS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(vault_id, status);
}

/// Latest scan of vault `vault_id`. `None` if the process has not scanned it.
pub fn get(vault_id: Uuid) -> Option<ScanStatus> {
    STATUS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&vault_id)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_latest_record() {
        let vault = Uuid::from_u128(0x5ca1);
        assert_eq!(get(vault), None);

        record(vault, ScanOutcome::Waiting { files: 2 });
        record(vault, ScanOutcome::Synced);

        let status = get(vault).unwrap();
        assert_eq!(status.outcome, ScanOutcome::Synced);
        assert!(status.at > 0);
    }

    #[test]
    fn records_kept_per_vault() {
        let first = Uuid::from_u128(0x5ca2);
        let second = Uuid::from_u128(0x5ca3);

        record(first, ScanOutcome::Synced);
        record(
            second,
            ScanOutcome::Failed {
                message: "failed".to_string(),
            },
        );

        assert_eq!(get(first).unwrap().outcome, ScanOutcome::Synced);
        assert!(matches!(
            get(second).unwrap().outcome,
            ScanOutcome::Failed { .. }
        ));
    }
}
