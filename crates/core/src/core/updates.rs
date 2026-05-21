use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Serialize, Deserialize, Clone)]
pub struct UpdateCheckRecord {
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
    pub result: UpdateCheckResult,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged, rename_all = "snake_case")]
pub enum UpdateCheckResult {
    UpdateAvailable { version: String },
    UpToDate {},
    Error { error: String },
}
