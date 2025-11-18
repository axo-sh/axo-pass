use std::io::Read;
use std::path::PathBuf;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReadError {
    #[error("Error reading file: {0}")]
    FileReadError(#[source] std::io::Error),

    #[error("Error reading from stdin: {0}")]
    FailedToReadStdin(#[source] std::io::Error),
}

pub fn read_file_or_stdin(file_path: &Option<PathBuf>) -> Result<Vec<u8>, ReadError> {
    if let Some(path) = file_path {
        std::fs::read(path).map_err(|e| ReadError::FileReadError(e))
    } else {
        let mut buffer = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buffer)
            .map_err(|e| ReadError::FailedToReadStdin(e))?;
        Ok(buffer)
    }
}
