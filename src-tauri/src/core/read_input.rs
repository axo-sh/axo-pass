use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReadError {
    #[error("Error reading file: {0}")]
    FileReadError(#[source] std::io::Error),

    #[error("Error reading from stdin: {0}")]
    FailedToReadStdin(#[source] std::io::Error),

    #[error("No input provided via file or stdin")]
    NoInputProvided,
}

pub fn read_file_or_stdin(file_path: &Option<PathBuf>) -> Result<Vec<u8>, ReadError> {
    if let Some(path) = file_path {
        return std::fs::read(path).map_err(ReadError::FileReadError);
    }

    if !std::io::stdin().is_terminal() {
        let mut buffer = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buffer)
            .map_err(ReadError::FailedToReadStdin)?;
        return Ok(buffer);
    }

    Err(ReadError::NoInputProvided)
}
