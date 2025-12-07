use std::io;

use percent_encoding::percent_decode_str;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub struct PinentryServer<R, W> {
    reader: BufReader<R>,
    writer: W,
}

#[async_trait::async_trait]
pub trait PinentryServerHandler: Send + Sync {
    /// GETPIN handler
    async fn get_pin(
        &mut self,
        desc: Option<&str>,
        prompt: Option<&str>,
        keyinfo: Option<&str>,
        skip_saved_password: bool,
    ) -> io::Result<String>;

    /// CONFIRM handler
    async fn confirm(&mut self, desc: Option<&str>) -> io::Result<bool>;

    /// MESSAGE handler
    async fn message(&mut self, desc: Option<&str>) -> io::Result<()>;

    /// BYE/QUIT handler (signals that the server should exit)
    fn signal_exit(&mut self);
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> PinentryServer<R, W> {
    /// Create a new pinentry server with the given input/output streams
    pub async fn new(reader: R, writer: W) -> io::Result<Self> {
        let mut server = PinentryServer {
            reader: BufReader::new(reader),
            writer,
        };
        server.send_ok(Some("hello")).await?;
        Ok(server)
    }

    // Run the server loop, handling commands until BYE QUIT or EOF. Very basic
    // implementation
    pub async fn run<H: PinentryServerHandler>(&mut self, handler: &mut H) -> io::Result<()> {
        let mut description: Option<String> = None;
        let mut prompt: Option<String> = None;
        let mut keyinfo: Option<String> = None;
        // Currently unused fields
        let mut _error_msg: Option<String> = None;
        let mut _title: Option<String> = None;
        // Set when bad passphrase error is received
        let mut skip_saved_password = false;

        let mut buf = String::new();

        loop {
            buf.clear();
            let n = self.reader.read_line(&mut buf).await?;

            if n == 0 {
                // EOF
                return Ok(());
            }

            let line = buf.trim_end_matches(['\n', '\r']);
            log::debug!("[pinentry] {line}");

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            let command = parts[0];
            let args = parts.get(1).copied();
            match command {
                "GETPIN" => {
                    match handler
                        .get_pin(
                            description.as_deref(),
                            prompt.as_deref(),
                            keyinfo.as_deref(),
                            skip_saved_password,
                        )
                        .await
                    {
                        Ok(pin) => {
                            self.send_data(pin.as_bytes()).await?;
                            self.send_ok(None).await?;
                            skip_saved_password = false;
                        },
                        Err(e) => {
                            self.send_error(256, &format!("get_pin failed: {}", e))
                                .await?;
                        },
                    }
                },

                "CONFIRM" => match handler.confirm(description.as_deref()).await {
                    Ok(true) => self.send_ok(None).await?,
                    Ok(false) => self.send_error(277, "Operation cancelled").await?,
                    Err(e) => {
                        self.send_error(256, &format!("confirm failed: {}", e))
                            .await?
                    },
                },

                "MESSAGE" => match handler.message(description.as_deref()).await {
                    Ok(()) => self.send_ok(None).await?,
                    Err(e) => {
                        self.send_error(256, &format!("message failed: {}", e))
                            .await?
                    },
                },

                "SETKEYINFO" => {
                    // treat keyinfo as opaque string, per docs
                    keyinfo = args.map(|s| s.to_owned());
                    self.send_ok(None).await?;
                },

                "SETDESC" => {
                    if let Some(desc) = args {
                        description =
                            Some(percent_decode_str(desc).decode_utf8_lossy().into_owned());
                    }
                    self.send_ok(None).await?;
                },

                "SETPROMPT" => {
                    if let Some(p) = args {
                        prompt = Some(percent_decode_str(p).decode_utf8_lossy().into_owned());
                    }
                    self.send_ok(None).await?;
                },

                "SETERROR" => {
                    if let Some(err) = args {
                        let decoded = percent_decode_str(err).decode_utf8_lossy();
                        if decoded.contains("Bad Passphrase") {
                            skip_saved_password = true;
                        }
                        _error_msg = Some(decoded.into_owned());
                    }
                    self.send_ok(None).await?;
                },

                "SETTITLE" => {
                    if let Some(t) = args {
                        _title = Some(percent_decode_str(t).decode_utf8_lossy().into_owned());
                    }
                    self.send_ok(None).await?;
                },

                "SETOK" | "SETCANCEL" | "SETNOTOK" | "SETTIMEOUT" | "SETQUALITYBAR"
                | "SETQUALITYBAR_TT" | "SETREPEAT" | "SETGENPIN" | "SETGENPIN_TT" => {
                    // Accept but ignore these commands for now
                    self.send_ok(None).await?;
                },

                "OPTION" => {
                    // Accept options but don't do anything with them
                    self.send_ok(None).await?;
                },

                "RESET" => {
                    // Clear all state
                    description = None;
                    prompt = None;
                    keyinfo = None;
                    _error_msg = None;
                    _title = None;
                    self.send_ok(None).await?;
                },

                "BYE" | "QUIT" => {
                    self.send_ok(None).await?;
                    handler.signal_exit();
                    return Ok(());
                },

                "NOP" => {
                    self.send_ok(None).await?;
                },

                "HELP" => {
                    self.send_ok(None).await?;
                },

                _ => {
                    self.send_error(275, &format!("Unknown command: {}", command))
                        .await?;
                },
            }
        }
    }

    async fn send_ok(&mut self, message: Option<&str>) -> io::Result<()> {
        if let Some(msg) = message {
            self.writer.write_all(b"OK ").await?;
            self.writer.write_all(msg.as_bytes()).await?;
            self.writer.write_all(b"\n").await?;
        } else {
            self.writer.write_all(b"OK\n").await?;
        }
        self.writer.flush().await?;
        Ok(())
    }

    async fn send_error(&mut self, code: u32, message: &str) -> io::Result<()> {
        let line = format!("ERR {} {}\n", code, message);
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn send_data(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(b"D ").await?;
        self.writer.write_all(data).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;
        Ok(())
    }
}
