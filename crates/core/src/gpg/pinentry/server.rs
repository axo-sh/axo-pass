//! The assuan side of pinentry: reads gpg-agent's commands and answers them.
//!
//! A partial implementation, covering the commands gpg-agent actually sends.
//! Where the answers come from is the handler's business; see
//! [`super::handler::BrokerPinentryHandler`].

use std::io;

use percent_encoding::percent_decode_str;
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub struct PinentryServer<R, W> {
    reader: BufReader<R>,
    writer: W,
}

pub trait PinentryServerHandler {
    /// GETPIN handler
    fn get_pin(
        &mut self,
        desc: Option<&str>,
        prompt: Option<&str>,
        keyinfo: Option<&str>,
        error_message: Option<&str>,
    ) -> impl Future<Output = io::Result<SecretString>>;

    /// CONFIRM handler
    fn confirm(&mut self, desc: Option<&str>) -> impl Future<Output = io::Result<bool>>;

    /// MESSAGE handler
    fn message(&mut self, desc: Option<&str>) -> impl Future<Output = io::Result<()>>;
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
        let mut error_message: Option<String> = None;
        let mut _title: Option<String> = None;

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
                            error_message.as_deref(),
                        )
                        .await
                    {
                        Ok(pin) => {
                            self.send_data(pin.expose_secret().as_bytes()).await?;
                            self.send_ok(None).await?;
                            error_message = None;
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
                        error_message =
                            Some(percent_decode_str(err).decode_utf8_lossy().into_owned());
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
                    error_message = None;
                    _title = None;
                    self.send_ok(None).await?;
                },

                "BYE" | "QUIT" => {
                    self.send_ok(None).await?;
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

    /// Send a `D` line. Assuan reserves `%`, CR and LF inside data, so those
    /// three bytes go out percent-escaped; a passphrase containing one would
    /// otherwise arrive truncated or mangled.
    async fn send_data(&mut self, data: &[u8]) -> io::Result<()> {
        let mut line = Vec::with_capacity(data.len() + 2);
        line.extend_from_slice(b"D ");
        for byte in data {
            match byte {
                b'%' => line.extend_from_slice(b"%25"),
                b'\r' => line.extend_from_slice(b"%0D"),
                b'\n' => line.extend_from_slice(b"%0A"),
                _ => line.push(*byte),
            }
        }
        line.push(b'\n');
        self.writer.write_all(&line).await?;
        self.writer.flush().await?;
        Ok(())
    }
}
