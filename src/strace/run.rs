//! Strace invocation code

use std::{
    fs::File,
    io::BufReader,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use anyhow::Context as _;

use crate::strace::{STRACE_BIN, parser::LogParser};

pub(crate) struct Strace {
    /// Strace process
    process: Child,
    /// Temp dir for pipe location
    pipe_dir: tempfile::TempDir,
    /// Strace log mirror path
    log_path: Option<PathBuf>,
}

impl Strace {
    pub(crate) fn run(command: &[&str], log_path: Option<PathBuf>) -> anyhow::Result<Self> {
        // Create named pipe
        let pipe_dir = tempfile::tempdir().context("Failed to create temporary directory")?;
        let pipe_path = Self::pipe_path(&pipe_dir);
        #[expect(clippy::unwrap_used)]
        nix::unistd::mkfifo(&pipe_path, nix::sys::stat::Mode::from_bits(0o600).unwrap())
            .context("Failed to create named pipe")?;

        // Start process
        // TODO setuid/setgid execution will be broken unless strace runs as root
        let child = Command::new(STRACE_BIN)
            .args([
                "--daemonize=grandchild",
                "--relative-timestamps",
                "--follow-forks",
                // TODO APPROXIMATION this can make us miss interesting stuff like open with O_EXCL|O_CREAT which
                // returns -1 because file exists
                "--successful-only",
                "--strings-in-hex=all",
                // Despite this, some structs are still truncated
                "-e",
                "abbrev=none",
                // "-e",
                // "read=all",
                // "-e",
                // "write=all",
                "-e",
                "decode-fds=path",
                "--output-append-mode",
                "-o",
                #[expect(clippy::unwrap_used)]
                pipe_path.to_str().unwrap(),
                "--",
            ])
            .args(command)
            .env("LANG", "C") // avoids locale side effects
            .stdin(Stdio::null())
            .spawn()
            .context("Failed to start strace")?;

        Ok(Self {
            process: child,
            pipe_dir,
            log_path,
        })
    }

    fn pipe_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("strace.pipe")
    }

    pub(crate) fn log_lines(&self) -> anyhow::Result<LogParser> {
        let pipe_path = Self::pipe_path(&self.pipe_dir);
        let reader = BufReader::new(File::open(pipe_path)?);
        LogParser::new(Box::new(reader), self.log_path.as_deref())
    }
}

impl Drop for Strace {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
