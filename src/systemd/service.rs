//! Systemd service actions

use std::{
    env, fmt,
    fs::{self, File},
    io::{self, BufRead as _, BufWriter, Write},
    num::ParseIntError,
    ops::RangeInclusive,
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use itertools::Itertools as _;
use rand::RngExt as _;

use super::InstanceKind;
use crate::{
    cl::HardeningOptions,
    systemd::{JournalCursor, journal::ProfilingLogError, options::OptionWithValue},
};

pub(crate) struct Service {
    pub name: String,
    pub arg: Option<String>,
    pub instance: InstanceKind,
}

const PROFILING_FRAGMENT_NAME: &str = "profile";
const HARDENING_FRAGMENT_NAME: &str = "harden";
/// Command line prefix for `ExecStartXxx`= that bypasses all hardening options
/// See <https://www.freedesktop.org/software/systemd/man/255/systemd.service.html#Command%20lines>
const PRIVILEGED_PREFIX: &str = "+";

/// Systemd "exposure level", to rate service security.
/// The lower, the better
pub(crate) struct ExposureLevel(u8);

impl TryFrom<f64> for ExposureLevel {
    type Error = anyhow::Error;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        const RANGE: RangeInclusive<f64> = 0.0..=10.0;
        anyhow::ensure!(
            RANGE.contains(&value),
            "Value not in range [{:.1}; {:.1}]",
            RANGE.start(),
            RANGE.end()
        );
        #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Ok(Self((value * 10.0) as u8))
    }
}

impl fmt::Display for ExposureLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.1}", f64::from(self.0) / 10.0)
    }
}

/// Systemd unique instance invocation identifier
pub(crate) struct InvocationId(u128);

impl FromStr for InvocationId {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(u128::from_str_radix(s, 16)?))
    }
}

impl fmt::Display for InvocationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl InvocationId {
    pub(crate) fn from_env() -> Option<Self> {
        env::var("INVOCATION_ID").ok()?.parse::<Self>().ok()
    }
}

impl Service {
    pub(crate) fn new(unit: &str, instance: InstanceKind) -> anyhow::Result<Self> {
        const UNSUPPORTED_UNIT_SUFFIXS: [&str; 10] = [
            ".socket",
            ".device",
            ".mount",
            ".automount",
            ".swap",
            ".target",
            ".path",
            ".timer",
            ".slice",
            ".scope",
        ];
        if let Some(suffix) = UNSUPPORTED_UNIT_SUFFIXS.iter().find(|s| unit.ends_with(*s)) {
            let type_ = suffix.split_at(1).1;
            anyhow::bail!("Unit type {type_:?} is not supported");
        }
        let unit = unit.strip_suffix(".service").unwrap_or(unit);
        if let Some((name, arg)) = unit.split_once('@') {
            Ok(Self {
                name: name.to_owned(),
                arg: Some(arg.to_owned()),
                instance,
            })
        } else {
            Ok(Self {
                name: unit.to_owned(),
                arg: None,
                instance,
            })
        }
    }

    pub(crate) fn unit_name(&self) -> String {
        format!(
            "{}{}.service",
            self.name,
            if let Some(arg) = self.arg.as_ref() {
                format!("@{arg}")
            } else {
                String::new()
            }
        )
    }

    /// Get systemd "exposure level" for the service (0-100).
    /// 100 means extremely exposed (no hardening), 0 means so sandboxed it can't do much.
    /// Although this is a very crude heuristic, below 40-50 is generally good.
    pub(crate) fn get_exposure_level(&self) -> anyhow::Result<ExposureLevel> {
        let mut cmd = Command::new("systemd-analyze");
        cmd.arg("security");
        if matches!(self.instance, InstanceKind::User) {
            cmd.arg("--user");
        }
        let output = cmd
            .arg(self.unit_name())
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "systemd-analyze failed: {}",
            output.status
        );
        let last_line = output
            .stdout
            .lines()
            .map_while(Result::ok)
            .last()
            .context("Failed to read systemd-analyze output")?;
        let val_f = last_line
            .rsplit(' ')
            .nth(2)
            .and_then(|v| v.parse::<f64>().ok())
            .ok_or_else(|| anyhow::anyhow!("Failed to parse exposure level"))?;
        val_f.try_into()
    }

    pub(crate) fn add_profile_fragment(
        &self,
        hardening_opts: &HardeningOptions,
    ) -> anyhow::Result<()> {
        // Check first if our fragment does not yet exist
        let fragment_path = self.fragment_path(PROFILING_FRAGMENT_NAME, false);
        anyhow::ensure!(
            !fragment_path.is_file(),
            "Fragment config already exists at {fragment_path:?}"
        );
        let harden_fragment_path = self.fragment_path(HARDENING_FRAGMENT_NAME, true);
        anyhow::ensure!(
            !harden_fragment_path.is_file(),
            "Hardening config already exists at {harden_fragment_path:?} and may conflict with profiling"
        );

        // Read current config
        let current_config = self.cat_config().context("Failed to cat service config")?;
        let is_container = current_config.lines().any(|l| l == "[Container]");
        if is_container {
            log::info!("Detected unit generated from .container template");
        }

        // Write new fragment
        #[expect(clippy::unwrap_used)] // fragment_path guarantees by construction we have a parent
        fs::create_dir_all(fragment_path.parent().unwrap())?;
        let mut fragment_file = BufWriter::new(File::create(&fragment_path)?);
        Self::write_fragment_header(&mut fragment_file)?;
        writeln!(fragment_file, "[Service]")?;
        // writeln!(fragment_file, "AmbientCapabilities=CAP_SYS_PTRACE")?;
        let service_type = Self::config_vals("Type", &current_config)?;
        let service_type = service_type.last().map(String::as_str);
        if service_type.is_some_and(|v| v.starts_with("notify")) {
            // needed because strace becomes the main process
            writeln!(fragment_file, "NotifyAccess=all")?;
        }
        if service_type.is_some_and(|v| v == "forking") {
            // strace wrapping keeps the main process alive, so forking semantics no longer apply
            writeln!(fragment_file, "Type=simple")?;
        }
        writeln!(fragment_file, "Environment=RUST_BACKTRACE=1")?;
        if !Self::config_vals("SystemCallFilter", &current_config)?.is_empty() {
            // Allow ptracing, only if a syscall filter is already in place, otherwise it becomes a whitelist
            writeln!(fragment_file, "SystemCallFilter=@debug")?;
        }
        if cfg!(debug_assertions) {
            // strace parsing may slow down enough to risk reaching some service timeouts,
            // but some services also never stop if we set this unconditionally to infinity
            for timeout_config in ["TimeoutStartSec", "TimeoutStopSec"] {
                let timeout = if let Some(timeout) =
                    Self::config_vals(timeout_config, &current_config)?
                        .last()
                        .and_then(|t| systemd_duration::stdtime::parse(t).ok())
                {
                    // Double timeout if we have one
                    format!("{}s", timeout.as_secs() * 2)
                } else {
                    // Default to infinity
                    "infinity".into()
                };
                writeln!(fragment_file, "{timeout_config}={timeout}")?;
            }
        }
        writeln!(fragment_file, "KillMode=control-group")?;
        writeln!(fragment_file, "StandardOutput=journal")?;

        // Profile data dir
        // %t maps to /run for system instances or $XDG_RUNTIME_DIR (usually /run/user/[UID]) for user instance
        let mut rng = rand::rng();
        let profile_data_dir = PathBuf::from(format!(
            "%t/{}-profile-data_{:08x}",
            env!("CARGO_BIN_NAME"),
            rng.random::<u32>()
        ));
        #[expect(clippy::unwrap_used)]
        writeln!(
            fragment_file,
            "RuntimeDirectory={}",
            profile_data_dir.file_name().unwrap().to_str().unwrap()
        )?;

        let shh_bin = env::current_exe()?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Unable to decode current executable path"))?
            .to_owned();
        let shh_common_args = self
            .instance
            .to_cmd_args()
            .into_iter()
            .chain(hardening_opts.to_cmd_args())
            .chain(is_container.then(|| "-c".to_owned()))
            .collect::<Vec<_>>()
            .join(" ");

        // Wrap ExecStartXxx directives
        let mut exec_start_idx = 1;
        let mut profile_data_paths = Vec::new();
        for exec_start_opt in ["ExecStartPre", "ExecStart", "ExecStartPost"] {
            let exec_start_cmds = Self::config_vals(exec_start_opt, &current_config)?;
            if !exec_start_cmds.is_empty() {
                writeln!(fragment_file, "{exec_start_opt}=")?;
            }
            for cmd in exec_start_cmds {
                if cmd.starts_with(PRIVILEGED_PREFIX) {
                    // TODO handle other special prefixes?
                    // Write command unchanged
                    writeln!(fragment_file, "{exec_start_opt}={cmd}")?;
                } else {
                    let profile_data_path = profile_data_dir.join(format!("{exec_start_idx:03}"));
                    exec_start_idx += 1;
                    #[expect(clippy::unwrap_used)]
                    writeln!(
                        fragment_file,
                        "{}={} run {} -p {} -- {}",
                        exec_start_opt,
                        shh_bin,
                        shh_common_args,
                        profile_data_path.to_str().unwrap(),
                        cmd
                    )?;
                    profile_data_paths.push(profile_data_path);
                }
            }
        }

        // Add invocation that merges previous profiles
        #[expect(clippy::unwrap_used)]
        writeln!(
            fragment_file,
            "ExecStopPost={} merge-profile-data {} {}",
            shh_bin,
            shh_common_args,
            profile_data_paths
                .iter()
                .map(|p| p.to_str().unwrap())
                .join(" ")
        )?;

        log::info!("Config fragment written in {fragment_path:?}");
        Ok(())
    }

    pub(crate) fn remove_profile_fragment(&self) -> anyhow::Result<()> {
        let fragment_path = self.fragment_path(PROFILING_FRAGMENT_NAME, false);
        fs::remove_file(&fragment_path)?;
        log::info!("{fragment_path:?} removed");
        // let mut parent_dir = fragment_path;
        // while let Some(parent_dir) = parent_dir.parent() {
        //     if fs::remove_dir(parent_dir).is_err() {
        //         // Likely directory not empty
        //         break;
        //     }
        //     log::info!("{parent_dir:?} removed");
        // }
        Ok(())
    }

    pub(crate) fn remove_hardening_fragment(&self) -> anyhow::Result<()> {
        let fragment_path = self.fragment_path(HARDENING_FRAGMENT_NAME, true);
        fs::remove_file(&fragment_path)?;
        log::info!("{fragment_path:?} removed");
        Ok(())
    }

    pub(crate) fn rename_hardening_fragment(&self) -> anyhow::Result<bool> {
        let fragment_path = self.fragment_path(HARDENING_FRAGMENT_NAME, true);
        let moved = if fragment_path.is_file() {
            let now = chrono::Local::now();
            #[expect(clippy::unwrap_used)]
            let dest_fragment_path = fragment_path.with_file_name(format!(
                "{}.old.{}",
                fragment_path.file_name().unwrap().to_string_lossy(),
                now.format("%Y%m%d%H%M%S")
            ));
            fs::rename(&fragment_path, &dest_fragment_path)?;
            log::info!("{fragment_path:?} moved to {dest_fragment_path:?}");
            true
        } else {
            false
        };
        Ok(moved)
    }

    pub(crate) fn add_hardening_fragment(
        &self,
        opts: Vec<OptionWithValue<String>>,
    ) -> anyhow::Result<PathBuf> {
        let fragment_path = self.fragment_path(HARDENING_FRAGMENT_NAME, true);
        #[expect(clippy::unwrap_used)]
        fs::create_dir_all(fragment_path.parent().unwrap())?;

        let mut fragment_file = BufWriter::new(File::create(&fragment_path)?);
        Self::write_fragment_header(&mut fragment_file)?;
        writeln!(fragment_file, "[Service]")?;
        for opt in opts {
            writeln!(fragment_file, "{opt}")?;
        }

        log::info!("Config fragment written in {fragment_path:?}");
        Ok(fragment_path)
    }

    fn write_fragment_header<W: Write>(writer: &mut W) -> io::Result<()> {
        writeln!(
            writer,
            "# This file has been autogenerated by {} v{}",
            env!("CARGO_BIN_NAME"),
            env!("CARGO_PKG_VERSION"),
        )
    }

    pub(crate) fn reload_unit_config(&self) -> anyhow::Result<()> {
        let mut cmd = Command::new("systemctl");
        if matches!(self.instance, InstanceKind::User) {
            cmd.arg("--user");
        }
        let status = cmd.arg("daemon-reload").status()?;
        anyhow::ensure!(status.success(), "systemctl failed: {status}");
        Ok(())
    }

    pub(crate) fn reset_failed(&self) -> anyhow::Result<()> {
        match self.action("reset-failed", true) {
            Ok(()) => Ok(()),
            Err(err)
                if self.arg.is_some()
                    && err.root_cause().to_string().starts_with("systemctl failed") =>
            {
                // Templated instances can cause systemctl to return 1 if not running,
                // ignore it
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn action(&self, verb: &str, block: bool) -> anyhow::Result<()> {
        let unit_name = self.unit_name();
        log::info!("{verb} {unit_name}");
        let mut cmd = vec![verb];
        if matches!(self.instance, InstanceKind::User) {
            cmd.push("--user");
        }
        if !block {
            cmd.push("--no-block");
        }
        cmd.push(&unit_name);
        let status = Command::new("systemctl").args(cmd).status()?;
        anyhow::ensure!(status.success(), "systemctl failed: {status}");
        Ok(())
    }

    pub(crate) fn profiling_result_retry(
        &self,
        cursor: &JournalCursor,
        invocation: &InvocationId,
    ) -> anyhow::Result<Vec<OptionWithValue<String>>> {
        // DefaultTimeoutStopSec is typically 90s and services can dynamically extend it
        // See https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#TimeoutStopSec=
        const PROFILING_RESULT_TIMEOUT: Duration = Duration::from_secs(90);
        const PROFILING_RESULT_USLEEP: Duration = Duration::from_millis(300);
        const PROFILING_RESULT_WARN_DELAY: Duration = Duration::from_secs(3);

        // For user units or under load, sometimes journalctl does not have the logs yet, so retry with a delay
        let time_start = Instant::now();
        let mut slow_result_warned = false;
        loop {
            match cursor.profiling_result(self, invocation) {
                Ok(opts) => return Ok(opts),
                Err(err) => match err {
                    ProfilingLogError::Incomplete { .. } => {
                        let now = Instant::now();
                        let waited = now.saturating_duration_since(time_start);
                        if waited > PROFILING_RESULT_TIMEOUT {
                            return Err(err).context("Timeout waiting for profiling result");
                        } else if !slow_result_warned && (waited > PROFILING_RESULT_WARN_DELAY) {
                            log::warn!(
                                "Profiling result is not available after {}s ({}), this can be caused by slow service shutdown. Will retry and wait up to {}s",
                                PROFILING_RESULT_WARN_DELAY.as_secs(),
                                err,
                                PROFILING_RESULT_TIMEOUT.as_secs()
                            );
                            slow_result_warned = true;
                        }
                    }
                    ProfilingLogError::Other(_) => {
                        return Err(err)
                            .context("Failed to parse profiling result from journalctl output");
                    }
                },
            }
            sleep(PROFILING_RESULT_USLEEP);
        }
    }

    fn config_vals(key: &str, config: &str) -> anyhow::Result<Vec<String>> {
        // Note: we could use 'systemctl show -p xxx' but its output is different from config
        // files, and we would need to interpret it anyway
        let mut vals = Vec::new();
        let prefix = format!("{key}=");
        let mut lines = config.lines();
        while let Some(line) = lines.next() {
            if let Some(line_val) = line.strip_prefix(&prefix) {
                let val = if line_val.ends_with('\\') {
                    let mut val = line_val.trim_start().to_owned();
                    // Remove trailing '\'
                    val.pop();
                    // Append next lines
                    loop {
                        let next_line = lines
                            .next()
                            .ok_or_else(|| anyhow::anyhow!("Unexpected end of file"))?;
                        val = format!("{} {}", val, next_line.trim_start());
                        if next_line.ends_with('\\') {
                            // Remove trailing '\'
                            val.pop();
                        } else {
                            break;
                        }
                    }
                    val
                } else {
                    line_val.trim().to_owned()
                };
                vals.push(val);
            }
        }
        // Handles lines that reset previously set options
        if let Some((last, _)) = vals
            .split_inclusive(String::is_empty)
            .rev()
            .take(2)
            .collect_tuple()
        {
            vals = last.to_vec();
        }
        Ok(vals)
    }

    fn fragment_path(&self, name: &str, persistent: bool) -> PathBuf {
        // https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#System%20Unit%20Search%20Path
        let base_dir = if persistent {
            let etc = "/etc";
            match self.instance {
                InstanceKind::System => etc.to_owned(),
                InstanceKind::User => {
                    // Use /etc if we can, which affects all user instances, otherwise use per user XDG dir
                    let aflags = nix::unistd::AccessFlags::R_OK
                        .union(nix::unistd::AccessFlags::W_OK)
                        .union(nix::unistd::AccessFlags::X_OK);
                    if nix::unistd::access(etc, aflags).is_ok() {
                        etc.to_owned()
                    } else {
                        #[expect(clippy::unwrap_used)]
                        env::var_os("XDG_CONFIG_DIR")
                            .or_else(|| {
                                env::var_os("HOME").map(|h| {
                                    PathBuf::from(h).join(".config").as_os_str().to_owned()
                                })
                            })
                            .and_then(|p| p.to_str().map(ToOwned::to_owned))
                            .unwrap()
                    }
                }
            }
        } else {
            match self.instance {
                InstanceKind::System => "/run".to_owned(),
                InstanceKind::User => env::var_os("XDG_RUNTIME_DIR")
                    .and_then(|p| p.to_str().map(ToOwned::to_owned))
                    .unwrap_or_else(|| format!("/run/user/{}", nix::unistd::getuid().as_raw())),
            }
        };
        [
            &base_dir,
            "systemd",
            &self.instance.to_string(),
            &format!(
                "{}{}.service.d",
                self.name,
                if self.arg.is_some() { "@" } else { "" }
            ),
            &format!("zz_{}-{}.conf", env!("CARGO_BIN_NAME"), name),
        ]
        .iter()
        .collect()
    }

    fn cat_config(&self) -> anyhow::Result<String> {
        let unit_name = self.unit_name();
        let mut cmd = vec!["cat"];
        if matches!(self.instance, InstanceKind::User) {
            cmd.push("--user");
        }
        cmd.push(&unit_name);
        let output = Command::new("systemctl").args(cmd).output()?;
        anyhow::ensure!(
            output.status.success(),
            "systemctl failed: {}",
            output.status
        );
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn property(&self, prop: &str) -> anyhow::Result<String> {
        let unit_name = self.unit_name();
        let mut cmd = vec!["show", "-p", prop];
        if matches!(self.instance, InstanceKind::User) {
            cmd.push("--user");
        }
        cmd.push(&unit_name);
        let output = Command::new("systemctl").args(cmd).output()?;
        anyhow::ensure!(
            output.status.success(),
            "systemctl failed: {}",
            output.status
        );
        let value = String::from_utf8_lossy(&output.stdout)
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Unexpected systemctl show output"))?
            .1
            .trim_ascii_end()
            .to_owned();
        Ok(value)
    }

    pub(crate) fn invocation_id(&self) -> anyhow::Result<InvocationId> {
        self.property("InvocationID")?
            .parse()
            .context("Failed to parse invocation id")
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    #[test]
    fn config_vals_override() {
        let _ = simple_logger::SimpleLogger::new().init();

        let mut cfg_file = String::new();

        writeln!(cfg_file, "blah=a").unwrap();
        writeln!(cfg_file, "blah=b").unwrap();
        writeln!(cfg_file, "blah=").unwrap();
        writeln!(cfg_file, "blah=c").unwrap();
        writeln!(cfg_file, "blih=e").unwrap();
        writeln!(cfg_file, "bloh=f").unwrap();
        writeln!(cfg_file, "blah=d").unwrap();

        assert_eq!(
            Service::config_vals("blah", &cfg_file).unwrap(),
            vec!["c", "d"]
        );
    }

    #[test]
    fn config_val_multiline() {
        let _ = simple_logger::SimpleLogger::new().init();

        let mut cfg_file = String::new();

        writeln!(
            cfg_file,
            r#"ExecStartPre=/bin/sh -c "[ ! -e /usr/bin/galera_recovery ] && VAR= || \
VAR=`cd /usr/bin/..; /usr/bin/galera_recovery`; [ $? -eq 0 ] \
&& systemctl set-environment _WSREP_START_POSITION=$VAR || exit 1""#
        )
        .unwrap();

        assert_eq!(
            Service::config_vals("ExecStartPre", &cfg_file).unwrap(),
            vec![
                r#"/bin/sh -c "[ ! -e /usr/bin/galera_recovery ] && VAR= ||  VAR=`cd /usr/bin/..; /usr/bin/galera_recovery`; [ $? -eq 0 ]  && systemctl set-environment _WSREP_START_POSITION=$VAR || exit 1""#
            ]
        );
    }
}
