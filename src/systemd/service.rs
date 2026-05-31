//! Systemd service actions

use std::{
    collections::HashSet,
    env, fmt,
    fs::{self, File},
    io::{self, BufRead as _, BufWriter, Write},
    ops::RangeInclusive,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::Context as _;
use itertools::Itertools as _;
use rand::RngExt as _;

use super::InstanceKind;
use crate::{cl::HardeningOptions, systemd::options::OptionWithValue};

#[cfg_attr(test, derive(Debug, Eq, PartialEq))]
pub(crate) struct Service {
    pub name: String,
    /// Instance arguments for templated units (empty for a plain, non-templated unit)
    pub args: Vec<String>,
    pub instance: InstanceKind,
}

/// Profiling fragment comment line prefix used to persist the hardening parameters
const PROFILING_ARGS_COMMENT_PREFIX: &str = "# shh-args: ";

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

impl Service {
    pub(crate) fn new(units: &[String], instance: InstanceKind) -> anyhow::Result<Self> {
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
        let mut name: Option<&str> = None;
        let mut args = Vec::with_capacity(units.len());
        let mut non_templated = false;
        for unit in units {
            if let Some(suffix) = UNSUPPORTED_UNIT_SUFFIXS.iter().find(|s| unit.ends_with(*s)) {
                let type_ = suffix.split_at(1).1;
                anyhow::bail!("Unit type {type_:?} is not supported");
            }
            let unit = unit.strip_suffix(".service").unwrap_or(unit);
            let (base, arg) = if let Some((base, arg)) = unit.split_once('@') {
                anyhow::ensure!(
                    !arg.is_empty(),
                    "Templated unit {unit:?} requires a concrete instance argument"
                );
                (base, Some(arg))
            } else {
                non_templated = true;
                (unit, None)
            };
            match name {
                None => name = Some(base),
                Some(name) => anyhow::ensure!(
                    name == base,
                    "All units must be instances of the same template (got {name:?} and {base:?})"
                ),
            }
            if let Some(arg) = arg {
                args.push(arg.to_owned());
            }
        }
        let name = name
            .ok_or_else(|| anyhow::anyhow!("No service unit specified"))?
            .to_owned();
        anyhow::ensure!(
            !non_templated || args.is_empty(),
            "Cannot mix templated and non-templated units"
        );
        anyhow::ensure!(
            !non_templated || units.len() == 1,
            "Only a single non-templated unit can be specified"
        );
        anyhow::ensure!(
            args.iter().collect::<HashSet<_>>().len() == args.len(),
            "Duplicate instances specified"
        );
        Ok(Self {
            name,
            args,
            instance,
        })
    }

    /// Names of all the concrete units this service refers to
    pub(crate) fn unit_names(&self) -> Vec<String> {
        if self.args.is_empty() {
            vec![format!("{}.service", self.name)]
        } else {
            self.args
                .iter()
                .map(|arg| format!("{}@{arg}.service", self.name))
                .collect()
        }
    }

    /// Get systemd "exposure level" for the service (0-100).
    /// 100 means extremely exposed (no hardening), 0 means so sandboxed it can't do much.
    /// Although this is a very crude heuristic, below 40-50 is generally good.
    pub(crate) fn get_exposure_level(&self, unit_name: &str) -> anyhow::Result<ExposureLevel> {
        let mut cmd = Command::new("systemd-analyze");
        cmd.arg("security");
        if matches!(self.instance, InstanceKind::User) {
            cmd.arg("--user");
        }
        let output = cmd
            .arg(unit_name)
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

        // Read current config (template-level fragment, so any instance is representative)
        #[expect(clippy::indexing_slicing)] // unit_names() is never empty
        let current_config = self
            .cat_config(&self.unit_names()[0])
            .context("Failed to cat service config")?;
        let is_container = current_config.lines().any(|l| l == "[Container]");
        if is_container {
            log::info!("Detected unit generated from .container template");
        }

        // Write new fragment
        #[expect(clippy::unwrap_used)] // fragment_path guarantees by construction we have a parent
        fs::create_dir_all(fragment_path.parent().unwrap())?;
        let mut fragment_file = BufWriter::new(File::create(&fragment_path)?);
        Self::write_fragment_header(&mut fragment_file)?;
        // Persist hardening parameters so finish-profile can resolve options with the same ones
        let hardening_args = hardening_opts
            .to_cmd_args()
            .into_iter()
            .chain(is_container.then(|| "-c".to_owned()))
            .collect::<Vec<_>>();
        writeln!(
            fragment_file,
            "{PROFILING_ARGS_COMMENT_PREFIX}{}",
            hardening_args.join(" ")
        )?;
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
        // %t maps to /run for system instances or $XDG_RUNTIME_DIR (usually /run/user/[UID]) for user instance.
        // For templated units, %i gives each instance a private subdirectory so concurrent
        // instances don't clobber each other's profile data.
        let mut rng = rand::rng();
        let mut runtime_subdir = format!(
            "{}-profile-data_{:08x}",
            env!("CARGO_BIN_NAME"),
            rng.random::<u32>()
        );
        if !self.args.is_empty() {
            runtime_subdir.push_str("/%i");
        }
        let profile_data_dir = PathBuf::from("%t").join(&runtime_subdir);
        writeln!(fragment_file, "RuntimeDirectory={runtime_subdir}")?;
        // Keep profile data after the instance stops so finish-profile can read and merge it
        writeln!(fragment_file, "RuntimeDirectoryPreserve=yes")?;

        let shh_bin = env::current_exe()?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Unable to decode current executable path"))?
            .to_owned();
        let shh_common_args = self
            .instance
            .to_cmd_args()
            .into_iter()
            .chain(hardening_args)
            .collect::<Vec<_>>()
            .join(" ");

        // Wrap ExecStartXxx directives
        let mut exec_start_idx = 1;
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
                }
            }
        }

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
        opts: Vec<OptionWithValue<&'static str>>,
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
        for unit_name in self.unit_names() {
            match self.action_unit(&unit_name, "reset-failed", true) {
                Ok(()) => {}
                Err(err)
                    if !self.args.is_empty()
                        && err.root_cause().to_string().starts_with("systemctl failed") =>
                {
                    // Templated instances can cause systemctl to return 1 if not running,
                    // ignore it
                }
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    /// Run a systemctl action on every instance of the service
    pub(crate) fn action(&self, verb: &str, block: bool) -> anyhow::Result<()> {
        for unit_name in self.unit_names() {
            self.action_unit(&unit_name, verb, block)?;
        }
        Ok(())
    }

    fn action_unit(&self, unit_name: &str, verb: &str, block: bool) -> anyhow::Result<()> {
        log::info!("{verb} {unit_name}");
        let mut cmd = vec![verb];
        if matches!(self.instance, InstanceKind::User) {
            cmd.push("--user");
        }
        if !block {
            cmd.push("--no-block");
        }
        cmd.push(unit_name);
        let status = Command::new("systemctl").args(cmd).status()?;
        anyhow::ensure!(status.success(), "systemctl failed: {status}");
        Ok(())
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
            self.runtime_base_dir()
        };
        [
            &base_dir,
            "systemd",
            &self.instance.to_string(),
            &format!(
                "{}{}.service.d",
                self.name,
                if self.args.is_empty() { "" } else { "@" }
            ),
            &format!("zz_{}-{}.conf", env!("CARGO_BIN_NAME"), name),
        ]
        .iter()
        .collect()
    }

    /// Runtime directory base (`%t`): `/run` for system instances, the user runtime dir otherwise
    fn runtime_base_dir(&self) -> String {
        match self.instance {
            InstanceKind::System => "/run".to_owned(),
            InstanceKind::User => env::var_os("XDG_RUNTIME_DIR")
                .and_then(|p| p.to_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| format!("/run/user/{}", nix::unistd::getuid().as_raw())),
        }
    }

    pub(crate) fn read_profiling_fragment(&self) -> anyhow::Result<String> {
        let path = self.fragment_path(PROFILING_FRAGMENT_NAME, false);
        fs::read_to_string(&path).with_context(|| format!("Failed to read {path:?}"))
    }

    /// Recover the hardening parameters persisted in the profiling fragment
    pub(crate) fn persisted_profiling_args(fragment: &str) -> anyhow::Result<Vec<String>> {
        let line = fragment
            .lines()
            .find_map(|l| l.strip_prefix(PROFILING_ARGS_COMMENT_PREFIX))
            .ok_or_else(|| anyhow::anyhow!("Missing profiling parameters in fragment"))?;
        Ok(line.split_whitespace().map(ToOwned::to_owned).collect())
    }

    /// Absolute path of the profile data directory, parsed back from the profiling fragment
    fn profile_data_base(&self, fragment: &str) -> anyhow::Result<PathBuf> {
        let runtime_dir = Self::config_vals("RuntimeDirectory", fragment)?
            .pop()
            .ok_or_else(|| anyhow::anyhow!("Missing RuntimeDirectory in profiling fragment"))?;
        let subdir = runtime_dir.strip_suffix("/%i").unwrap_or(&runtime_dir);
        Ok(PathBuf::from(self.runtime_base_dir()).join(subdir))
    }

    /// Paths of all per-instance profile data files produced during profiling
    pub(crate) fn profile_data_paths(&self, fragment: &str) -> anyhow::Result<Vec<PathBuf>> {
        let base = self.profile_data_base(fragment)?;
        let dirs = if self.args.is_empty() {
            vec![base]
        } else {
            self.args.iter().map(|arg| base.join(arg)).collect()
        };
        let mut paths = Vec::new();
        for dir in dirs {
            paths.append(&mut Self::instance_profile_data_files(&dir)?);
        }
        Ok(paths)
    }

    /// Regular profile data files in a single instance's preserved runtime directory, sorted by
    /// name. The strace named pipe that also lives in that directory is skipped, as reading it
    /// would block forever.
    fn instance_profile_data_files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        for entry in fs::read_dir(dir)
            .with_context(|| format!("Failed to read profile data directory {dir:?}"))?
        {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                files.push(entry.path());
            }
        }
        anyhow::ensure!(!files.is_empty(), "No profiling data found in {dir:?}");
        files.sort_unstable();
        Ok(files)
    }

    /// Remove the preserved profile data directory tree
    pub(crate) fn remove_profile_data(&self, fragment: &str) -> anyhow::Result<()> {
        let base = self.profile_data_base(fragment)?;
        fs::remove_dir_all(&base).with_context(|| format!("Failed to remove {base:?}"))?;
        log::info!("{base:?} removed");
        Ok(())
    }

    fn cat_config(&self, unit_name: &str) -> anyhow::Result<String> {
        let mut cmd = vec!["cat"];
        if matches!(self.instance, InstanceKind::User) {
            cmd.push("--user");
        }
        cmd.push(unit_name);
        let output = Command::new("systemctl").args(cmd).output()?;
        anyhow::ensure!(
            output.status.success(),
            "systemctl failed: {}",
            output.status
        );
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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

    fn svc(units: &[&str]) -> anyhow::Result<Service> {
        Service::new(
            &units.iter().map(|u| (*u).to_owned()).collect::<Vec<_>>(),
            InstanceKind::System,
        )
    }

    #[test]
    fn new_non_templated() {
        assert_eq!(
            svc(&["foo.service"]).unwrap(),
            Service {
                name: "foo".to_owned(),
                args: vec![],
                instance: InstanceKind::System,
            }
        );
    }

    #[test]
    fn new_multiple_instances() {
        assert_eq!(
            svc(&["foo@a", "foo@b.service"]).unwrap(),
            Service {
                name: "foo".to_owned(),
                args: vec!["a".to_owned(), "b".to_owned()],
                instance: InstanceKind::System,
            }
        );
    }

    #[test]
    fn new_rejects_empty() {
        assert!(svc(&[]).is_err());
    }

    #[test]
    fn new_rejects_different_templates() {
        assert!(svc(&["foo@a", "bar@b"]).is_err());
    }

    #[test]
    fn new_rejects_mixed_templated() {
        assert!(svc(&["foo", "foo@a"]).is_err());
    }

    #[test]
    fn new_rejects_multiple_non_templated() {
        assert!(svc(&["foo", "bar"]).is_err());
    }

    #[test]
    fn new_rejects_empty_instance_arg() {
        assert!(svc(&["foo@"]).is_err());
    }

    #[test]
    fn new_rejects_duplicate_instances() {
        assert!(svc(&["foo@a", "foo@a"]).is_err());
    }

    #[test]
    fn new_rejects_unsupported_unit_type() {
        assert!(svc(&["foo.socket"]).is_err());
    }

    #[test]
    fn unit_names_templated_and_plain() {
        assert_eq!(
            svc(&["foo@a", "foo@b"]).unwrap().unit_names(),
            vec!["foo@a.service", "foo@b.service"]
        );
        assert_eq!(svc(&["foo"]).unwrap().unit_names(), vec!["foo.service"]);
    }

    #[test]
    fn persisted_profiling_args_roundtrip() {
        let fragment = format!(
            "# header\n{PROFILING_ARGS_COMMENT_PREFIX}-m aggressive -w --merge-paths-threshold 5\n[Service]\n"
        );
        assert_eq!(
            Service::persisted_profiling_args(&fragment).unwrap(),
            vec!["-m", "aggressive", "-w", "--merge-paths-threshold", "5"]
        );
    }

    #[test]
    fn persisted_profiling_args_missing() {
        assert!(Service::persisted_profiling_args("[Service]\n").is_err());
    }

    #[test]
    fn profile_data_base_strips_instance_specifier() {
        assert_eq!(
            svc(&["foo@a"])
                .unwrap()
                .profile_data_base("RuntimeDirectory=shh-profile-data_abcd1234/%i\n")
                .unwrap(),
            PathBuf::from("/run/shh-profile-data_abcd1234")
        );
        assert_eq!(
            svc(&["foo"])
                .unwrap()
                .profile_data_base("RuntimeDirectory=shh-profile-data_abcd1234\n")
                .unwrap(),
            PathBuf::from("/run/shh-profile-data_abcd1234")
        );
    }

    #[test]
    fn instance_profile_data_files_skips_pipe() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("001"), b"data").unwrap();
        let pipe = dir.path().join("strace_x.pipe");
        nix::unistd::mkfifo(&pipe, nix::sys::stat::Mode::from_bits(0o600).unwrap()).unwrap();
        assert_eq!(
            Service::instance_profile_data_files(dir.path()).unwrap(),
            vec![dir.path().join("001")]
        );
    }
}
