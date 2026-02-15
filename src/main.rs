//! Systemd Hardening Helper

#![cfg_attr(all(feature = "nightly", test), feature(test))]

use std::{
    env,
    fs::{self, File},
    io,
    path::Path,
    process::Command,
    sync::Arc,
    thread::{self, sleep},
    time::Duration,
};

use anyhow::Context as _;
use clap::Parser as _;

mod cl;
mod strace;
mod summarize;
mod sysctl;
mod systemd;

#[cfg(feature = "generate-extras")]
mod extras;

fn sd_options(
    sd_version: &systemd::SystemdVersion,
    kernel_version: &systemd::KernelVersion,
    sysctl_state: &sysctl::State,
    instance_kind: &systemd::InstanceKind,
    container: bool,
    hardening_opts: &cl::HardeningOptions,
) -> Vec<systemd::OptionDescription> {
    let sd_opts = systemd::build_options(
        sd_version,
        kernel_version,
        sysctl_state,
        instance_kind,
        container,
        hardening_opts,
    );
    log::info!(
        "Enabled support for systemd options: {}",
        sd_opts
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    sd_opts
}

fn edit_file(path: &Path) -> anyhow::Result<()> {
    let editor = env::var("VISUAL")
        .or_else(|_| env::var("EDITOR"))
        .unwrap_or_else(|_| {
            log::warn!("Neither VISUAL or EDITOR environment variable is set, defaulting to nano");
            "nano".into()
        });
    let editor_args = shlex::split(&editor)
        .ok_or_else(|| anyhow::anyhow!("Unable to parse environment variable value {editor:?}"))?;
    let (first_arg, other_args) = editor_args
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("Empty editor environment variable value"))?;
    let status = Command::new(first_arg)
        .args(other_args)
        .arg(path)
        .status()?;
    anyhow::ensure!(status.success(), "Editor failed with status {status}");
    Ok(())
}

#[expect(clippy::too_many_lines)]
fn main() -> anyhow::Result<()> {
    // Init logger
    simple_logger::SimpleLogger::new()
        .with_level(if cfg!(debug_assertions) {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .env()
        .init()
        .context("Failed to setup logger")?;

    // Get versions
    let sd_version =
        systemd::SystemdVersion::local_system().context("Failed to get systemd version")?;
    let kernel_version =
        systemd::KernelVersion::local_system().context("Failed to get Linux kernel version")?;
    let strace_version =
        strace::StraceVersion::local_system().context("Failed to get strace version")?;
    log::info!(
        "Detected versions: Systemd {sd_version}, Linux kernel {kernel_version}, strace {strace_version}"
    );
    anyhow::ensure!(
        strace_version >= strace::StraceVersion::new(6, 6),
        "Strace version >=6.6 is required"
    );

    // Parse cl args
    let args = cl::Args::parse();

    // Handle CL args
    match args.action {
        cl::Action::Run {
            command,
            instance,
            container,
            hardening_opts,
            profile_data_path,
            strace_log_path,
        } => {
            hardening_opts
                .validate()
                .context("Invalid command line options")?;

            // Build supported systemd options
            let sysctl_state = sysctl::State::fetch()?;
            let sd_opts = sd_options(
                &sd_version,
                &kernel_version,
                &sysctl_state,
                &instance.instance,
                container,
                &hardening_opts,
            );

            // Run strace
            let cmd = command.iter().map(|a| &**a).collect::<Vec<&str>>();
            let st = Arc::new(
                strace::Strace::run(&cmd, strace_log_path)
                    .context("Failed to setup strace profiling")?,
            );

            // Start signal handling thread
            let mut signals = signal_hook::iterator::Signals::new([
                signal_hook::consts::signal::SIGINT,
                signal_hook::consts::signal::SIGQUIT,
                signal_hook::consts::signal::SIGTERM,
            ])
            .context("Failed to setup signal handlers")?;
            let st_sig = Arc::clone(&st);
            thread::spawn(move || {
                for sig in signals.forever() {
                    // Propagate signal to strace after this delay, in most cases everything should have already stopped
                    const SIGNAL_STRACE_STOP_DELAY: Duration = Duration::from_secs(5);

                    log::info!("Got signal {sig:?}");
                    sleep(SIGNAL_STRACE_STOP_DELAY);
                    log::info!("Stopping strace");
                    st_sig.stop();
                }
            });

            // Get & parse PATH env var
            let env_paths: Vec<_> = env::var_os("PATH")
                .map(|ev| env::split_paths(&ev).collect())
                .unwrap_or_default();

            // Initialize state
            let state = summarize::ProgramState::new(
                env::current_dir().context("Failed to read current directory")?,
            );

            // Summarize actions
            let logs = st
                .log_lines()
                .context("Failed to setup strace output reader")?;
            let actions = summarize::summarize(logs, &env_paths, state)
                .context("Failed to summarize syscalls")?;
            log::debug!("{actions:?}");

            if let Some(profile_data_path) = profile_data_path {
                // Dump profile data
                log::info!("Writing profile data into {profile_data_path:?}...");
                let mut file = File::create(&profile_data_path)
                    .with_context(|| format!("Failed to create {profile_data_path:?}"))?;
                postcard::to_io(&actions, &mut file).context("Failed to serialize profile")?;
            } else {
                // Resolve
                let resolved_opts = systemd::resolve(&sd_opts, &actions, &hardening_opts);

                // Report
                systemd::report_options(resolved_opts);
            }
        }
        cl::Action::MergeProfileData {
            instance,
            container,
            hardening_opts,
            paths,
        } => {
            hardening_opts
                .validate()
                .context("Invalid command line options")?;

            // Build supported systemd options
            let sysctl_state = sysctl::State::fetch()?;
            let sd_opts = sd_options(
                &sd_version,
                &kernel_version,
                &sysctl_state,
                &instance.instance,
                container,
                &hardening_opts,
            );

            // Load and merge profile data
            let mut actions: Vec<summarize::ProgramAction> = Vec::new();
            for path in &paths {
                let profile_data =
                    fs::read(path).with_context(|| format!("Failed to read {path:?}"))?;
                let (mut profile_actions, _): (Vec<summarize::ProgramAction>, _) =
                    postcard::take_from_bytes(&profile_data)
                        .with_context(|| format!("Failed to deserialize profile from {path:?}"))?;
                actions.append(&mut profile_actions);
            }
            log::debug!("{actions:?}");

            // Resolve
            let resolved_opts = systemd::resolve(&sd_opts, &actions, &hardening_opts);

            // Report
            systemd::report_options(resolved_opts);

            // Remove profile data files
            for path in paths {
                fs::remove_file(&path)
                    .with_context(|| format!("Failed to remove profile file {path:?}"))?;
            }
        }
        cl::Action::Service(cl::ServiceAction::StartProfile {
            service,
            hardening_opts,
            no_restart,
            refresh,
        }) => {
            hardening_opts
                .validate()
                .context("Invalid command line options")?;

            let service = systemd::Service::new(&service.name, service.instance.instance)
                .context("Invalid service name")?;
            log::info!(
                "Current service exposure level: {}",
                service
                    .get_exposure_level()
                    .context("Failed to get exposure level")?
            );
            if refresh {
                let moved = service
                    .rename_hardening_fragment()
                    .context("Failed to move existing systemd hardening fragment")?;
                if moved {
                    service
                        .reload_unit_config()
                        .context("Failed to reload systemd config")?;
                }
            }
            service
                .add_profile_fragment(&hardening_opts)
                .context("Failed to write systemd unit profiling fragment")?;
            if no_restart {
                log::warn!(
                    "Profiling config will only be applied when systemd config is reloaded, and service restarted"
                );
            } else {
                service
                    .reload_unit_config()
                    .context("Failed to reload systemd config")?;
                service
                    .action("restart", false)
                    .context("Failed to restart service")?;
            }
        }
        cl::Action::Service(cl::ServiceAction::FinishProfile {
            service,
            apply,
            edit,
            no_restart,
        }) => {
            let service = systemd::Service::new(&service.name, service.instance.instance)
                .context("Invalid service name")?;
            let cursor = systemd::JournalCursor::current()?;
            service
                .action("stop", true)
                .context("Failed to stop service")?;
            service
                .remove_profile_fragment()
                .context("Failed to remove systemd unit profiling fragment")?;
            let resolved_opts = service.profiling_result_retry(&cursor)?;
            log::info!(
                "Resolved systemd options:\n{}",
                resolved_opts
                    .iter()
                    .map(|o| format!("{o}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            if apply && !resolved_opts.is_empty() {
                let fragment_path = service
                    .add_hardening_fragment(resolved_opts)
                    .context("Failed to write systemd unit hardening fragment")?;
                if edit {
                    edit_file(&fragment_path).with_context(|| {
                        format!("Failed to edit geneted frament {fragment_path:?}")
                    })?;
                }
            }
            service
                .reload_unit_config()
                .context("Failed to reload systemd config")?;
            if apply {
                log::info!(
                    "New service exposure level: {}",
                    service
                        .get_exposure_level()
                        .context("Failed to get exposure level")?
                );
            }
            if !no_restart {
                service
                    .action("start", false)
                    .context("Failed to start service")?;
            }
        }
        cl::Action::Service(cl::ServiceAction::Reset { service }) => {
            let service = systemd::Service::new(&service.name, service.instance.instance)?;
            let _ = service.remove_profile_fragment();
            let _ = service.remove_hardening_fragment();
            service
                .reload_unit_config()
                .context("Failed to reload systemd config")?;
            let _ = service.action("try-restart", true);
        }
        cl::Action::ListSystemdOptions => {
            println!("# Supported systemd options\n");
            let sysctl_state = sysctl::State::all();
            let mut sd_opts = sd_options(
                &sd_version,
                &kernel_version,
                &sysctl_state,
                &systemd::InstanceKind::System,
                false,
                &cl::HardeningOptions::strict(),
            );
            sd_opts.sort_unstable_by_key(|o| o.name);
            {
                let mut stdout = io::stdout().lock();
                for sd_opt in sd_opts {
                    sd_opt
                        .write_markdown(&mut stdout)
                        .context("Failed to write markdown output")?;
                }
            }
        }
        #[cfg(feature = "generate-extras")]
        cl::Action::GenManPages { dir } => {
            extras::generate_man_pages(&dir)?;
        }
        #[cfg(feature = "generate-extras")]
        cl::Action::GenShellCompletions { shell, dir } => {
            extras::generate_shell_completions(shell, dir.as_deref())?;
        }
    }

    Ok(())
}
