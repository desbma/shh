//! Systemd Hardening Helper

#![cfg_attr(all(feature = "nightly", test), feature(test))]

use std::{
    env,
    fs::{self, File},
    io,
    path::Path,
    process::Command,
    thread,
};

use anyhow::Context as _;
use clap::Parser as _;

mod cl;
mod strace;
mod summarize;
mod systemd;

fn sd_options(
    sd_version: &systemd::SystemdVersion,
    kernel_version: &systemd::KernelVersion,
    hardening_opts: &cl::HardeningOptions,
) -> Vec<systemd::OptionDescription> {
    let sd_opts = systemd::build_options(sd_version, kernel_version, hardening_opts);
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
    if !status.success() {
        anyhow::bail!("Editor failed with status {}", status);
    }
    Ok(())
}

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
    if strace_version < strace::StraceVersion::new(6, 4) {
        log::warn!(
            "Strace version >=6.4 is strongly recommended, if you experience strace output parsing errors, please consider upgrading"
        );
    }

    // Parse cl args
    let args = cl::Args::parse();

    // Handle CL args
    match args.action {
        cl::Action::Run {
            command,
            hardening_opts,
            profile_data_path,
            strace_log_path,
        } => {
            // Build supported systemd options
            let sd_opts = sd_options(&sd_version, &kernel_version, &hardening_opts);

            // Run strace
            let cmd = command.iter().map(|a| &**a).collect::<Vec<&str>>();
            let st = strace::Strace::run(&cmd, strace_log_path)
                .context("Failed to setup strace profiling")?;

            // Start signal handling thread
            let mut signals = signal_hook::iterator::Signals::new([
                signal_hook::consts::signal::SIGINT,
                signal_hook::consts::signal::SIGQUIT,
                signal_hook::consts::signal::SIGTERM,
            ])
            .context("Failed to setup signal handlers")?;
            thread::spawn(move || {
                for sig in signals.forever() {
                    // The strace, and its watched child processes already get the signal, so the iterator will stop naturally
                    log::info!("Got signal {sig:?}, ignoring");
                }
            });

            // Get & parse PATH env var
            let env_paths: Vec<_> = env::var_os("PATH")
                .map(|ev| env::split_paths(&ev).collect())
                .unwrap_or_default();

            // Summarize actions
            let logs = st
                .log_lines()
                .context("Failed to setup strace output reader")?;
            let actions =
                summarize::summarize(logs, &env_paths).context("Failed to summarize syscalls")?;
            log::debug!("{actions:?}");

            if let Some(profile_data_path) = profile_data_path {
                // Dump profile data
                log::info!("Writing profile data into {profile_data_path:?}...");
                let mut file = File::create(&profile_data_path)
                    .with_context(|| format!("Failed to create {profile_data_path:?}"))?;
                bincode::serde::encode_into_std_write(
                    &actions,
                    &mut file,
                    bincode::config::standard(),
                )
                .context("Failed to serialize profile")?;
            } else {
                // Resolve
                let resolved_opts = systemd::resolve(&sd_opts, &actions, &hardening_opts);

                // Report
                systemd::report_options(resolved_opts);
            }
        }
        cl::Action::MergeProfileData {
            hardening_opts,
            paths,
        } => {
            // Build supported systemd options
            let sd_opts = sd_options(&sd_version, &kernel_version, &hardening_opts);

            // Load and merge profile data
            let mut actions: Vec<summarize::ProgramAction> = Vec::new();
            for path in &paths {
                let mut file =
                    File::open(path).with_context(|| format!("Failed to open {path:?}"))?;
                let mut profile_actions: Vec<summarize::ProgramAction> =
                    bincode::serde::decode_from_std_read(&mut file, bincode::config::standard())
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
        }) => {
            let service = systemd::Service::new(&service).context("Invalid service name")?;
            log::info!(
                "Current service exposure level: {}",
                service
                    .get_exposure_level()
                    .context("Failed to get exposure level")?
            );
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
            let service = systemd::Service::new(&service).context("Invalid service name")?;
            service
                .action("stop", true)
                .context("Failed to stop service")?;
            service
                .remove_profile_fragment()
                .context("Failed to remove systemd unit profiling fragment")?;
            let resolved_opts = service.profiling_result()?;
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
            let service = systemd::Service::new(&service)?;
            let _ = service.remove_profile_fragment();
            let _ = service.remove_hardening_fragment();
            service
                .reload_unit_config()
                .context("Failed to reload systemd config")?;
            let _ = service.action("try-restart", true);
        }
        cl::Action::ListSystemdOptions => {
            println!("# Supported systemd options\n");
            let mut sd_opts = sd_options(
                &sd_version,
                &kernel_version,
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
        #[cfg(feature = "generate-extra")]
        cl::Action::GenManPages { dir } => {
            use clap::CommandFactory as _;

            // Use the binary name instead of the default of the package name
            let cmd = cl::Args::command().name(env!("CARGO_BIN_NAME"));
            clap_mangen::generate_to(cmd, &dir)?;
        }
        #[cfg(feature = "generate-extra")]
        cl::Action::GenShellComplete { shell, dir } => {
            use clap::CommandFactory as _;
            use clap::ValueEnum as _;
            use clap_complete::{Shell, generate, generate_to};

            // Use the binary name instead of the default of the package name
            let name = env!("CARGO_BIN_NAME");
            let mut cmd = cl::Args::command().name(name);

            if let Some(shell) = shell {
                if let Some(dir) = dir {
                    generate_to(shell, &mut cmd, name, dir)?;
                } else {
                    generate(shell, &mut cmd, name, &mut io::stdout());
                }
            } else if let Some(dir) = dir {
                let shells = Shell::value_variants();
                for shell_i in shells {
                    generate_to(*shell_i, &mut cmd, name, &dir)?;
                }
            }
        }
    }

    Ok(())
}
