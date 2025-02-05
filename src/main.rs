//! Systemd Hardening Helper

#![cfg_attr(all(feature = "nightly", test), feature(test))]
#![cfg_attr(
    feature = "gen-man-pages",
    expect(dead_code, unused_crate_dependencies, unused_imports)
)]

use std::{
    fs::{self, File},
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

#[cfg(feature = "gen-man-pages")]
fn main() -> anyhow::Result<()> {
    use clap::CommandFactory as _;
    let cmd = cl::Args::command();
    let output = std::env::args_os()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Missing output dir argument"))?;
    clap_mangen::generate_to(cmd, output)?;
    Ok(())
}

#[cfg(not(feature = "gen-man-pages"))]
fn main() -> anyhow::Result<()> {
    use std::env;

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
    log::info!("Detected versions: Systemd {sd_version}, Linux kernel {kernel_version}, strace {strace_version}");
    if strace_version < strace::StraceVersion::new(6, 4) {
        log::warn!("Strace version >=6.4 is strongly recommended, if you experience strace output parsing errors, please consider upgrading");
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
                let file = File::create(&profile_data_path)
                    .with_context(|| format!("Failed to create {profile_data_path:?}"))?;
                bincode::serialize_into(file, &actions).context("Failed to serialize profile")?;
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
                let file = File::open(path).with_context(|| format!("Failed to open {path:?}"))?;
                let mut profile_actions: Vec<summarize::ProgramAction> =
                    bincode::deserialize_from(file)
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
                log::warn!("Profiling config will only be applied when systemd config is reloaded, and service restarted");
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
                "Resolved systemd options: {}",
                resolved_opts
                    .iter()
                    .map(|o| format!("{o}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if apply && !resolved_opts.is_empty() {
                service
                    .add_hardening_fragment(resolved_opts)
                    .context("Failed to write systemd unit hardening fragment")?;
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
            service
                .action("try-restart", false)
                .context("Failed to restart service")?;
        }
        cl::Action::ListSystemdOptions => {
            println!("# Supported systemd options\n");
            let mut sd_opts = sd_options(
                &sd_version,
                &kernel_version,
                &cl::HardeningOptions::strict(),
            );
            sd_opts.sort_unstable_by_key(|o| o.name);
            for sd_opt in sd_opts {
                println!("- [`{sd_opt}`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#{sd_opt}=)");
                for opt_val in sd_opt.possible_values {
                    match opt_val.value {
                        systemd::OptionValue::Boolean(v) => {
                            println!("  - `{}`", if v { "true" } else { "false" });
                        }
                        systemd::OptionValue::String(v) => println!("  - `{v}`"),
                        systemd::OptionValue::List(systemd::ListOptionValue { values, .. }) => {
                            for val in values {
                                println!("  - `{val}`");
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
