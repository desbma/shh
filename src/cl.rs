//! Command line interface

use std::path::PathBuf;

use clap::Parser;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(version, about)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub action: Action,
}

/// How hard we should harden
#[derive(Debug, Clone, Default, clap::ValueEnum, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum HardeningMode {
    /// Only generate hardening options if they have a very low risk of breaking things
    #[default]
    Safe,
    /// Will harden further and prevent circumventing restrictions of some options, but may increase the risk of
    /// breaking services
    Aggressive,
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum Action {
    /// Run a program to profile its behavior
    Run {
        /// The command line to run
        #[arg(num_args = 1.., required = true)]
        command: Vec<String>,
        /// How hard we should harden
        #[arg(short, long, default_value_t, value_enum)]
        mode: HardeningMode,
        /// Generate profile data file to be merged with others instead of generating systemd options directly
        #[arg(short, long, default_value = None)]
        profile_data_path: Option<PathBuf>,
        /// Log strace output to this file.
        /// Only use for debugging: this will slow down processing, and may generate a huge file.
        #[arg(short = 'l', long, default_value = None)]
        strace_log_path: Option<PathBuf>,
    },
    /// Merge profile data from previous runs to generate systemd options
    MergeProfileData {
        /// How hard we should harden
        #[arg(short, long, default_value_t, value_enum)]
        mode: HardeningMode,
        /// Profile data paths
        #[arg(num_args = 1.., required = true)]
        paths: Vec<PathBuf>,
    },
    /// Act on a systemd service unit
    #[clap(subcommand)]
    Service(ServiceAction),
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum ServiceAction {
    /// Add fragment config to service to profile its behavior
    StartProfile {
        /// Service unit name
        service: String,
        /// How hard we should harden
        #[arg(short, long, default_value_t, value_enum)]
        mode: HardeningMode,
        /// Disable immediate service restart
        #[arg(short, long, default_value_t = false)]
        no_restart: bool,
    },
    /// Get profiling result and remove fragment config from service
    FinishProfile {
        /// Service unit name
        service: String,
        /// Automatically apply hardening config
        #[arg(short, long, default_value_t = false)]
        apply: bool,
        /// Disable immediate service restart
        #[arg(short, long, default_value_t = false)]
        no_restart: bool,
    },
    /// Remove profiling and/or hardening config fragments, and restart service to restore its initial state
    Reset {
        /// Service unit name
        service: String,
    },
}
