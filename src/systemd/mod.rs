//! Systemd code

mod config;
mod journal;
mod options;
mod resolver;
mod service;
mod version;

pub(crate) use journal::JournalCursor;
pub(crate) use options::{
    ListOptionValue, OptionDescription, SocketFamily, SocketProtocol, build_options,
};
pub(crate) use resolver::resolve;
pub(crate) use service::Service;
pub(crate) use version::{KernelVersion, SystemdVersion};

use crate::systemd::service::InvocationId;

#[derive(Debug, Clone, Default, Eq, PartialEq, clap::ValueEnum, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum InstanceKind {
    #[default]
    System,
    User,
}

impl InstanceKind {
    pub(crate) fn to_cmd_args(&self) -> Vec<String> {
        vec!["-i".to_owned(), self.to_string()]
    }
}

pub(crate) fn start_option_output_line(invocation: Option<&InvocationId>) -> String {
    if let Some(invocation) = invocation {
        format!("-------- Start of suggested service options for {invocation} --------")
    } else {
        "-------- Start of suggested service options --------".to_owned()
    }
}

pub(crate) fn end_option_output_line(invocation: Option<&InvocationId>) -> String {
    if let Some(invocation) = invocation {
        format!("-------- End of suggested service options for {invocation} --------")
    } else {
        "-------- End of suggested service options --------".to_owned()
    }
}

pub(crate) fn report_options(opts: Vec<options::OptionWithValue<&'static str>>) {
    // Report (not through logging facility because we may need to parse it back from service logs)
    let invocation = InvocationId::from_env();
    println!("{}", start_option_output_line(invocation.as_ref()));
    for opt in opts {
        println!("{opt}");
    }
    println!("{}", end_option_output_line(invocation.as_ref()));
}
