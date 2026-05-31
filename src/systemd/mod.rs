//! Systemd code

mod options;
mod resolver;
mod service;
mod version;

pub(crate) use options::{
    ListOptionValue, OptionDescription, SocketFamily, SocketProtocol, build_options,
};
pub(crate) use resolver::resolve;
pub(crate) use service::Service;
pub(crate) use version::{KernelVersion, SystemdVersion};

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

pub(crate) fn report_options(opts: Vec<options::OptionWithValue<&'static str>>) {
    println!("-------- Start of suggested service options --------");
    for opt in opts {
        println!("{opt}");
    }
    println!("-------- End of suggested service options --------");
}
