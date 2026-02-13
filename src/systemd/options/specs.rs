//! Systemd options specs

// Last updated for systemd v257

use std::{
    fs, iter,
    path::{Path, PathBuf},
};

use itertools::Itertools as _;
use strum::IntoEnumIterator as _;

use crate::{
    cl::{HardeningMode, HardeningOptions},
    summarize::{NetworkActivity, NetworkActivityKind, ProgramAction, SetSpecifier},
    systemd::{
        ListOptionValue, OptionDescription, SocketFamily, SocketProtocol,
        options::{
            DenySyscalls, EmptyPathDescription, ListMode, OptionContext, OptionEffect,
            OptionUpdater, OptionValue, OptionValueDescription, OptionValueEffect, OptionWithValue,
            PathDescription, SYSCALL_CLASSES, action_path_exception, merge_similar_paths,
        },
    },
};

/// Systemd option specification
pub(crate) trait OptionSpec: Sync {
    /// Builds the option description for this option
    fn build(&'static self, ctx: &OptionContext<'_>) -> OptionDescription;

    /// Returns true if this option should be enabled for the given context
    fn enabled_if(&self, _ctx: &OptionContext<'_>) -> bool {
        // Default to always enabled
        true
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectSystem=
struct ProtectSystem;

impl OptionSpec for ProtectSystem {
    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        let mut protect_system_yes_nowrite: Vec<_> = [
            "/usr/", "/boot/", "/efi/", "/lib/", "/lib64/", "/bin/", "/sbin/",
        ]
        .iter()
        .map(|p| OptionValueEffect::DenyWrite(PathDescription::base(p)))
        .collect();
        let mut protect_system_full_nowrite = protect_system_yes_nowrite.clone();
        protect_system_full_nowrite
            .push(OptionValueEffect::DenyWrite(PathDescription::base("/etc/")));
        protect_system_yes_nowrite.push(OptionValueEffect::DenyAction(ProgramAction::MountToHost));
        protect_system_full_nowrite.push(OptionValueEffect::DenyAction(ProgramAction::MountToHost));
        OptionDescription {
            name: "ProtectSystem",
            possible_values: vec![
                OptionValueDescription {
                    value: OptionValue::Boolean(true),
                    desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                        protect_system_yes_nowrite,
                    )),
                },
                OptionValueDescription {
                    value: OptionValue::String("full".to_owned()),
                    desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                        protect_system_full_nowrite,
                    )),
                },
                OptionValueDescription {
                    value: OptionValue::String("strict".to_owned()),
                    desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                        OptionValueEffect::DenyWrite(PathDescription::Base {
                            base: "/".into(),
                            exceptions: vec!["/dev/".into(), "/proc/".into(), "/sys/".into()],
                        }),
                        OptionValueEffect::DenyAction(ProgramAction::MountToHost),
                    ])),
                },
            ],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectHome=
struct ProtectHome;

impl OptionSpec for ProtectHome {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces()
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        let home_paths = ["/home/", "/root/", "/run/user/"];
        OptionDescription {
            name: "ProtectHome",
            possible_values: vec![
                OptionValueDescription {
                    value: OptionValue::String("tmpfs".to_owned()),
                    desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                        home_paths
                            .iter()
                            .map(|p| OptionValueEffect::EmptyPath(EmptyPathDescription::base(p)))
                            .chain(iter::once(OptionValueEffect::DenyAction(
                                ProgramAction::MountToHost,
                            )))
                            .collect(),
                    )),
                },
                OptionValueDescription {
                    value: OptionValue::String("read-only".to_owned()),
                    desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                        home_paths
                            .iter()
                            .map(|p| OptionValueEffect::EmptyPath(EmptyPathDescription::base_ro(p)))
                            .chain(iter::once(OptionValueEffect::DenyAction(
                                ProgramAction::MountToHost,
                            )))
                            .collect(),
                    )),
                },
                OptionValueDescription {
                    value: OptionValue::Boolean(true),
                    desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                        home_paths
                            .iter()
                            .map(|p| OptionValueEffect::RemovePath(PathDescription::base(p)))
                            .chain(iter::once(OptionValueEffect::DenyAction(
                                ProgramAction::MountToHost,
                            )))
                            .collect(),
                    )),
                },
            ],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateTmp=
struct PrivateTmp;

impl OptionSpec for PrivateTmp {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces()
    }

    fn build(&self, ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "PrivateTmp",
            possible_values: vec![OptionValueDescription {
                value: if ctx.systemd_min_version(257, 0) {
                    OptionValue::String("disconnected".into())
                } else {
                    OptionValue::Boolean(true)
                },
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                    OptionValueEffect::EmptyPath(EmptyPathDescription::base("/tmp")),
                    OptionValueEffect::EmptyPath(EmptyPathDescription::base("/var/tmp")),
                    OptionValueEffect::DenyAction(ProgramAction::MountToHost),
                ])),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateDevices=
struct PrivateDevices;

impl OptionSpec for PrivateDevices {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces()
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "PrivateDevices",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                    OptionValueEffect::EmptyPath(EmptyPathDescription {
                        base: "/dev/".into(),
                        base_ro: true,
                        exceptions_ro: vec![],
                        // https://github.com/systemd/systemd/blob/v254/src/core/namespace.c#L912
                        exceptions_rw: [
                            "null",
                            "zero",
                            "full",
                            "random",
                            "urandom",
                            "tty",
                            "pts/",
                            "ptmx",
                            "shm/",
                            "mqueue/",
                            "hugepages/",
                            "log",
                        ]
                        .iter()
                        .map(|p| PathBuf::from("/dev/").join(p))
                        .collect(),
                    }),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Class("raw-io")),
                    OptionValueEffect::DenyAction(ProgramAction::MknodSpecial),
                    OptionValueEffect::DenyExec(PathDescription::base("/dev")),
                    OptionValueEffect::DenyAction(ProgramAction::MountToHost),
                ])),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateMounts=
struct PrivateMounts;

impl OptionSpec for PrivateMounts {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces()
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "PrivateMounts",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::DenyAction(
                    ProgramAction::MountToHost,
                )),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelTunables=
struct ProtectKernelTunables;

impl OptionSpec for ProtectKernelTunables {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces()
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "ProtectKernelTunables",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(
                    // https://github.com/systemd/systemd/blob/v254/src/core/namespace.c#L113
                    [
                        "acpi/",
                        "apm",
                        "asound/",
                        "bus/",
                        "fs/",
                        "irq/",
                        "latency_stats",
                        "mttr",
                        "scsi/",
                        "sys/",
                        "sysrq-trigger",
                        "timer_stats",
                    ]
                    .iter()
                    .map(|p| {
                        OptionValueEffect::DenyWrite(PathDescription::Base {
                            base: PathBuf::from("/proc/").join(p),
                            exceptions: vec![],
                        })
                    })
                    .chain(["kallsyms", "kcore"].iter().map(|p| {
                        OptionValueEffect::RemovePath(PathDescription::Base {
                            base: PathBuf::from("/proc/").join(p),
                            exceptions: vec![],
                        })
                    }))
                    .chain(
                        // https://github.com/systemd/systemd/blob/v254/src/core/namespace.c#L130
                        iter::once(OptionValueEffect::DenyWrite(PathDescription::base("/sys"))),
                    )
                    .chain(iter::once(OptionValueEffect::DenyAction(
                        ProgramAction::MountToHost,
                    )))
                    .collect(),
                )),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelModules=
struct ProtectKernelModules;

impl OptionSpec for ProtectKernelModules {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces() && !ctx.container_unit()
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "ProtectKernelModules",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                    // https://github.com/systemd/systemd/blob/v254/src/core/namespace.c#L140
                    OptionValueEffect::RemovePath(PathDescription::base("/lib/modules/")),
                    OptionValueEffect::RemovePath(PathDescription::base("/usr/lib/modules/")),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Class("module")),
                    OptionValueEffect::DenyAction(ProgramAction::MountToHost),
                ])),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelLogs=
struct ProtectKernelLogs;

impl OptionSpec for ProtectKernelLogs {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces() && !ctx.container_unit()
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "ProtectKernelLogs",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                    // https://github.com/systemd/systemd/blob/v254/src/core/namespace.c#L148
                    OptionValueEffect::RemovePath(PathDescription::base("/proc/kmsg")),
                    OptionValueEffect::RemovePath(PathDescription::base("/dev/kmsg")),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("syslog")),
                    // TODO figure out about this one, systemd doc says it doesn't but tests seem to say otherwise?
                    OptionValueEffect::DenyAction(ProgramAction::MountToHost),
                ])),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectControlGroups=
struct ProtectControlGroups;

impl OptionSpec for ProtectControlGroups {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.is_system_instance()
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        // TODO private/strip
        OptionDescription {
            name: "ProtectControlGroups",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                    OptionValueEffect::DenyWrite(PathDescription::base("/sys/fs/cgroup/")),
                    OptionValueEffect::DenyAction(ProgramAction::MountToHost),
                ])),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectProc=
// https://github.com/systemd/systemd/blob/v247/NEWS#L342
// https://github.com/systemd/systemd/commit/4e39995371738b04d98d27b0d34ea8fe09ec9fab
// https://docs.kernel.org/filesystems/proc.html#mount-options
struct ProtectProc;

impl OptionSpec for ProtectProc {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.is_system_instance()
            && ctx.systemd_min_version(247, 0)
            && ctx.kernel_min_version(5, 8, 0)
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "ProtectProc",
            // Since we have no easy & reliable (race free) way to know which process belongs to
            // which user, only support the most restrictive option
            possible_values: vec![OptionValueDescription {
                value: OptionValue::String("ptraceable".to_owned()),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                    OptionValueEffect::RemovePath(PathDescription::pattern("^/proc/[0-9]+(/|$)")),
                    OptionValueEffect::DenyAction(ProgramAction::MountToHost),
                ])),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProcSubset=
struct ProcSubset;

impl OptionSpec for ProcSubset {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.is_system_instance()
            && ctx.systemd_min_version(247, 0)
            && ctx.kernel_min_version(5, 8, 0)
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "ProcSubset",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::String("pid".to_owned()),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                    OptionValueEffect::RemovePath(PathDescription::pattern(
                        "^/proc/[^/]*[^0-9/]+[^/]*",
                    )),
                    OptionValueEffect::DenyAction(ProgramAction::MountToHost),
                ])),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#LockPersonality=
struct LockPersonality;

impl OptionSpec for LockPersonality {
    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "LockPersonality",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                // In practice, the option allows the call if the default personality is set, but we don't
                // need to model that level of precision.
                // The "deny" model prevents false positives
                desc: OptionEffect::Simple(OptionValueEffect::DenySyscalls(DenySyscalls::Single(
                    "personality",
                ))),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictRealtime=
struct RestrictRealtime;

impl OptionSpec for RestrictRealtime {
    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "RestrictRealtime",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::DenyAction(
                    ProgramAction::SetRealtimeScheduler,
                )),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectClock=
struct ProtectClock;

impl OptionSpec for ProtectClock {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces() && !ctx.container_unit()
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "ProtectClock",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                    OptionValueEffect::DenyWrite(PathDescription::pattern("/dev/rtc.*")),
                    // See handling of CAP_SYS_TIME
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("stime")),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Class("clock")),
                    // See handling of CAP_WAKE_ALARM
                    OptionValueEffect::DenyAction(ProgramAction::SetAlarm),
                ])),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#MemoryDenyWriteExecute=
// https://github.com/systemd/systemd/blob/v254/src/shared/seccomp-util.c#L1721
struct MemoryDenyWriteExecute;

impl OptionSpec for MemoryDenyWriteExecute {
    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "MemoryDenyWriteExecute",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::DenyAction(
                    ProgramAction::WriteExecuteMemoryMapping,
                )),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallArchitectures=
//
// This is actually very safe to enable, but since we don't currently support checking for its
// compatibility during profiling, only enable it in aggressive mode
struct SystemCallArchitectures;

impl OptionSpec for SystemCallArchitectures {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        matches!(ctx.hardening_opts.mode, HardeningMode::Aggressive)
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "SystemCallArchitectures",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::String("native".to_owned()),
                desc: OptionEffect::None,
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#ReadWritePaths=
#[derive(Debug)]
struct ReadOnlyPaths;

impl OptionSpec for ReadOnlyPaths {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces() && ctx.hardening_opts.filesystem_whitelisting
    }

    fn build(&'static self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "ReadOnlyPaths",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::List(ListOptionValue {
                    values: vec!["/".to_owned()],
                    value_if_empty: None,
                    option_prefix: "",
                    elem_prefix: "-",
                    repeat_option: false,
                    mode: ListMode::BlackList,
                    mergeable_paths: true,
                }),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                    OptionValueEffect::DenyWrite(PathDescription::base("/")),
                    OptionValueEffect::DenyAction(ProgramAction::MountToHost),
                ])),
            }],
            updater: Some(self),
        }
    }
}

impl OptionUpdater for ReadOnlyPaths {
    fn effect(
        &self,
        cur_effect: &OptionValueEffect,
        action: &ProgramAction,
        _opts: &HardeningOptions,
    ) -> Option<OptionValueEffect> {
        let action_path = match action {
            ProgramAction::Write(action_path) => action_path.to_owned(),
            ProgramAction::Create(action_path) => action_path.parent()?.to_owned(),
            _ => return None,
        };
        match cur_effect {
            OptionValueEffect::DenyWrite(PathDescription::Base { base, exceptions })
                if action_path != Path::new("/") =>
            {
                let mut new_exceptions = Vec::with_capacity(exceptions.len() + 1);
                new_exceptions.extend(exceptions.iter().cloned());
                new_exceptions.push(action_path);
                Some(OptionValueEffect::DenyWrite(PathDescription::Base {
                    base: base.to_owned(),
                    exceptions: new_exceptions,
                }))
            }
            _ => None,
        }
    }

    fn options(&self, new_effect: &OptionValueEffect) -> Vec<OptionWithValue<&'static str>> {
        match new_effect {
            OptionValueEffect::DenyWrite(PathDescription::Base { base, exceptions }) => {
                vec![
                    OptionWithValue {
                        name: "ReadOnlyPaths",
                        value: OptionValue::List(ListOptionValue {
                                    #[expect(clippy::unwrap_used)] // path is from our option, so unicode safe
                                    values: vec![base.to_str().unwrap().to_owned()],
                                    value_if_empty: None,
                                    option_prefix: "",
                                    elem_prefix: "-",
                                    repeat_option: false,
                                    mode: ListMode::BlackList,
                                    mergeable_paths: true,
                                }),
                    },
                    OptionWithValue {
                        name: "ReadWritePaths",
                        value: OptionValue::List(ListOptionValue {
                            values: merge_similar_paths(exceptions, None)
                                .iter()
                                .filter_map(|p| p.to_str().map(ToOwned::to_owned))
                                .collect(),
                            value_if_empty: None,
                            option_prefix: "",
                            elem_prefix: "-",
                            repeat_option: false,
                            mode: ListMode::WhiteList,
                            mergeable_paths: true,
                        }),
                    },
                ]
            }
            OptionValueEffect::DenyAction(ProgramAction::MountToHost) => {
                vec![OptionWithValue {
                    name: "PrivateMounts",
                    value: OptionValue::Boolean(true),
                }]
            }
            _ => unreachable!(),
        }
    }

    fn dynamic_option_names(&self) -> &[&str] {
        &["PrivateMounts", "ReadOnlyPaths", "ReadWritePaths"]
    }
}

// https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#ReadWritePaths=
#[derive(Debug)]
struct InaccessiblePaths;

impl OptionSpec for InaccessiblePaths {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces() && ctx.hardening_opts.filesystem_whitelisting
    }

    fn build(&'static self, _ctx: &OptionContext<'_>) -> OptionDescription {
        let mut possible_values = vec![OptionValueDescription {
            value: OptionValue::List(ListOptionValue {
                values: vec!["/".to_owned()],
                value_if_empty: None,
                option_prefix: "",
                elem_prefix: "-",
                repeat_option: false,
                mode: ListMode::BlackList,
                mergeable_paths: true,
            }),
            desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                OptionValueEffect::RemovePath(PathDescription::base("/")),
                OptionValueEffect::DenyAction(ProgramAction::MountToHost),
            ])),
        }];
        // To avoid InaccessiblePaths being completely disabled simply because of the equivalent of 'ls /',
        // we set another option value for each dir directly under /
        let base_paths: Option<Vec<String>> = fs::read_dir("/")
            .ok()
            .and_then(|i| i.collect::<Result<Vec<_>, _>>().ok())
            .and_then(|v| {
                // Don't make those inaccessible, systemd won't be able to start anything
                let excluded_run_dirs = [Path::new("/run"), Path::new("/proc")];
                v.into_iter()
                    .filter(|e| !excluded_run_dirs.contains(&e.path().as_ref()))
                    // systemd follows symlinks when applying option, so exclude them
                    .filter(|e| e.file_type().is_ok_and(|t| !t.is_symlink()))
                    .map(|e| e.path().to_str().map(ToOwned::to_owned))
                    .collect()
            })
            .map(|mut v: Vec<_>| {
                v.sort_unstable();
                v
            });
        if let Some(base_paths) = base_paths {
            possible_values.insert(
                0,
                OptionValueDescription {
                    value: OptionValue::List(ListOptionValue {
                        values: base_paths.clone(),
                        value_if_empty: None,
                        option_prefix: "",
                        elem_prefix: "-",
                        repeat_option: false,
                        mode: ListMode::BlackList,
                        mergeable_paths: true,
                    }),
                    desc: OptionEffect::Cumulative(
                        base_paths
                            .iter()
                            .map(|p| {
                                OptionValueEffect::Multiple(vec![
                                    OptionValueEffect::RemovePath(PathDescription::base(p)),
                                    OptionValueEffect::DenyAction(ProgramAction::MountToHost),
                                ])
                            })
                            .collect(),
                    ),
                },
            );
        }
        OptionDescription {
            name: "InaccessiblePaths",
            possible_values,
            updater: Some(self),
        }
    }
}

impl OptionUpdater for InaccessiblePaths {
    fn effect(
        &self,
        cur_effect: &OptionValueEffect,
        action: &ProgramAction,
        _opts: &HardeningOptions,
    ) -> Option<OptionValueEffect> {
        {
            let (action_path, action_ro) = match action {
                ProgramAction::Read(action_path) | ProgramAction::Exec(action_path) => {
                    (action_path.to_owned(), true)
                }
                ProgramAction::Write(action_path) => (action_path.to_owned(), false),
                ProgramAction::Create(action_path) => {
                    (action_path.parent().map(Path::to_path_buf)?, false)
                }
                _ => return None,
            };
            match cur_effect {
                OptionValueEffect::RemovePath(PathDescription::Base { base, exceptions }) => {
                    // This will be reached only when first transforming an initial InaccessiblePaths option (RemovePath) into
                    // less restrictive EmptyPaths + exceptions
                    assert!(exceptions.is_empty());
                    let new_exception_path = action_path_exception(action_path);
                    if base.starts_with(&new_exception_path) {
                        return None;
                    }
                    let (exceptions_ro, exceptions_rw) = if action_ro {
                        (vec![new_exception_path], vec![])
                    } else {
                        (vec![], vec![new_exception_path])
                    };
                    Some(OptionValueEffect::EmptyPath(EmptyPathDescription {
                        base: base.to_owned(),
                        base_ro: true,
                        exceptions_ro,
                        exceptions_rw,
                    }))
                }
                OptionValueEffect::EmptyPath(EmptyPathDescription {
                    base,
                    base_ro,
                    exceptions_ro,
                    exceptions_rw,
                }) => {
                    let mut new_exceptions_ro =
                        Vec::with_capacity(exceptions_ro.len() + usize::from(action_ro));
                    new_exceptions_ro.extend(exceptions_ro.iter().cloned());
                    let mut new_exceptions_rw =
                        Vec::with_capacity(exceptions_rw.len() + usize::from(!action_ro));
                    new_exceptions_rw.extend(exceptions_rw.iter().cloned());
                    let mut base_ro = *base_ro;
                    let new_exception_path = action_path_exception(action_path);
                    if matches!(action, ProgramAction::Create(_)) && new_exception_path == *base {
                        base_ro = false;
                    } else {
                        if base.starts_with(&new_exception_path) {
                            return None;
                        }
                        if action_ro {
                            new_exceptions_ro.push(new_exception_path);
                        } else {
                            new_exceptions_rw.push(new_exception_path);
                        }
                    }
                    // Remove exceptions in ro list if in rw
                    new_exceptions_ro
                        .retain(|ero| !new_exceptions_rw.iter().any(|erw| ero.starts_with(erw)));
                    Some(OptionValueEffect::EmptyPath(EmptyPathDescription {
                        base: base.to_owned(),
                        base_ro,
                        exceptions_ro: new_exceptions_ro,
                        exceptions_rw: new_exceptions_rw,
                    }))
                }
                _ => None,
            }
        }
    }

    fn options(&self, new_effect: &OptionValueEffect) -> Vec<OptionWithValue<&'static str>> {
        match new_effect {
            OptionValueEffect::EmptyPath(EmptyPathDescription {
                base,
                base_ro,
                exceptions_ro,
                exceptions_rw,
            }) => {
                // TemporayFileSystem nullifies ReadOnlyPaths, so we must apply read only restrictions here too
                let mut new_opts = Vec::with_capacity(
                    1 + usize::from(!exceptions_ro.is_empty())
                        + usize::from(!exceptions_rw.is_empty()),
                );
                new_opts.push(OptionWithValue {
                    name: "TemporaryFileSystem",
                    value: OptionValue::List(ListOptionValue {
                                #[expect(clippy::unwrap_used)]  // path is from our option, so unicode safe
                                values: vec![if *base_ro {
                                    format!("{}:ro", base.to_str().unwrap())
                                } else {
                                    base.to_str().unwrap().to_owned()
                                }],
                                value_if_empty: None,
                                option_prefix: "",
                                elem_prefix: "",
                                repeat_option: false,
                                mode: ListMode::BlackList,
                                mergeable_paths: true,
                            }),
                });
                let merged_exceptions_ro: Vec<_> = {
                    let merged_paths = merge_similar_paths(exceptions_ro, None);
                    if merged_paths.iter().any(|p| *base_ro && (p == base)) {
                        // The exception nullifies the option, bail out
                        return vec![];
                    }
                    merged_paths
                        .into_iter()
                        .filter_map(|p| p.to_str().map(ToOwned::to_owned))
                        .collect()
                };
                if !merged_exceptions_ro.is_empty() {
                    new_opts.push(OptionWithValue {
                        name: "BindReadOnlyPaths",
                        value: OptionValue::List(ListOptionValue {
                            values: merged_exceptions_ro,
                            value_if_empty: None,
                            option_prefix: "",
                            elem_prefix: "-",
                            repeat_option: false,
                            mode: ListMode::WhiteList,
                            mergeable_paths: true,
                        }),
                    });
                }
                let merged_exceptions_rw: Vec<_> = {
                    let merged_paths = merge_similar_paths(exceptions_rw, None);
                    if merged_paths.iter().any(|p| p == base) {
                        // The exception nullifies the option, bail out
                        return vec![];
                    }
                    merged_paths
                        .into_iter()
                        .filter_map(|p| p.to_str().map(ToOwned::to_owned))
                        .collect()
                };
                if !merged_exceptions_rw.is_empty() {
                    new_opts.push(OptionWithValue {
                        name: "BindPaths",
                        value: OptionValue::List(ListOptionValue {
                            values: merged_exceptions_rw,
                            value_if_empty: None,
                            option_prefix: "",
                            elem_prefix: "-",
                            repeat_option: false,
                            mode: ListMode::WhiteList,
                            mergeable_paths: true,
                        }),
                    });
                }
                new_opts
            }
            OptionValueEffect::DenyAction(ProgramAction::MountToHost) => {
                vec![OptionWithValue {
                    name: "PrivateMounts",
                    value: OptionValue::Boolean(true),
                }]
            }
            #[expect(clippy::unwrap_used)]
            OptionValueEffect::RemovePath(PathDescription::Base { base, exceptions }) => {
                assert!(exceptions.is_empty());
                vec![OptionWithValue {
                    name: "InaccessiblePaths",
                    value: OptionValue::List(ListOptionValue {
                        values: vec![base.to_str().unwrap().to_owned()],
                        value_if_empty: None,
                        option_prefix: "",
                        elem_prefix: "-",
                        repeat_option: false,
                        mode: ListMode::BlackList,
                        mergeable_paths: true,
                    }),
                }]
            }
            _ => unreachable!(),
        }
    }

    fn dynamic_option_names(&self) -> &[&str] {
        &[
            "PrivateMounts",
            "TemporaryFileSystem",
            "BindReadOnlyPaths",
            "BindPaths",
        ]
    }
}

// https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#ReadWritePaths=
#[derive(Debug)]
struct NoExecPaths;

impl OptionSpec for NoExecPaths {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces() && ctx.hardening_opts.filesystem_whitelisting
    }

    fn build(&'static self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "NoExecPaths",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::List(ListOptionValue {
                    values: vec!["/".to_owned()],
                    value_if_empty: None,
                    option_prefix: "",
                    elem_prefix: "-",
                    repeat_option: false,
                    mode: ListMode::BlackList,
                    mergeable_paths: true,
                }),
                desc: OptionEffect::Simple(OptionValueEffect::Multiple(vec![
                    OptionValueEffect::DenyExec(PathDescription::base("/")),
                    OptionValueEffect::DenyAction(ProgramAction::MountToHost),
                ])),
            }],
            updater: Some(self),
        }
    }
}

impl OptionUpdater for NoExecPaths {
    fn effect(
        &self,
        cur_effect: &OptionValueEffect,
        action: &ProgramAction,
        _opts: &HardeningOptions,
    ) -> Option<OptionValueEffect> {
        let ProgramAction::Exec(action_path) = action else {
            return None;
        };
        match cur_effect {
            OptionValueEffect::DenyExec(PathDescription::Base { base, exceptions })
                if action_path != Path::new("/") =>
            {
                let mut new_exceptions = Vec::with_capacity(exceptions.len() + 1);
                new_exceptions.extend(exceptions.iter().cloned());
                new_exceptions.push(action_path.to_owned());
                Some(OptionValueEffect::DenyExec(PathDescription::Base {
                    base: base.to_owned(),
                    exceptions: new_exceptions,
                }))
            }
            _ => None,
        }
    }

    fn options(&self, new_effect: &OptionValueEffect) -> Vec<OptionWithValue<&'static str>> {
        match new_effect {
            OptionValueEffect::DenyExec(PathDescription::Base { base, exceptions }) => {
                vec![
                    OptionWithValue {
                        name: "NoExecPaths",
                        value: OptionValue::List(ListOptionValue {
                                    #[expect(clippy::unwrap_used)] // path is from our option, so unicode safe
                                    values: vec![base.to_str().unwrap().to_owned()],
                                    value_if_empty: None,
                                    option_prefix: "",
                                    elem_prefix: "-",
                                    repeat_option: false,
                                    mode: ListMode::BlackList,
                                    mergeable_paths: true,
                                }),
                    },
                    OptionWithValue {
                        name: "ExecPaths",
                        value: OptionValue::List(ListOptionValue {
                            values: merge_similar_paths(exceptions, None)
                                .iter()
                                .filter_map(|p| p.to_str().map(ToOwned::to_owned))
                                .collect(),
                            value_if_empty: None,
                            option_prefix: "",
                            elem_prefix: "-",
                            repeat_option: false,
                            mode: ListMode::WhiteList,
                            mergeable_paths: true,
                        }),
                    },
                ]
            }
            OptionValueEffect::DenyAction(ProgramAction::MountToHost) => {
                vec![OptionWithValue {
                    name: "PrivateMounts",
                    value: OptionValue::Boolean(true),
                }]
            }
            _ => unreachable!(),
        }
    }

    fn dynamic_option_names(&self) -> &[&str] {
        &["NoExecPaths", "PrivateMounts", "ExecPaths"]
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictAddressFamilies=
struct RestrictAddressFamilies;

impl OptionSpec for RestrictAddressFamilies {
    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "RestrictAddressFamilies",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::List(ListOptionValue {
                    values: ADDRESS_FAMILIES.iter().map(|s| (*s).to_owned()).collect(),
                    value_if_empty: Some("none"),
                    option_prefix: "",
                    elem_prefix: "",
                    repeat_option: false,
                    mode: ListMode::WhiteList,
                    mergeable_paths: false,
                }),
                desc: OptionEffect::Cumulative(
                    ADDRESS_FAMILIES
                        .iter()
                        .map(|af| {
                            OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(
                                NetworkActivity {
                                    #[expect(clippy::unwrap_used)]
                                    af: SetSpecifier::One(af.parse().unwrap()),
                                    proto: SetSpecifier::All,
                                    kind: SetSpecifier::All,
                                    local_port: SetSpecifier::All,
                                    address: SetSpecifier::All,
                                }
                                .into(),
                            ))
                        })
                        .collect(),
                ),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateNetwork=
struct PrivateNetwork;

impl OptionSpec for PrivateNetwork {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces() && matches!(ctx.hardening_opts.mode, HardeningMode::Aggressive)
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        // For now we enable this option if no sockets are used at all, in theory this could break if
        // a socket file descriptor is passed to it from another process.
        // Although this is probably a very rare/niche case, it is possible, so we consider it only in aggressive mode
        OptionDescription {
            name: "PrivateNetwork",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::Boolean(true),
                desc: OptionEffect::Simple(OptionValueEffect::DenyAction(
                    ProgramAction::NetworkActivity(
                        NetworkActivity {
                            af: SetSpecifier::All,
                            proto: SetSpecifier::All,
                            kind: SetSpecifier::All,
                            local_port: SetSpecifier::All,
                            address: SetSpecifier::All,
                        }
                        .into(),
                    ),
                )),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html#SocketBindAllow=bind-rule
#[derive(Debug)]
struct SocketBindDeny;

impl OptionSpec for SocketBindDeny {
    fn build(&'static self, ctx: &OptionContext<'_>) -> OptionDescription {
        let deny_binds: Vec<_> = SocketFamily::iter()
            .take(2)
            .cartesian_product(SocketProtocol::iter().take(2))
            .collect();
        OptionDescription {
            name: "SocketBindDeny",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::List(ListOptionValue {
                    values: deny_binds
                        .iter()
                        .map(|(af, proto)| format!("{af}:{proto}"))
                        .collect(),
                    value_if_empty: None,
                    option_prefix: "",
                    elem_prefix: "",
                    repeat_option: true,
                    mode: ListMode::BlackList,
                    mergeable_paths: false,
                }),
                desc: OptionEffect::Cumulative(
                    deny_binds
                        .into_iter()
                        .map(|(af, proto)| {
                            OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(
                                NetworkActivity {
                                    af: SetSpecifier::One(af),
                                    proto: SetSpecifier::One(proto),
                                    kind: SetSpecifier::One(NetworkActivityKind::Bind),
                                    local_port: SetSpecifier::All,
                                    address: SetSpecifier::All,
                                }
                                .into(),
                            ))
                        })
                        .collect(),
                ),
            }],
            updater: ctx.hardening_opts.network_firewalling.then_some(self),
        }
    }
}

impl OptionUpdater for SocketBindDeny {
    fn effect(
        &self,
        cur_effect: &OptionValueEffect,
        action: &ProgramAction,
        _opts: &HardeningOptions,
    ) -> Option<OptionValueEffect> {
        let OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(effect_na)) = cur_effect
        else {
            return None;
        };
        let local_port = if let ProgramAction::NetworkActivity(na) = action {
            if let SetSpecifier::One(local_port) = &na.as_ref().local_port {
                local_port
            } else {
                return None;
            }
        } else {
            return None;
        };
        let mut new_eff_local_port = effect_na.local_port.clone();
        new_eff_local_port.remove(local_port);
        Some(OptionValueEffect::DenyAction(
            ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: effect_na.af.clone(),
                    proto: effect_na.proto.clone(),
                    kind: effect_na.kind.clone(),
                    local_port: new_eff_local_port,
                    address: effect_na.address.clone(),
                }
                .into(),
            ),
        ))
    }

    fn options(&self, new_effect: &OptionValueEffect) -> Vec<OptionWithValue<&'static str>> {
        let (af, proto, local_port) =
            if let OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(na)) = new_effect {
                if let NetworkActivity {
                    af: SetSpecifier::One(af),
                    proto: SetSpecifier::One(proto),
                    local_port,
                    ..
                } = na.as_ref()
                {
                    (af, proto, local_port)
                } else {
                    unreachable!()
                }
            } else {
                unreachable!();
            };
        let port_exceptions = local_port.excluded_elements();
        let mut opts = Vec::with_capacity(1 + port_exceptions.len());
        opts.push(OptionWithValue {
            name: "SocketBindDeny",
            value: OptionValue::String(format!("{af}:{proto}")),
        });
        opts.extend(
            port_exceptions
                .iter()
                .map(|port_exception| OptionWithValue {
                    name: "SocketBindAllow",
                    value: OptionValue::String(format!("{af}:{proto}:{port_exception}")),
                }),
        );
        opts
    }

    fn dynamic_option_names(&self) -> &[&str] {
        &["SocketBindDeny"]
    }
}

// https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#IPAddressAllow=ADDRESS%5B/PREFIXLENGTH%5D%E2%80%A6
#[derive(Debug)]
struct IpAddressDeny;

impl OptionSpec for IpAddressDeny {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.hardening_opts.network_firewalling
    }

    fn build(&'static self, _ctx: &OptionContext<'_>) -> OptionDescription {
        OptionDescription {
            name: "IPAddressDeny",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::String("any".into()),
                desc: OptionEffect::Simple(OptionValueEffect::DenyAction(
                    ProgramAction::NetworkActivity(
                        NetworkActivity {
                            af: SetSpecifier::Some(vec![SocketFamily::Ipv4, SocketFamily::Ipv6]),
                            proto: SetSpecifier::All,
                            kind: SetSpecifier::Some(NetworkActivityKind::ADDRESSED.to_vec()),
                            local_port: SetSpecifier::All,
                            address: SetSpecifier::All,
                        }
                        .into(),
                    ),
                )),
            }],
            updater: Some(self),
        }
    }
}

impl OptionUpdater for IpAddressDeny {
    fn effect(
        &self,
        cur_effect: &OptionValueEffect,
        action: &ProgramAction,
        _opts: &HardeningOptions,
    ) -> Option<OptionValueEffect> {
        let OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(effect_na)) = cur_effect
        else {
            return None;
        };
        let action_addr = if let ProgramAction::NetworkActivity(na) = action {
            if let NetworkActivity {
                address: SetSpecifier::One(action_addr),
                ..
            } = na.as_ref()
            {
                action_addr
            } else {
                return None;
            }
        } else {
            return None;
        };
        let mut new_effect_address = effect_na.address.clone();
        new_effect_address.remove(action_addr);
        Some(OptionValueEffect::DenyAction(
            ProgramAction::NetworkActivity(
                NetworkActivity {
                    address: new_effect_address,
                    ..*effect_na.to_owned()
                }
                .into(),
            ),
        ))
    }

    fn options(&self, new_effect: &OptionValueEffect) -> Vec<OptionWithValue<&'static str>> {
        match new_effect {
            OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(na)) => {
                let NetworkActivity { address, .. } = na.as_ref();
                vec![
                    OptionWithValue {
                        name: "IPAddressDeny",
                        value: OptionValue::String("any".into()),
                    },
                    OptionWithValue {
                        name: "IPAddressAllow",
                        value: OptionValue::List(ListOptionValue {
                            values: address
                                .excluded_elements()
                                .into_iter()
                                .map(|e| e.to_string())
                                .collect(),
                            value_if_empty: None,
                            option_prefix: "",
                            elem_prefix: "",
                            repeat_option: false,
                            mode: ListMode::WhiteList,
                            mergeable_paths: false,
                        }),
                    },
                ]
            }
            _ => unreachable!(),
        }
    }

    fn dynamic_option_names(&self) -> &[&str] {
        &["IPAddressDeny", "IPAddressAllow"]
    }
}

// https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#CapabilityBoundingSet=
struct CapabilityBoundingSet;

impl OptionSpec for CapabilityBoundingSet {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        ctx.can_use_namespaces() && !ctx.container_unit()
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        // Note: we don't want to duplicate the kernel permission checking logic here, which would be
        // a maintenance nightmare, so in most case we over (never under!) simplify the capability's effect
        // or we don't implement it at all if too complex because the risk of breakage is too high
        let cap_effects = [
            // CAP_AUDIT_CONTROL, CAP_AUDIT_READ, CAP_AUDIT_WRITE: requires netlink socket message handling
            (
                "CAP_BLOCK_SUSPEND",
                OptionValueEffect::Multiple(vec![
                    OptionValueEffect::DenyWrite(PathDescription::base("/proc/sys/wake_lock")),
                    OptionValueEffect::DenyAction(ProgramAction::Wakeup),
                ]),
            ),
            (
                "CAP_BPF",
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("bpf")),
            ),
            // CAP_CHECKPOINT_RESTORE: too complex?
            (
                "CAP_CHOWN",
                OptionValueEffect::DenySyscalls(DenySyscalls::Class("chown")),
            ),
            // CAP_DAC_OVERRIDE: too complex?
            // CAP_DAC_READ_SEARCH: too complex?
            // CAP_FOWNER: too complex?
            // CAP_FSETID: too complex?
            (
                "CAP_IPC_LOCK",
                OptionValueEffect::Multiple(vec![
                    OptionValueEffect::DenySyscalls(DenySyscalls::Class("memlock")),
                    OptionValueEffect::DenyAction(ProgramAction::LockMemoryMapping),
                    OptionValueEffect::DenyAction(ProgramAction::HugePageMemoryMapping),
                ]),
            ),
            // CAP_IPC_OWNER: too complex?
            (
                "CAP_KILL",
                OptionValueEffect::Multiple(vec![
                    OptionValueEffect::DenyAction(ProgramAction::KillOther),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("ioctl")),
                ]),
            ),
            // TODO CAP_LEASE
            // TODO CAP_LINUX_IMMUTABLE
            // CAP_MAC_ADMIN: too complex?
            // CAP_MAC_OVERRIDE: too complex?
            (
                "CAP_MKNOD",
                OptionValueEffect::DenyAction(ProgramAction::MknodSpecial),
            ),
            // CAP_NET_ADMIN: too complex?
            // CAP_NET_BIND_SERVICE would be too complex/unreliable to handle:
            // - for IPv4 sockets, either PROT_SOCK or net.ipv4.ip_unprivileged_port_start sysctl control the provileged port threshold
            // - for other socket families, rules are different
            // CAP_NET_BROADCAST: unused
            (
                "CAP_NET_RAW",
                OptionValueEffect::Multiple(
                    iter::once(OptionValueEffect::DenyAction(
                        ProgramAction::NetworkActivity(
                            NetworkActivity {
                                af: SetSpecifier::One(SocketFamily::Other("AF_PACKET".into())),
                                proto: SetSpecifier::All,
                                kind: SetSpecifier::All,
                                local_port: SetSpecifier::All,
                                address: SetSpecifier::All,
                            }
                            .into(),
                        ),
                    ))
                    .chain(
                        ADDRESS_FAMILIES
                            .iter()
                            // AF_NETLINK sockets use SOCK_RAW, but does not require CAP_NET_RAW
                            .filter(|af| **af != "AF_NETLINK")
                            .map(|af| {
                                OptionValueEffect::DenyAction(ProgramAction::NetworkActivity(
                                    NetworkActivity {
                                        #[expect(clippy::unwrap_used)]
                                        af: SetSpecifier::One(af.parse().unwrap()),
                                        proto: SetSpecifier::One(SocketProtocol::Other(
                                            "SOCK_RAW".into(),
                                        )),
                                        kind: SetSpecifier::All,
                                        local_port: SetSpecifier::All,
                                        address: SetSpecifier::All,
                                    }
                                    .into(),
                                ))
                            }),
                    )
                    .collect(),
                    // TODO non local bind
                ),
            ),
            (
                "CAP_PERFMON",
                OptionValueEffect::Multiple(vec![
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("perf_event_open")),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("bpf")),
                ]),
            ),
            // CAP_SETFCAP: too complex?
            // TODO CAP_SETGID
            // TODO CAP_SETPCAP
            // TODO CAP_SETUID
            // CAP_SYS_ADMIN: definitely too complex
            (
                "CAP_SYS_BOOT",
                OptionValueEffect::DenySyscalls(DenySyscalls::Class("reboot")),
            ),
            (
                "CAP_SYS_CHROOT",
                OptionValueEffect::Multiple(vec![
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("chroot")),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("setns")),
                ]),
            ),
            (
                "CAP_SYS_MODULE",
                OptionValueEffect::DenySyscalls(DenySyscalls::Class("module")),
            ),
            (
                "CAP_SYS_NICE",
                OptionValueEffect::DenySyscalls(DenySyscalls::Class("resources")),
            ),
            (
                "CAP_SYS_PACCT",
                OptionValueEffect::DenySyscalls(DenySyscalls::Single("acct")),
            ),
            (
                "CAP_SYS_PTRACE",
                OptionValueEffect::Multiple(vec![
                    // TODO distinguish other processes
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("ptrace)")),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("get_robust_list")),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("process_vm_readv")),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("process_vm_writev")),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("kcmp")),
                ]),
            ),
            // CAP_SYS_RAWIO: too complex?
            // CAP_SYS_RESOURCE: too complex?
            (
                "CAP_SYS_TIME",
                OptionValueEffect::Multiple(vec![
                    OptionValueEffect::DenySyscalls(DenySyscalls::Class("clock")),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("stime")),
                ]),
            ),
            (
                "CAP_SYS_TTY_CONFIG",
                OptionValueEffect::Multiple(vec![
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("vhangup")),
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("ioctl")),
                ]),
            ),
            (
                "CAP_SYSLOG",
                OptionValueEffect::Multiple(vec![
                    OptionValueEffect::DenySyscalls(DenySyscalls::Single("syslog")),
                    OptionValueEffect::DenyAction(ProgramAction::Read("/dev/kmsg".into())),
                ]),
            ),
            (
                "CAP_WAKE_ALARM",
                OptionValueEffect::DenyAction(ProgramAction::SetAlarm),
            ),
        ];
        OptionDescription {
            name: "CapabilityBoundingSet",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::List(ListOptionValue {
                    values: cap_effects.iter().map(|(c, _e)| (*c).to_owned()).collect(),
                    value_if_empty: None,
                    option_prefix: "~",
                    elem_prefix: "",
                    repeat_option: false,
                    mode: ListMode::BlackList,
                    mergeable_paths: false,
                }),
                desc: OptionEffect::Cumulative(cap_effects.into_iter().map(|(_c, e)| e).collect()),
            }],
            updater: None,
        }
    }
}

// https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=
struct SystemCallFilter;

impl OptionSpec for SystemCallFilter {
    fn enabled_if(&self, ctx: &OptionContext<'_>) -> bool {
        !matches!(ctx.hardening_opts.mode, HardeningMode::Generic)
    }

    fn build(&self, _ctx: &OptionContext<'_>) -> OptionDescription {
        let mut syscall_classes: Vec<_> = SYSCALL_CLASSES.keys().copied().collect();
        syscall_classes.sort_unstable();
        OptionDescription {
            name: "SystemCallFilter",
            possible_values: vec![OptionValueDescription {
                value: OptionValue::List(ListOptionValue {
                    values: syscall_classes
                        .iter()
                        .map(|c| format!("@{c}:EPERM"))
                        .collect(),
                    value_if_empty: None,
                    option_prefix: "~",
                    elem_prefix: "",
                    repeat_option: false,
                    mode: ListMode::BlackList,
                    mergeable_paths: false,
                }),
                desc: OptionEffect::Cumulative(
                    syscall_classes
                        .into_iter()
                        .map(|class| OptionValueEffect::DenySyscalls(DenySyscalls::Class(class)))
                        .collect(),
                ),
            }],
            updater: None,
        }
    }
}

//
// Warning: options values must be ordered from less to most restrictive
//

// Options model does not aim to accurately define the option's effects, it is often an oversimplification.
// However the model should always tend to make options *more* (or equally as) restrictive than what they really are,
// as to avoid suggesting options that might break execution.

// TODO APPROXIMATION
// Some options implicitly force NoNewPrivileges=true which has some effects in itself,
// which we need to model

/// Address families for `RestrictAddressFamilies` and `CapabilityBoundingSet`
const ADDRESS_FAMILIES: &[&str] = &[
    // curl https://man7.org/linux/man-pages/man7/address_families.7.html | grep -o 'AF_[A-Za-z0-9]*' | sort -u | xargs -I'{}' echo \"'{}'\",
    "AF_ALG",
    "AF_APPLETALK",
    "AF_ATMPVC",
    "AF_ATMSVC",
    "AF_AX25",
    "AF_BLUETOOTH",
    "AF_BRIDGE",
    "AF_CAIF",
    "AF_CAN",
    "AF_DECnet",
    "AF_ECONET",
    "AF_IB",
    "AF_IEEE802154",
    "AF_INET",
    "AF_INET6",
    "AF_IPX",
    "AF_IRDA",
    "AF_ISDN",
    "AF_IUCV",
    "AF_KCM",
    "AF_KEY",
    "AF_LLC",
    "AF_LOCAL",
    "AF_MPLS",
    "AF_NETBEUI",
    "AF_NETLINK",
    "AF_NETROM",
    "AF_PACKET",
    "AF_PHONET",
    "AF_PPPOX",
    "AF_QIPCRTR",
    "AF_RDS",
    "AF_ROSE",
    "AF_RXRPC",
    "AF_SECURITY",
    "AF_SMC",
    "AF_TIPC",
    "AF_UNIX",
    "AF_VSOCK",
    "AF_WANPIPE",
    "AF_X25",
    "AF_XDP",
];

/// Static registry of option specifications with their enable conditions
pub(crate) static OPTION_SPECS: &[&dyn OptionSpec] = &[
    &ProtectSystem,
    &ProtectHome,
    &PrivateTmp,
    &PrivateDevices,
    &PrivateMounts,
    &ProtectKernelTunables,
    &ProtectKernelModules,
    &ProtectKernelLogs,
    &ProtectControlGroups,
    &ProtectProc,
    &ProcSubset,
    &LockPersonality,
    &RestrictRealtime,
    &ProtectClock,
    &MemoryDenyWriteExecute,
    &SystemCallArchitectures,
    &ReadOnlyPaths,
    &InaccessiblePaths,
    &NoExecPaths,
    &RestrictAddressFamilies,
    &PrivateNetwork,
    &SocketBindDeny,
    &IpAddressDeny,
    &CapabilityBoundingSet,
    &SystemCallFilter,
];
