//! Resolver code that finds options compatible with program actions

use std::{
    collections::HashSet,
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

use itertools::Itertools as _;

use super::{
    ListOptionValue,
    options::{MergeConstraints, OptionUpdater, PathMount, merge_similar_paths},
};
use crate::{
    cl::HardeningOptions,
    strace::SyscallName,
    summarize::ProgramAction,
    systemd::options::{
        ListMode, OptionDescription, OptionEffect, OptionValue, OptionValueEffect, OptionWithValue,
    },
};

impl OptionValueEffect {
    /// Check if a single (non-`Multiple`) effect is compatible with an action
    fn is_compatible_with(&self, action: &ProgramAction, prev_actions: &[ProgramAction]) -> bool {
        match self {
            OptionValueEffect::DenyAction(denied) => !denied.denies(action),
            OptionValueEffect::DenyWrite(ro_paths) => match action {
                ProgramAction::Write(path_action) | ProgramAction::Create(path_action) => {
                    !ro_paths.matches(path_action)
                }
                // Removal also writes to the parent directory
                ProgramAction::Remove(path_action) => {
                    !ro_paths.matches(path_action)
                        && path_action
                            .parent()
                            .is_none_or(|pap| !ro_paths.matches(pap))
                }
                ProgramAction::RequireSameMount(a, b) => !ro_paths.splits_mount(a, b),
                _ => true,
            },
            OptionValueEffect::DenyExec(noexec_paths) => match action {
                ProgramAction::Exec(path_action) => !noexec_paths.matches(path_action),
                ProgramAction::RequireSameMount(a, b) => !noexec_paths.splits_mount(a, b),
                _ => true,
            },
            OptionValueEffect::EmptyPath(empty_paths) => {
                // A path created on the empty base, outside the exceptions mounting existing host entries
                let created = |path: &Path| {
                    empty_paths.matches(path, true)
                        && prev_actions.contains(&ProgramAction::Create(path.to_owned()))
                };
                match action {
                    ProgramAction::Read(path_action) | ProgramAction::Exec(path_action) => {
                        !empty_paths.matches(path_action, true) || created(path_action)
                    }
                    ProgramAction::Write(path_action) => {
                        !empty_paths.matches(path_action, false)
                            || created(path_action)
                            // The writable base itself exists, empty
                            || (!empty_paths.base_ro && *path_action == empty_paths.base)
                    }
                    ProgramAction::Remove(path_action) => {
                        (!empty_paths.matches(path_action, false)
                            && path_action
                                .parent()
                                .is_none_or(|pap| !empty_paths.matches(pap, false)))
                            || created(path_action)
                    }
                    ProgramAction::Create(path_action) => {
                        !empty_paths.matches(path_action, false)
                            || (!empty_paths.base_ro
                                && path_action
                                    .parent()
                                    .is_some_and(|pap| pap == empty_paths.base || created(pap)))
                    }
                    ProgramAction::RequireSameMount(a, b) => !empty_paths.splits_mount(a, b),
                    _ => true,
                }
            }
            OptionValueEffect::RemovePath(removed_paths) => match action {
                ProgramAction::Read(path_action)
                | ProgramAction::Write(path_action)
                | ProgramAction::Exec(path_action)
                | ProgramAction::Create(path_action)
                | ProgramAction::Remove(path_action) => !removed_paths.matches(path_action),
                ProgramAction::RequireSameMount(a, b) => !removed_paths.splits_mount(a, b),
                _ => true,
            },
            OptionValueEffect::DenySyscalls(denied) => {
                if let ProgramAction::Syscalls(syscalls) = action {
                    let denied_syscalls = denied.syscalls();
                    let syscalls = syscalls.iter().map(SyscallName::as_str).collect();
                    denied_syscalls.intersection(&syscalls).next().is_none()
                } else {
                    true
                }
            }
            OptionValueEffect::Multiple(_) => {
                unreachable!()
            }
        }
    }

    fn compatible(
        &self,
        action: &ProgramAction,
        prev_actions: &[ProgramAction],
        updater: Option<&dyn OptionUpdater>,
        hardening_opts: &HardeningOptions,
    ) -> ActionOptionEffectCompatibility {
        if self
            .iter()
            .all(|e| e.is_compatible_with(action, prev_actions))
        {
            return ActionOptionEffectCompatibility::Compatible;
        }

        let Some(updater) = updater else {
            return ActionOptionEffectCompatibility::Incompatible;
        };

        let mut changed_opt_desc = None;
        for subeff in self.iter() {
            let newopt_desc = if subeff.is_compatible_with(action, prev_actions) {
                ChangedOptionValueDescription {
                    new_options: updater.options(subeff),
                    effect: subeff.to_owned(),
                }
            } else if let Some(new_subeff) = updater.effect(subeff, action, hardening_opts) {
                ChangedOptionValueDescription {
                    new_options: updater.options(&new_subeff),
                    effect: new_subeff,
                }
            } else {
                return ActionOptionEffectCompatibility::Incompatible;
            };
            changed_opt_desc = Some(changed_opt_desc.map_or_else(
                || newopt_desc.clone(),
                |mut prev: ChangedOptionValueDescription| {
                    prev.merge(&newopt_desc);
                    prev
                },
            ));
        }
        changed_opt_desc.map_or(ActionOptionEffectCompatibility::Incompatible, |o| {
            ActionOptionEffectCompatibility::CompatibleIfChanged(o.into())
        })
    }
}

/// A systemd option value and its effect, altered from original
#[derive(Debug, Clone)]
pub(crate) struct ChangedOptionValueDescription {
    pub new_options: Vec<OptionWithValue<&'static str>>,
    pub effect: OptionValueEffect,
}

impl ChangedOptionValueDescription {
    fn merge(&mut self, other: &Self) {
        let mut to_append = Vec::with_capacity(other.new_options.len());
        for ooption in &other.new_options {
            let mut handled = false;
            for option in &mut self.new_options {
                handled = option.merge(ooption);
                if handled {
                    break;
                }
            }
            if !handled {
                to_append.push(ooption.clone());
            }
        }
        self.new_options.append(&mut to_append);
        self.effect.merge(&other.effect);
    }
}

/// How compatible is an action with an option effect?
pub(crate) enum ActionOptionEffectCompatibility {
    Compatible,
    CompatibleIfChanged(Box<ChangedOptionValueDescription>),
    Incompatible,
}

impl From<bool> for ActionOptionEffectCompatibility {
    fn from(value: bool) -> Self {
        if value {
            Self::Compatible
        } else {
            Self::Incompatible
        }
    }
}

fn actions_compatible(
    eff: &OptionValueEffect,
    actions: &[ProgramAction],
    updater: Option<&dyn OptionUpdater>,
    hardening_opts: &HardeningOptions,
) -> ActionOptionEffectCompatibility {
    let mut changed_desc: Option<Box<ChangedOptionValueDescription>> = None;
    let mut start = 0;
    loop {
        let mut changed = false;
        for i in start..actions.len() {
            let cur_eff = changed_desc.as_ref().map_or(eff, |d| &d.effect);
            #[expect(clippy::unwrap_used, clippy::indexing_slicing)]
            let (cur_action, previous_actions) = actions[..=i].split_last().unwrap();
            match cur_eff.compatible(cur_action, previous_actions, updater, hardening_opts) {
                ActionOptionEffectCompatibility::Compatible => {}
                ActionOptionEffectCompatibility::CompatibleIfChanged(new_desc) => {
                    log::debug!(
                        "Option effect {:?} is incompatible with {:?}, changing effect to {:?}",
                        cur_eff,
                        cur_action,
                        new_desc.effect
                    );
                    changed_desc = Some(new_desc);
                    changed = true;
                }
                ActionOptionEffectCompatibility::Incompatible => {
                    log::debug!("Option effect {cur_eff:?} is incompatible with {cur_action:?}");
                    return ActionOptionEffectCompatibility::Incompatible;
                }
            }
        }
        // A mount added for an action can split the paths of a mount requirement checked before it
        match actions
            .iter()
            .position(|a| matches!(a, ProgramAction::RequireSameMount(..)))
        {
            Some(first_requirement) if changed => start = first_requirement,
            _ => break,
        }
    }

    if let Some(new_desc) = changed_desc {
        ActionOptionEffectCompatibility::CompatibleIfChanged(new_desc)
    } else {
        ActionOptionEffectCompatibility::Compatible
    }
}

fn actions_compatible_list(
    opt_name: &'static str,
    list: &ListOptionValue,
    effects: &[OptionValueEffect],
    actions: &[ProgramAction],
    updater: Option<&dyn OptionUpdater>,
    hardening_opts: &HardeningOptions,
) -> ActionOptionEffectCompatibility {
    debug_assert_eq!(list.values.len(), effects.len());
    let mut changed_desc: Option<Box<ChangedOptionValueDescription>> = None;
    let mut enabled_list_vals = Vec::new();
    let mut enabled_list_val_effects = Vec::new();
    for (list_val, list_val_eff) in list.values.iter().zip(effects.to_vec().iter_mut()) {
        let compatible = actions_compatible(list_val_eff, actions, updater, hardening_opts);
        let enable_opt_val = match list.mode {
            ListMode::WhiteList => {
                matches!(compatible, ActionOptionEffectCompatibility::Incompatible)
            }
            ListMode::BlackList => match compatible {
                ActionOptionEffectCompatibility::Compatible => true,
                ActionOptionEffectCompatibility::CompatibleIfChanged(new_desc) => {
                    if let Some(changed_desc) = changed_desc.as_mut() {
                        changed_desc.merge(&new_desc);
                    } else {
                        changed_desc = Some(new_desc);
                    }
                    false
                }
                ActionOptionEffectCompatibility::Incompatible => false,
            },
        };
        if enable_opt_val {
            enabled_list_vals.push(list_val.to_owned());
            enabled_list_val_effects.push(list_val_eff.to_owned());
        }
    }
    if enabled_list_vals.is_empty() && matches!(list.mode, ListMode::BlackList) {
        return ActionOptionEffectCompatibility::Incompatible;
    }
    if list.values != enabled_list_vals || changed_desc.is_some() {
        // Rebuild option with changed list
        let mut new_list_desc = Box::new(ChangedOptionValueDescription {
            new_options: vec![OptionWithValue {
                name: opt_name,
                value: OptionValue::List(Box::new(ListOptionValue {
                    values: enabled_list_vals,
                    ..list.to_owned()
                })),
            }],
            effect: OptionValueEffect::Multiple(enabled_list_val_effects),
        });
        if let Some(changed_desc) = changed_desc.as_mut() {
            new_list_desc.merge(changed_desc);
            *changed_desc = new_list_desc;
        } else {
            changed_desc = Some(new_list_desc);
        }
    }
    if let Some(changed_desc) = changed_desc {
        ActionOptionEffectCompatibility::CompatibleIfChanged(changed_desc)
    } else {
        ActionOptionEffectCompatibility::Compatible
    }
}

/// Collect the values of the path lists with a given mount
fn mount_paths(opts: &[OptionWithValue<&'static str>], mount: PathMount) -> HashSet<PathBuf> {
    opts.iter()
        .filter_map(|o| match &o.value {
            OptionValue::List(list) if list.paths == Some(mount) => Some(&list.values),
            _ => None,
        })
        .flatten()
        .map(PathBuf::from)
        .collect()
}

/// Merge similar paths in the lists with a given mount, never into a forbidden path
fn merge_mount_paths(
    opts: &mut [OptionWithValue<&'static str>],
    mount: PathMount,
    threshold: NonZeroUsize,
    forbidden: &HashSet<PathBuf>,
) {
    for option in opts {
        if let OptionValue::List(list) = &mut option.value
            && list.paths == Some(mount)
        {
            list.values = merge_similar_paths(
                list.values
                    .iter()
                    .map(PathBuf::from)
                    .collect::<Vec<_>>()
                    .as_slice(),
                Some(MergeConstraints {
                    threshold,
                    forbidden,
                }),
            )
            .into_iter()
            .filter_map(|p| p.to_str().map(ToOwned::to_owned))
            .collect();
        }
    }
}

pub(crate) fn resolve(
    opts: &Vec<OptionDescription>,
    actions: &[ProgramAction],
    hardening_opts: &HardeningOptions,
) -> Vec<OptionWithValue<&'static str>> {
    // Mount requirements are checked once all other actions have set the mounts
    let mut actions = actions.to_vec();
    actions.sort_by_key(|a| matches!(a, ProgramAction::RequireSameMount(..)));

    let mut resolved_opts = Vec::new();
    for opt in opts {
        // Options are in the less to most restrictive order,
        // so for non cumulative options, iterate from the end
        for opt_value_desc in opt.possible_values.iter().rev() {
            match &opt_value_desc.desc {
                OptionEffect::None => {
                    resolved_opts.push(OptionWithValue {
                        name: opt.name,
                        value: opt_value_desc.value.clone(),
                    });
                    break;
                }
                OptionEffect::Simple(effect) => {
                    match actions_compatible(effect, &actions, opt.updater, hardening_opts) {
                        ActionOptionEffectCompatibility::Compatible => {
                            resolved_opts.push(OptionWithValue {
                                name: opt.name,
                                value: opt_value_desc.value.clone(),
                            });
                            break;
                        }
                        ActionOptionEffectCompatibility::CompatibleIfChanged(opt_new_desc) => {
                            resolved_opts.extend(opt_new_desc.new_options);
                            break;
                        }
                        ActionOptionEffectCompatibility::Incompatible => {}
                    }
                }
                OptionEffect::Cumulative(effects) => match &opt_value_desc.value {
                    OptionValue::List(lv) => {
                        match actions_compatible_list(
                            opt.name,
                            lv,
                            effects,
                            &actions,
                            opt.updater,
                            hardening_opts,
                        ) {
                            ActionOptionEffectCompatibility::Compatible => {
                                resolved_opts.push(OptionWithValue {
                                    name: opt.name,
                                    value: opt_value_desc.value.clone(),
                                });
                                break;
                            }
                            ActionOptionEffectCompatibility::CompatibleIfChanged(opt_new_desc) => {
                                resolved_opts.extend(opt_new_desc.new_options);
                                break;
                            }
                            ActionOptionEffectCompatibility::Incompatible => {}
                        }
                    }
                    _ => unreachable!(),
                },
            }
        }
    }

    // Merge paths in compatible options, post option merging.
    // A path is read-only when a read-only path sits between it and its closest writable ancestor (both included),
    // so writable paths are merged first, never into the ancestors of a read-only path with a writable path below,
    // then read-only paths, never between a writable path and its closest merged writable ancestor.
    // No merge result may separate paths that need the same mount.
    // Note: this can still simplify paths to a point where that negates another option of the same mount kind, for
    // example:
    // TemporaryFileSystem=/dev:ro
    // BindReadOnlyPaths=/dev
    let threshold = hardening_opts.merge_paths_threshold;
    let split_paths: HashSet<PathBuf> = actions
        .iter()
        .filter_map(|a| match a {
            ProgramAction::RequireSameMount(path1, path2) => Some((path1, path2)),
            _ => None,
        })
        .flat_map(|(path1, path2)| {
            path1
                .ancestors()
                .chain(path2.ancestors())
                .filter(|p| path1.starts_with(p) != path2.starts_with(p))
                .map(Path::to_path_buf)
        })
        .collect();
    let ro_paths = mount_paths(&resolved_opts, PathMount::ReadOnly);
    let rw_paths = mount_paths(&resolved_opts, PathMount::Writable);
    let rw_forbidden = ro_paths
        .iter()
        .filter(|ro| rw_paths.iter().any(|rw| rw.starts_with(ro)))
        .flat_map(|ro| ro.ancestors().map(Path::to_path_buf))
        .chain(split_paths.iter().cloned())
        .collect();
    merge_mount_paths(
        &mut resolved_opts,
        PathMount::Writable,
        threshold,
        &rw_forbidden,
    );
    let merged_rw_paths = mount_paths(&resolved_opts, PathMount::Writable);
    let ro_forbidden = rw_paths
        .iter()
        .flat_map(|rw| {
            rw.ancestors()
                .take_while_inclusive(|p| !merged_rw_paths.contains(*p))
                .map(Path::to_path_buf)
        })
        .chain(split_paths.iter().cloned())
        .collect();
    merge_mount_paths(
        &mut resolved_opts,
        PathMount::ReadOnly,
        threshold,
        &ro_forbidden,
    );
    merge_mount_paths(
        &mut resolved_opts,
        PathMount::Other,
        threshold,
        &split_paths,
    );

    // Deduplicate
    resolved_opts.into_iter().unique().collect()
}

#[expect(clippy::shadow_unrelated)]
#[cfg(test)]
mod tests {
    use std::{net::IpAddr, num::NonZeroUsize, os::unix, slice};

    use super::*;
    use crate::{
        cl::HardeningOptions,
        summarize::{NetworkActivity, NetworkActivityKind, SetSpecifier},
        sysctl,
        systemd::{
            self, KernelVersion, SystemdVersion, build_options,
            options::{SocketFamily, SocketProtocol},
        },
    };

    fn test_options_standard(names: &[&str]) -> (Vec<OptionDescription>, HardeningOptions) {
        let sd_version = SystemdVersion::new(254, 0);
        let kernel_version = KernelVersion::new(6, 4, 0);
        let hardening_opts = HardeningOptions {
            systemd_options: Some(names.iter().map(|n| (*n).to_owned()).collect()),
            ..HardeningOptions::standard()
        };
        let sysctl = sysctl::State::none();
        (
            build_options(
                &sd_version,
                &kernel_version,
                &sysctl,
                &systemd::InstanceKind::System,
                false,
                &hardening_opts,
            ),
            hardening_opts,
        )
    }

    fn test_options_strict(names: &[&str]) -> (Vec<OptionDescription>, HardeningOptions) {
        let sd_version = SystemdVersion::new(254, 0);
        let kernel_version = KernelVersion::new(6, 4, 0);
        let hardening_opts = HardeningOptions {
            systemd_options: Some(names.iter().map(|n| (*n).to_owned()).collect()),
            ..HardeningOptions::strict()
        };
        let sysctl = sysctl::State::all();
        (
            build_options(
                &sd_version,
                &kernel_version,
                &sysctl,
                &systemd::InstanceKind::System,
                false,
                &hardening_opts,
            ),
            hardening_opts,
        )
    }

    #[test]
    fn resolve_protect_system() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_standard(&["ProtectSystem"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectSystem=strict");

        let actions = vec![ProgramAction::Write("/sys/whatever".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectSystem=strict");

        let actions = vec![ProgramAction::Write("/var/cache/whatever".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectSystem=full");

        let actions = vec![ProgramAction::Write("/etc/plop.conf".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectSystem=true");

        let actions = vec![ProgramAction::Write("/usr/bin/false".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);
    }

    #[test]
    fn resolve_protect_home() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_standard(&["ProtectHome"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=true");

        let actions = vec![ProgramAction::Read("/home/user/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![ProgramAction::Write("/home/user/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![ProgramAction::Create("/home/user/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![
            ProgramAction::Create("/home/user/data".into()),
            ProgramAction::Read("/home/user/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![
            ProgramAction::Create("/home/user".into()),
            ProgramAction::Create("/home/user/data".into()),
            ProgramAction::Read("/home/user/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=tmpfs");

        let actions = vec![
            ProgramAction::Create("/home/user".into()),
            ProgramAction::Create("/home/user/data".into()),
            ProgramAction::Write("/home/user/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=tmpfs");

        let actions = vec![ProgramAction::Read("/home/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![ProgramAction::Write("/home/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![ProgramAction::Create("/home/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=tmpfs");

        let actions = vec![ProgramAction::Exec("/home/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![
            ProgramAction::Create("/home/data".into()),
            ProgramAction::Read("/home/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=tmpfs");

        let actions = vec![
            ProgramAction::Create("/home/data".into()),
            ProgramAction::Write("/home/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=tmpfs");

        let actions = vec![
            ProgramAction::Create("/home/data".into()),
            ProgramAction::Exec("/home/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=tmpfs");
    }

    #[test]
    fn resolve_private_tmp() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_standard(&["PrivateTmp"]);
        let expected = [OptionWithValue {
            name: "PrivateTmp",
            value: OptionValue::Boolean(true),
        }];

        assert_eq!(resolve(&opts, &[], &hardening_opts), expected);
        let actions = [ProgramAction::Create("/tmp/data".into())];
        assert_eq!(resolve(&opts, &actions, &hardening_opts), expected);
        for path in ["/tmp", "/var/tmp"] {
            let actions = [ProgramAction::Write(path.into())];
            assert_eq!(resolve(&opts, &actions, &hardening_opts), expected);
        }

        for action in [
            ProgramAction::Read("/tmp/data".into()),
            ProgramAction::Write("/tmp/data".into()),
            ProgramAction::Exec("/tmp/data".into()),
            ProgramAction::Remove("/tmp/data".into()),
        ] {
            assert!(resolve(&opts, slice::from_ref(&action), &hardening_opts).is_empty());
            let actions = [ProgramAction::Create("/tmp/data".into()), action];
            assert_eq!(resolve(&opts, &actions, &hardening_opts), expected);
        }
    }

    #[test]
    fn resolve_private_devices_base_write() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_standard(&["PrivateDevices"]);
        let actions = [ProgramAction::Write("/dev".into())];
        assert!(resolve(&opts, &actions, &hardening_opts).is_empty());
    }

    #[test]
    fn resolve_protect_system_remove() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_standard(&["ProtectSystem"]);

        let actions = vec![ProgramAction::Remove("/var/cache/whatever".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectSystem=full");

        let actions = vec![ProgramAction::Remove("/etc/plop.conf".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectSystem=true");
    }

    #[test]
    fn resolve_read_only_paths_remove() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_strict(&["ReadOnlyPaths"]);

        let actions = vec![
            ProgramAction::Write("/var/dir/data".into()),
            ProgramAction::Remove("/var/dir/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].to_string(), "ReadOnlyPaths=-/");
        assert_eq!(candidates[1].to_string(), "ReadWritePaths=-/var/dir");
        assert_eq!(candidates[2].to_string(), "PrivateMounts=true");
    }

    #[test]
    fn resolve_inaccessible_paths_remove() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_strict(&["InaccessiblePaths"]);

        let remove = ProgramAction::Remove("/var/dir/data".into());
        for actions in [
            vec![remove.clone()],
            vec![ProgramAction::Write("/var/dir/data".into()), remove],
        ] {
            let candidates = resolve(&opts, &actions, &hardening_opts);
            assert_eq!(candidates.len(), 3);
            assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
            assert_eq!(candidates[1].to_string(), "BindPaths=-/var/dir");
            assert_eq!(candidates[2].to_string(), "PrivateMounts=true");
        }
    }

    #[test]
    fn resolve_read_only_paths_symlink_write() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_strict(&["ReadOnlyPaths"]);

        let temp_dir = tempfile::tempdir().unwrap();
        let link = temp_dir.path().join("link");
        unix::fs::symlink("/nonexistent", &link).unwrap();
        let actions = vec![ProgramAction::Write(link)];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].to_string(), "ReadOnlyPaths=-/");
        assert_eq!(
            candidates[1].to_string(),
            format!("ReadWritePaths=-{}", temp_dir.path().to_str().unwrap())
        );
        assert_eq!(candidates[2].to_string(), "PrivateMounts=true");
    }

    #[test]
    fn resolve_link_same_mount() {
        let _ = simple_logger::SimpleLogger::new().init();

        let link = |old: &str, new: &str| {
            let new = PathBuf::from(new);
            [
                ProgramAction::Read(old.into()),
                ProgramAction::Create(new.clone()),
                ProgramAction::RequireSameMount(old.into(), new.parent().unwrap().to_owned()),
            ]
        };
        let rename_created = [
            ProgramAction::Create("/var/tmp/f".into()),
            ProgramAction::Read("/var/tmp/f".into()),
            ProgramAction::Write("/var/tmp/f".into()),
            ProgramAction::Create("/var/lib/f".into()),
            ProgramAction::Write("/var/lib/f".into()),
            ProgramAction::RequireSameMount("/var/tmp".into(), "/var/lib".into()),
        ];
        let mut link_executed = link("/tmp/tree/bin/tool", "/tmp/tree/old/tool").to_vec();
        link_executed.push(ProgramAction::Exec("/tmp/tree/bin/tool".into()));
        // The exception widened for the executed file's link splits the other link if checked first
        let link_out = link("/tmp/tree/data/f", "/tmp/out/f");
        let link_out_first = [&link_out[..], &link_executed].concat();
        let link_out_last = [&link_executed[..], &link_out].concat();
        for (standard, names, actions, expected) in [
            (
                true,
                &["ProtectSystem"][..],
                &link("/etc/f", "/var/lib/f")[..],
                &["ProtectSystem=true"][..],
            ),
            (true, &["PrivateTmp"], &rename_created, &[]),
            (
                false,
                &["ReadOnlyPaths"],
                &link("/tmp/tree/source/f", "/tmp/tree/destination/f"),
                &[
                    "ReadOnlyPaths=-/",
                    "ReadWritePaths=-/tmp/tree",
                    "PrivateMounts=true",
                ],
            ),
            (
                false,
                &["ReadOnlyPaths"],
                &link("/etc/f", "/var/lib/f"),
                &[],
            ),
            (
                false,
                &["InaccessiblePaths"],
                &link("/tmp/tree/source/f", "/tmp/tree/destination/f"),
                &[
                    "TemporaryFileSystem=/:ro",
                    "BindPaths=-/tmp/tree",
                    "PrivateMounts=true",
                ],
            ),
            (
                false,
                &["NoExecPaths"],
                &link_executed,
                &[
                    "NoExecPaths=-/",
                    "ExecPaths=-/tmp/tree",
                    "PrivateMounts=true",
                ],
            ),
            (
                false,
                &["NoExecPaths"],
                &link_out_first,
                &["NoExecPaths=-/", "ExecPaths=-/tmp", "PrivateMounts=true"],
            ),
            (
                false,
                &["NoExecPaths"],
                &link_out_last,
                &["NoExecPaths=-/", "ExecPaths=-/tmp", "PrivateMounts=true"],
            ),
        ] {
            let (opts, hardening_opts) = if standard {
                test_options_standard(names)
            } else {
                test_options_strict(names)
            };
            assert_eq!(
                resolve(&opts, actions, &hardening_opts)
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    #[expect(clippy::cognitive_complexity)]
    fn resolve_inaccessible_paths() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_strict(&["InaccessiblePaths"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "InaccessiblePaths=-/");

        let actions = vec![ProgramAction::Read("/".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].to_string().starts_with("InaccessiblePaths="));
        let OptionValue::List(opt_list) = &candidates[0].value else {
            panic!();
        };
        assert!(opt_list.values.contains(&"/boot".to_owned()));
        assert!(opt_list.values.contains(&"/dev".to_owned()));
        assert!(opt_list.values.contains(&"/etc".to_owned()));
        assert!(opt_list.values.contains(&"/home".to_owned()));
        assert!(opt_list.values.contains(&"/root".to_owned()));
        assert!(opt_list.values.contains(&"/sys".to_owned()));
        assert!(opt_list.values.contains(&"/tmp".to_owned()));
        assert!(opt_list.values.contains(&"/usr".to_owned()));
        assert!(opt_list.values.contains(&"/var".to_owned()));
        assert!(!opt_list.values.contains(&"/proc".to_owned()));
        assert!(!opt_list.values.contains(&"/run".to_owned()));

        let actions = vec![ProgramAction::Read("/var/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
        assert_eq!(candidates[1].to_string(), "BindReadOnlyPaths=-/var/data");
        assert_eq!(candidates[2].to_string(), "PrivateMounts=true");

        let actions = vec![
            ProgramAction::Exec("/usr/bin/prog".into()),
            ProgramAction::Read("/var/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
        assert_eq!(
            candidates[1].to_string(),
            "BindReadOnlyPaths=-/usr/bin/prog -/var/data"
        );
        assert_eq!(candidates[2].to_string(), "PrivateMounts=true");

        let actions = vec![
            ProgramAction::Exec("/usr/bin/prog".into()),
            ProgramAction::Write("/var/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
        assert_eq!(
            candidates[1].to_string(),
            "BindReadOnlyPaths=-/usr/bin/prog"
        );
        assert_eq!(candidates[2].to_string(), "BindPaths=-/var/data");
        assert_eq!(candidates[3].to_string(), "PrivateMounts=true");

        let actions = vec![
            ProgramAction::Exec("/usr/bin/prog".into()),
            ProgramAction::Create("/var/data".into()),
            ProgramAction::Write("/var/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
        assert_eq!(
            candidates[1].to_string(),
            "BindReadOnlyPaths=-/usr/bin/prog"
        );
        assert_eq!(candidates[2].to_string(), "BindPaths=-/var");
        assert_eq!(candidates[3].to_string(), "PrivateMounts=true");

        let actions = vec![
            ProgramAction::Exec("/usr/bin/prog".into()),
            ProgramAction::Create("/var/dir/data".into()),
            ProgramAction::Write("/var/dir/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
        assert_eq!(
            candidates[1].to_string(),
            "BindReadOnlyPaths=-/usr/bin/prog"
        );
        assert_eq!(candidates[2].to_string(), "BindPaths=-/var/dir");
        assert_eq!(candidates[3].to_string(), "PrivateMounts=true");

        let actions = vec![
            ProgramAction::Exec("/usr/bin/prog".into()),
            ProgramAction::Read("/var/data".into()),
            ProgramAction::Write("/var/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
        assert_eq!(
            candidates[1].to_string(),
            "BindReadOnlyPaths=-/usr/bin/prog"
        );
        assert_eq!(candidates[2].to_string(), "BindPaths=-/var/data");
        assert_eq!(candidates[3].to_string(), "PrivateMounts=true");
    }

    /// Resolve the named options with a merge threshold of 2, and return them except the host dependent
    /// `InaccessiblePaths`
    fn resolve_merged_paths(names: &[&str], actions: &[ProgramAction]) -> Vec<String> {
        let (opts, hardening_opts) = test_options_strict(names);
        let hardening_opts = HardeningOptions {
            merge_paths_threshold: NonZeroUsize::new(2).unwrap(),
            ..hardening_opts
        };
        resolve(&opts, actions, &hardening_opts)
            .iter()
            .filter(|o| o.name != "InaccessiblePaths")
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn resolve_merge_paths_ro_exception_writable_base() {
        let _ = simple_logger::SimpleLogger::new().init();

        let actions = [
            ProgramAction::Read("/".into()),
            ProgramAction::Read("/etc/a".into()),
            ProgramAction::Read("/etc/b".into()),
            ProgramAction::Read("/usr/c".into()),
            ProgramAction::Read("/tmp/src".into()),
            ProgramAction::Create("/tmp/dst".into()),
        ];
        assert_eq!(
            resolve_merged_paths(&["ReadOnlyPaths", "InaccessiblePaths"], &actions),
            [
                "ReadOnlyPaths=-/",
                "ReadWritePaths=-/tmp",
                "PrivateMounts=true",
                "TemporaryFileSystem=/etc:ro /usr:ro",
                "BindReadOnlyPaths=-/etc -/tmp/src -/usr",
                "TemporaryFileSystem=/tmp",
            ]
        );
    }

    #[test]
    fn resolve_merge_paths_rw_exceptions_ro_base() {
        let _ = simple_logger::SimpleLogger::new().init();

        let actions = [
            ProgramAction::Read("/".into()),
            ProgramAction::Create("/tmp/a/1/f".into()),
            ProgramAction::Create("/tmp/a/2/f".into()),
            ProgramAction::Create("/tmp/a/3/f".into()),
            ProgramAction::Create("/tmp/b/1/f".into()),
            ProgramAction::Create("/tmp/c/1/f".into()),
        ];
        assert_eq!(
            resolve_merged_paths(&["ReadOnlyPaths", "InaccessiblePaths"], &actions),
            [
                "ReadOnlyPaths=-/",
                "ReadWritePaths=-/tmp/a -/tmp/b -/tmp/c",
                "PrivateMounts=true",
                "TemporaryFileSystem=/tmp:ro",
                "BindPaths=-/tmp/a -/tmp/b -/tmp/c",
            ]
        );
    }

    #[test]
    fn resolve_merge_paths_rw_exceptions_ro_exception() {
        let _ = simple_logger::SimpleLogger::new().init();

        let actions = [
            ProgramAction::Read("/".into()),
            ProgramAction::Read("/tmp/d".into()),
            ProgramAction::Create("/tmp/d/1/f".into()),
            ProgramAction::Create("/tmp/d/2/f".into()),
            ProgramAction::Create("/tmp/d/3/f".into()),
        ];
        assert_eq!(
            resolve_merged_paths(&["ReadOnlyPaths", "InaccessiblePaths"], &actions),
            [
                "ReadOnlyPaths=-/",
                "ReadWritePaths=-/tmp/d/1 -/tmp/d/2 -/tmp/d/3",
                "PrivateMounts=true",
                "TemporaryFileSystem=/tmp:ro",
                "BindReadOnlyPaths=-/tmp/d",
                "BindPaths=-/tmp/d/1 -/tmp/d/2 -/tmp/d/3",
            ]
        );
    }

    #[test]
    fn resolve_merge_paths_rw_exceptions_ro_exception_ancestor() {
        let _ = simple_logger::SimpleLogger::new().init();

        let actions = [
            ProgramAction::Read("/".into()),
            ProgramAction::Read("/tmp/d".into()),
            ProgramAction::Create("/tmp/f".into()),
            ProgramAction::Create("/tmp/d/1/f".into()),
            ProgramAction::Create("/tmp/e/1/f".into()),
            ProgramAction::Create("/tmp/e/2/f".into()),
            ProgramAction::Create("/tmp/g/1/f".into()),
        ];
        assert_eq!(
            resolve_merged_paths(&["ReadOnlyPaths", "InaccessiblePaths"], &actions),
            [
                "ReadOnlyPaths=-/",
                "ReadWritePaths=-/tmp",
                "PrivateMounts=true",
                "TemporaryFileSystem=/tmp",
                "BindReadOnlyPaths=-/tmp/d",
                "BindPaths=-/tmp/d/1 -/tmp/e -/tmp/g",
            ]
        );
    }

    #[test]
    fn resolve_merge_paths_ro_exceptions_under_merged_rw_exceptions() {
        let _ = simple_logger::SimpleLogger::new().init();

        let actions = [
            ProgramAction::Read("/".into()),
            ProgramAction::Read("/tmp/d/x".into()),
            ProgramAction::Create("/tmp/f".into()),
            ProgramAction::Read("/tmp/d/y".into()),
            ProgramAction::Read("/tmp/d/z".into()),
            ProgramAction::Create("/tmp/d/1/f".into()),
            ProgramAction::Create("/tmp/e/1/f".into()),
            ProgramAction::Create("/tmp/e/2/f".into()),
            ProgramAction::Create("/tmp/g/1/f".into()),
        ];
        assert_eq!(
            resolve_merged_paths(&["ReadOnlyPaths", "InaccessiblePaths"], &actions),
            [
                "ReadOnlyPaths=-/",
                "ReadWritePaths=-/tmp",
                "PrivateMounts=true",
                "TemporaryFileSystem=/tmp",
                "BindReadOnlyPaths=-/tmp/d/x -/tmp/d/y -/tmp/d/z",
                "BindPaths=-/tmp",
            ]
        );
    }

    #[test]
    fn resolve_merge_paths_ro_exceptions_above_merged_rw_exceptions() {
        let _ = simple_logger::SimpleLogger::new().init();

        let actions = [
            ProgramAction::Read("/".into()),
            ProgramAction::Read("/tmp/s/a".into()),
            ProgramAction::Read("/tmp/s/b".into()),
            ProgramAction::Read("/tmp/s/c".into()),
            ProgramAction::Create("/tmp/s/d/1/f".into()),
            ProgramAction::Create("/tmp/s/d/2/f".into()),
            ProgramAction::Create("/tmp/s/d/3/f".into()),
        ];
        assert_eq!(
            resolve_merged_paths(&["ReadOnlyPaths", "InaccessiblePaths"], &actions),
            [
                "ReadOnlyPaths=-/",
                "ReadWritePaths=-/tmp/s/d",
                "PrivateMounts=true",
                "TemporaryFileSystem=/tmp:ro",
                "BindReadOnlyPaths=-/tmp/s",
                "BindPaths=-/tmp/s/d",
            ]
        );
    }

    #[test]
    fn resolve_merge_paths_exec_exceptions() {
        let _ = simple_logger::SimpleLogger::new().init();

        let actions = [
            ProgramAction::Exec("/usr/x/a".into()),
            ProgramAction::Exec("/usr/x/b".into()),
            ProgramAction::Exec("/usr/x/c".into()),
            ProgramAction::Create("/usr/x/new".into()),
        ];
        assert_eq!(
            resolve_merged_paths(&["ReadOnlyPaths", "NoExecPaths"], &actions),
            [
                "ReadOnlyPaths=-/",
                "ReadWritePaths=-/usr/x",
                "PrivateMounts=true",
                "NoExecPaths=-/",
                "ExecPaths=-/usr/x",
            ]
        );
    }

    #[test]
    fn resolve_merge_paths_same_mount() {
        let _ = simple_logger::SimpleLogger::new().init();

        let actions = [
            ProgramAction::Exec("/tmp/tree/source/a".into()),
            ProgramAction::Exec("/tmp/tree/source/b".into()),
            ProgramAction::Exec("/tmp/tree/source/c".into()),
            ProgramAction::Read("/tmp/tree/source/f".into()),
            ProgramAction::Create("/tmp/tree/destination/f".into()),
            ProgramAction::RequireSameMount(
                "/tmp/tree/source/f".into(),
                "/tmp/tree/destination".into(),
            ),
        ];
        assert_eq!(
            resolve_merged_paths(&["ReadOnlyPaths", "NoExecPaths"], &actions),
            [
                "ReadOnlyPaths=-/",
                "ReadWritePaths=-/tmp/tree",
                "PrivateMounts=true",
                "NoExecPaths=-/",
                "ExecPaths=-/tmp/tree",
            ]
        );
    }

    #[test]
    fn resolve_merge_bind_paths_same_mount() {
        let _ = simple_logger::SimpleLogger::new().init();

        for (access, expected) in [
            (
                ProgramAction::Read as fn(PathBuf) -> ProgramAction,
                "BindReadOnlyPaths=-/tree/source/a -/tree/source/b -/tree/source/c",
            ),
            (
                ProgramAction::Write,
                "BindPaths=-/tree/source/a -/tree/source/b -/tree/source/c",
            ),
        ] {
            let mut actions: Vec<_> = ["a", "b", "c"]
                .iter()
                .map(|n| access(Path::new("/tree/source").join(n)))
                .collect();
            actions.extend(
                ["/tree", "/tree/source", "/out", "/tree/source/f", "/out/f"]
                    .map(|p| ProgramAction::Create(p.into())),
            );
            actions.push(ProgramAction::RequireSameMount(
                "/tree/source/f".into(),
                "/out".into(),
            ));
            assert_eq!(
                resolve_merged_paths(&["InaccessiblePaths"], &actions),
                ["TemporaryFileSystem=/", expected, "PrivateMounts=true"]
            );
        }
    }

    #[test]
    fn resolve_link_same_mount_ro_exception() {
        let _ = simple_logger::SimpleLogger::new().init();

        let actions = [
            ProgramAction::Read("/".into()),
            ProgramAction::Read("/tmp/source".into()),
            ProgramAction::Create("/tmp/link".into()),
            ProgramAction::RequireSameMount("/tmp/source".into(), "/tmp".into()),
        ];
        assert!(resolve_merged_paths(&["InaccessiblePaths"], &actions).is_empty());
    }

    #[test]
    fn resolve_inaccessible_paths_existing_entry_created() {
        let _ = simple_logger::SimpleLogger::new().init();

        // An entry read before its creation exists, and is mounted when it still does
        let actions = [
            ProgramAction::Read("/".into()),
            ProgramAction::Read("/tmp/data".into()),
            ProgramAction::Create("/tmp/data".into()),
            ProgramAction::Write("/tmp/data".into()),
        ];
        assert_eq!(
            resolve_merged_paths(&["InaccessiblePaths"], &actions),
            [
                "TemporaryFileSystem=/tmp",
                "BindPaths=-/tmp/data",
                "PrivateMounts=true"
            ]
        );

        let actions = [
            ProgramAction::Read("/".into()),
            ProgramAction::Read("/tmp/lock".into()),
            ProgramAction::Create("/tmp/lock".into()),
            ProgramAction::Write("/tmp/lock".into()),
            ProgramAction::Remove("/tmp/lock".into()),
            ProgramAction::Create("/tmp/lock".into()),
            ProgramAction::Write("/tmp/lock".into()),
        ];
        assert!(resolve_merged_paths(&["InaccessiblePaths"], &actions).is_empty());

        let actions = [
            ProgramAction::Read("/".into()),
            ProgramAction::Read("/tmp/dir".into()),
            ProgramAction::Create("/tmp/dir".into()),
            ProgramAction::Create("/tmp/dir/file".into()),
            ProgramAction::Write("/tmp/dir/file".into()),
        ];
        assert_eq!(
            resolve_merged_paths(&["InaccessiblePaths"], &actions),
            [
                "TemporaryFileSystem=/tmp",
                "BindPaths=-/tmp/dir",
                "PrivateMounts=true"
            ]
        );
    }

    #[test]
    fn resolve_ip_address_deny_bind_ipv6_unspecified() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_strict(&["IPAddressDeny"]);

        let actions = vec![ProgramAction::NetworkActivity(
            NetworkActivity {
                af: SetSpecifier::One(SocketFamily::Ipv6),
                proto: SetSpecifier::One(SocketProtocol::Tcp),
                kind: SetSpecifier::One(NetworkActivityKind::Bind),
                local_port: SetSpecifier::All,
                address: SetSpecifier::One("::".parse::<IpAddr>().unwrap().into()),
            }
            .into(),
        )];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert!(candidates.is_empty());
    }

    #[test]
    fn resolve_ip_address_deny_bind_ipv4_unspecified() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_strict(&["IPAddressDeny"]);

        let actions = vec![ProgramAction::NetworkActivity(
            NetworkActivity {
                af: SetSpecifier::One(SocketFamily::Ipv4),
                proto: SetSpecifier::One(SocketProtocol::Tcp),
                kind: SetSpecifier::One(NetworkActivityKind::Bind),
                local_port: SetSpecifier::All,
                address: SetSpecifier::One("0.0.0.0".parse::<IpAddr>().unwrap().into()),
            }
            .into(),
        )];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert!(candidates.is_empty());
    }

    #[test]
    fn resolve_protect_kernel_tunables_mtrr() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_standard(&["ProtectKernelTunables"]);

        let actions = vec![ProgramAction::Write("/proc/mtrr".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert!(candidates.is_empty());
    }

    #[test]
    fn resolve_capability_bounding_set_ptrace() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_standard(&["CapabilityBoundingSet"]);

        let actions = vec![ProgramAction::Syscalls(["ptrace".into()].into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert!(!candidates[0].to_string().contains("CAP_SYS_PTRACE"));
    }

    #[test]
    fn resolve_capability_bounding_set_wake_lock() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_standard(&["CapabilityBoundingSet"]);

        for path in ["/sys/power/wake_lock", "/sys/power/wake_unlock"] {
            let actions = vec![ProgramAction::Write(path.into())];
            let candidates = resolve(&opts, &actions, &hardening_opts);
            assert_eq!(candidates.len(), 1);
            assert!(!candidates[0].to_string().contains("CAP_BLOCK_SUSPEND"));
        }
    }

    #[test]
    fn resolve_restrict_address_families_nfc_mctp() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_standard(&["RestrictAddressFamilies"]);

        for (af, proto) in [("AF_MCTP", "SOCK_DGRAM"), ("AF_NFC", "SOCK_SEQPACKET")] {
            let actions = vec![ProgramAction::NetworkActivity(
                NetworkActivity {
                    af: SetSpecifier::One(SocketFamily::Other(af.into())),
                    proto: SetSpecifier::One(proto.parse().unwrap()),
                    kind: SetSpecifier::One(NetworkActivityKind::SocketCreation),
                    local_port: SetSpecifier::All,
                    address: SetSpecifier::All,
                }
                .into(),
            )];
            let candidates = resolve(&opts, &actions, &hardening_opts);
            assert_eq!(candidates.len(), 1);
            assert_eq!(
                candidates[0].to_string(),
                format!("RestrictAddressFamilies={af}")
            );
        }
    }

    #[test]
    fn resolve_capability_bounding_set_raw_unlisted_family() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_standard(&["CapabilityBoundingSet"]);

        let actions = vec![ProgramAction::NetworkActivity(
            NetworkActivity {
                af: SetSpecifier::One(SocketFamily::Other("AF_UNLISTED".into())),
                proto: SetSpecifier::One(SocketProtocol::Other("SOCK_RAW".into())),
                kind: SetSpecifier::One(NetworkActivityKind::SocketCreation),
                local_port: SetSpecifier::All,
                address: SetSpecifier::All,
            }
            .into(),
        )];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert!(!candidates[0].to_string().contains("CAP_NET_RAW"));
    }
}
