//! Summarize program syscalls into higher level action

use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display},
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU16,
    os::fd::RawFd,
    path::PathBuf,
    sync::LazyLock,
};

use anyhow::Context as _;
use nix::libc::pid_t;

use crate::{
    strace::{SyscallItem, SyscallName},
    systemd::{SocketFamily, SocketProtocol},
};

mod handlers;

use handlers::{
    ChdirHandler, Clone3Handler, EpollCtlHandler, ExecHandler, FollowSymlink, ForkHandler,
    KillHandler, MemfdCreateHandler, MknodHandler, MmapHandler, MountHandler, NetworkHandler,
    OpenHandler, PathHandler, RenameHandler, SetSchedulerHandler, SetsockoptHandler, ShmCtlHandler,
    SocketHandler, StatFdHandler, SyscallHandler, TimerCreateHandler, UnshareHandler,
};

/// A high level program runtime action
/// This does *not* map 1-1 with a syscall, and does *not* necessarily respect chronology
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum ProgramAction {
    /// Path was created
    Create(PathBuf),
    /// Path was exec'd
    Exec(PathBuf),
    /// Memory mapping with huge pages
    HugePageMemoryMapping,
    /// Send signal to other process ("other" being defined as requiring `CAP_KILL`)
    KillOther,
    /// Lock memory mapping
    LockMemoryMapping,
    /// Create special files
    MknodSpecial,
    /// Mount propagated to host
    MountToHost,
    /// Network (socket) activity
    NetworkActivity(Box<NetworkActivity>),
    /// Path was accessed (open, stat'ed, read...)
    Read(PathBuf),
    /// Path was removed
    Remove(PathBuf),
    /// Set privileged timer alarm
    SetAlarm,
    /// Set scheduler to a real time one
    SetRealtimeScheduler,
    /// Names of the syscalls made by the program
    Syscalls(HashSet<SyscallName>),
    /// Inhibit suspend
    Wakeup,
    /// Path was written to (data, metadata...)
    Write(PathBuf),
    /// Memory mapping with write and execute bits, or execute bit added
    /// after initial mapping
    WriteExecuteMemoryMapping,
}

/// Network (socket) activity
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkActivity {
    pub af: SetSpecifier<SocketFamily>,
    pub proto: SetSpecifier<SocketProtocol>,
    pub kind: SetSpecifier<NetworkActivityKind>,
    pub local_port: SetSpecifier<NetworkPort>,
    // Note: this account for source and destination addresses
    pub address: SetSpecifier<NetworkAddress>,
}

/// Quantify something that is done or denied
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum SetSpecifier<T> {
    None,
    One(T),
    Some(Vec<T>),
    AllExcept(Vec<T>),
    All,
}

impl<T: Eq + Clone> SetSpecifier<T> {
    fn contains_one(&self, needle: &T) -> bool {
        match self {
            Self::None => false,
            Self::One(e) => e == needle,
            Self::Some(es) => es.contains(needle),
            Self::AllExcept(es) => !es.contains(needle),
            Self::All => true,
        }
    }

    pub(crate) fn intersects(&self, other: &Self) -> bool {
        match self {
            Self::None => false,
            Self::One(e) => other.contains_one(e),
            Self::Some(es) => es.iter().any(|e| other.contains_one(e)),
            Self::AllExcept(excs) => match other {
                Self::None => false,
                Self::One(e) => !excs.contains(e),
                Self::Some(es) => es.iter().any(|e| !excs.contains(e)),
                Self::AllExcept(other_excs) => excs != other_excs,
                Self::All => true, // this is incorrect, but unless excs has the whole address/port space, we should be good
            },
            Self::All => !matches!(other, Self::None),
        }
    }

    pub(crate) fn excluded_elements(&self) -> Vec<T> {
        match self {
            Self::AllExcept(vec) => vec.to_owned(),
            _ => unimplemented!(),
        }
    }

    /// Remove a single element from the set
    /// The element to remove **must** be in the set, otherwise may panic
    #[expect(clippy::unwrap_used, clippy::panic)]
    pub(crate) fn remove(&mut self, to_rm: &T) {
        debug_assert!(self.contains_one(to_rm));
        match self {
            Self::None => panic!(),
            Self::One(_) => {
                *self = Self::None;
            }
            Self::Some(es) => {
                let idx = es.iter().position(|e| e == to_rm).unwrap();
                es.remove(idx);
            }
            Self::AllExcept(excs) => {
                debug_assert!(!excs.contains(to_rm));
                excs.push(to_rm.to_owned());
            }
            Self::All => {
                *self = Self::AllExcept(vec![to_rm.to_owned()]);
            }
        }
    }
}

/// Socket activity
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum NetworkActivityKind {
    SocketCreation,
    Bind,
    Connect,
    Accept,
    SendRecv,
}

impl NetworkActivityKind {
    /// All kinds that are linked with one or more addresses
    pub(crate) const ADDRESSED: [Self; 4] = [
        NetworkActivityKind::Bind,
        NetworkActivityKind::Connect,
        NetworkActivityKind::Accept,
        NetworkActivityKind::SendRecv,
    ];

    /// Get kind from syscall name, panic if it fails
    fn from_sc_name(sc: &str) -> Self {
        match sc {
            "socket" => NetworkActivityKind::SocketCreation,
            "bind" => NetworkActivityKind::Bind,
            "connect" => NetworkActivityKind::Connect,
            "accept" | "accept4" => NetworkActivityKind::Accept,
            "sendto" | "recvfrom" => NetworkActivityKind::SendRecv,
            _ => unreachable!("{:?}", sc),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkPort(NonZeroU16);

impl Display for NetworkPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkAddress(IpAddr);

impl NetworkAddress {
    /// Check if this address is the unspecified address (`::` or `0.0.0.0`).
    pub(crate) fn is_unspecified(&self) -> bool {
        self.0.is_unspecified()
    }

    /// Return the IPv4 equivalent of this address on a dual-stack socket, if any.
    /// `::` -> `0.0.0.0`, `::ffff:A.B.C.D` -> `A.B.C.D`, everything else -> None.
    pub(crate) fn ipv4_equivalent(&self) -> Option<Self> {
        match self.0 {
            IpAddr::V6(v6) if v6.is_unspecified() => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED).into()),
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v4| IpAddr::V4(v4).into()),
            IpAddr::V4(_) => None,
        }
    }
}

impl From<IpAddr> for NetworkAddress {
    fn from(value: IpAddr) -> Self {
        Self(value)
    }
}

impl Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Address family info for a socket
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(crate) enum SocketAfInfo {
    Ipv4,
    Ipv6 { v6only: Option<bool> },
    Other(String),
}

impl SocketAfInfo {
    pub(crate) fn is_dual_stack(&self, bindv6only_default: bool) -> bool {
        matches!(self, Self::Ipv6 { v6only } if !v6only.unwrap_or(bindv6only_default))
    }

    pub(crate) fn family(&self) -> SocketFamily {
        match self {
            Self::Ipv4 => SocketFamily::Ipv4,
            Self::Ipv6 { .. } => SocketFamily::Ipv6,
            Self::Other(s) => SocketFamily::Other(s.clone()),
        }
    }
}

impl From<SocketFamily> for SocketAfInfo {
    fn from(af: SocketFamily) -> Self {
        match af {
            SocketFamily::Ipv4 => Self::Ipv4,
            SocketFamily::Ipv6 => Self::Ipv6 { v6only: None },
            SocketFamily::Other(s) => Self::Other(s),
        }
    }
}

/// Combined socket info: protocol and address family details
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(crate) struct SocketInfo {
    pub proto: SocketProtocol,
    pub af: SocketAfInfo,
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
enum FdOrPath<T> {
    Fd(T),
    Path(T),
}

//
// For some reference on syscalls, see:
// - https://man7.org/linux/man-pages/man2/syscalls.2.html
// - https://filippo.io/linux-syscall-table/
// - https://linasm.sourceforge.net/docs/syscalls/filesystem.php
//
static SYSCALL_MAP: LazyLock<HashMap<&'static str, Box<dyn SyscallHandler>>> =
    LazyLock::new(|| {
        let mut m: HashMap<&'static str, Box<dyn SyscallHandler>> = HashMap::new();
        m.insert("accept", Box::new(NetworkHandler { fd: 0, sockaddr: 1 }));
        m.insert("accept4", Box::new(NetworkHandler { fd: 0, sockaddr: 1 }));
        m.insert("bind", Box::new(NetworkHandler { fd: 0, sockaddr: 1 }));
        m.insert(
            "chdir",
            Box::new(ChdirHandler {
                path: FdOrPath::Path(0),
            }),
        );
        m.insert(
            "chmod",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Always,
                action: ProgramAction::Write,
            }),
        );
        m.insert(
            "chown",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Always,
                action: ProgramAction::Write,
            }),
        );
        // Note: strace decodes clone's arguments as a struct, like clone3
        m.insert("clone", Box::new(Clone3Handler { args: 0 }));
        m.insert("clone3", Box::new(Clone3Handler { args: 0 }));
        m.insert("connect", Box::new(NetworkHandler { fd: 0, sockaddr: 1 }));
        m.insert("epoll_ctl", Box::new(EpollCtlHandler { op: 1, event: 3 }));
        m.insert(
            "execve",
            Box::new(ExecHandler {
                relfd: None,
                path: 0,
            }),
        );
        m.insert(
            "execveat",
            Box::new(ExecHandler {
                relfd: Some(0),
                path: 1,
            }),
        );
        m.insert(
            "fchdir",
            Box::new(ChdirHandler {
                path: FdOrPath::Fd(0),
            }),
        );
        m.insert(
            "fchmodat",
            Box::new(PathHandler {
                relfd: Some(0),
                path: 1,
                follow: FollowSymlink::Always,
                action: ProgramAction::Write,
            }),
        );
        m.insert(
            "fchmodat2",
            Box::new(PathHandler {
                relfd: Some(0),
                path: 1,
                follow: FollowSymlink::UnlessNoFollowFlag(3),
                action: ProgramAction::Write,
            }),
        );
        m.insert(
            "fchownat",
            Box::new(PathHandler {
                relfd: Some(0),
                path: 1,
                follow: FollowSymlink::UnlessNoFollowFlag(4),
                action: ProgramAction::Write,
            }),
        );
        m.insert("fork", Box::new(ForkHandler));
        m.insert("fstat", Box::new(StatFdHandler { fd: 0 }));
        m.insert(
            "futimesat",
            Box::new(PathHandler {
                relfd: Some(0),
                path: 1,
                follow: FollowSymlink::Always,
                action: ProgramAction::Write,
            }),
        );
        m.insert("getdents", Box::new(StatFdHandler { fd: 0 }));
        m.insert("kill", Box::new(KillHandler { pid: 0, sig: 1 }));
        m.insert(
            "lchown",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Never,
                action: ProgramAction::Write,
            }),
        );
        m.insert(
            "lremovexattr",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Never,
                action: ProgramAction::Write,
            }),
        );
        m.insert(
            "lsetxattr",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Never,
                action: ProgramAction::Write,
            }),
        );
        m.insert(
            "lstat",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Always,
                action: ProgramAction::Read,
            }),
        );
        m.insert("memfd_create", Box::new(MemfdCreateHandler { flags: 1 }));
        m.insert(
            "mkdir",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Always,
                action: ProgramAction::Create,
            }),
        );
        m.insert(
            "mkdirat",
            Box::new(PathHandler {
                relfd: Some(0),
                path: 1,
                follow: FollowSymlink::Always,
                action: ProgramAction::Create,
            }),
        );
        m.insert(
            "mknod",
            Box::new(MknodHandler {
                path: FdOrPath::Path(0),
                mode: 1,
            }),
        );
        m.insert(
            "mknodat",
            Box::new(MknodHandler {
                path: FdOrPath::Fd(1),
                mode: 2,
            }),
        );
        m.insert(
            "mmap",
            Box::new(MmapHandler {
                prot: 2,
                flags: Some(3),
                fd: Some(4),
            }),
        );
        m.insert(
            "mmap2",
            Box::new(MmapHandler {
                prot: 2,
                flags: Some(3),
                fd: Some(4),
            }),
        );
        m.insert("mount", Box::new(MountHandler { flags: 3 }));
        m.insert(
            "mprotect",
            Box::new(MmapHandler {
                prot: 2,
                flags: None,
                fd: None,
            }),
        );
        m.insert(
            "newfstatat",
            Box::new(PathHandler {
                relfd: Some(0),
                path: 1,
                follow: FollowSymlink::Always,
                action: ProgramAction::Read,
            }),
        );
        m.insert(
            "open",
            Box::new(OpenHandler {
                relfd: None,
                path: 0,
                flags: 1,
            }),
        );
        m.insert(
            "openat",
            Box::new(OpenHandler {
                relfd: Some(0),
                path: 1,
                flags: 2,
            }),
        );
        m.insert(
            "pkey_mprotect",
            Box::new(MmapHandler {
                prot: 2,
                flags: None,
                fd: None,
            }),
        );
        m.insert("recvfrom", Box::new(NetworkHandler { fd: 0, sockaddr: 4 }));
        m.insert(
            "removexattr",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Always,
                action: ProgramAction::Write,
            }),
        );
        m.insert(
            "rename",
            Box::new(RenameHandler {
                relfd_src: None,
                path_src: 0,
                relfd_dst: None,
                path_dst: 1,
                flags: None,
            }),
        );
        m.insert(
            "renameat",
            Box::new(RenameHandler {
                relfd_src: Some(0),
                path_src: 1,
                relfd_dst: Some(2),
                path_dst: 3,
                flags: None,
            }),
        );
        m.insert(
            "renameat2",
            Box::new(RenameHandler {
                relfd_src: Some(0),
                path_src: 1,
                relfd_dst: Some(2),
                path_dst: 3,
                flags: Some(4),
            }),
        );
        m.insert(
            "rmdir",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Never,
                action: ProgramAction::Remove,
            }),
        );
        m.insert(
            "sched_setscheduler",
            Box::new(SetSchedulerHandler { policy: 1 }),
        );
        m.insert("sendto", Box::new(NetworkHandler { fd: 0, sockaddr: 4 }));
        m.insert(
            "setsockopt",
            Box::new(SetsockoptHandler {
                fd: 0,
                level: 1,
                optname: 2,
                optval: 3,
            }),
        );
        m.insert(
            "setxattr",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Always,
                action: ProgramAction::Write,
            }),
        );
        m.insert("shmctl", Box::new(ShmCtlHandler { op: 1 }));
        m.insert("socket", Box::new(SocketHandler { af: 0, flags: 1 }));
        m.insert(
            "stat",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Always,
                action: ProgramAction::Read,
            }),
        );
        m.insert("timer_create", Box::new(TimerCreateHandler { clockid: 0 }));
        m.insert(
            "truncate",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Always,
                action: ProgramAction::Write,
            }),
        );
        m.insert(
            "unlink",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Never,
                action: ProgramAction::Remove,
            }),
        );
        m.insert(
            "unlinkat",
            Box::new(PathHandler {
                relfd: Some(0),
                path: 1,
                follow: FollowSymlink::Never,
                action: ProgramAction::Remove,
            }),
        );
        m.insert("unshare", Box::new(UnshareHandler { flags: 0 }));
        m.insert(
            "utime",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Always,
                action: ProgramAction::Write,
            }),
        );
        m.insert(
            "utimensat",
            Box::new(PathHandler {
                relfd: Some(0),
                path: 1,
                follow: FollowSymlink::UnlessNoFollowFlag(3),
                action: ProgramAction::Write,
            }),
        );
        m.insert(
            "utimes",
            Box::new(PathHandler {
                relfd: None,
                path: 0,
                follow: FollowSymlink::Always,
                action: ProgramAction::Write,
            }),
        );
        m.insert("vfork", Box::new(ForkHandler));
        m
    });

/// Synthetic fd-table identifier, used to group pids that share an fd table
type FdTableId = usize;

/// Track process fd-table topology and socket info across threads.
///
/// Implicit fd closures (`FD_CLOEXEC` / `O_CLOEXEC` / `SOCK_CLOEXEC`) are intentionally
/// not modeled: we only need the protocol at the time of a `bind`/`connect`/etc. call,
/// and when a new socket reuses the same fd number, `add_sock_info` overwrites the old entry.
#[derive(Debug, Default)]
pub(crate) struct ProcessFdTracker {
    /// Socket info keyed by (fd-table id, fd).
    /// We don't track socket closings because the fd will be reused or never bound again.
    sock_info: HashMap<(FdTableId, RawFd), SocketInfo>,
    /// Which fd table each pid currently uses.
    pid_table: HashMap<pid_t, FdTableId>,
    /// Counter for allocating synthetic fd-table ids.
    next_table_id: FdTableId,
}

impl ProcessFdTracker {
    /// Register socket info for a PID and socket file descriptor
    pub(crate) fn add_sock_info(&mut self, pid: pid_t, fd: RawFd, info: SocketInfo) {
        let table_id = self.table_id_for_pid_mut(pid);
        self.sock_info.insert((table_id, fd), info);
    }

    /// Get socket info for a PID and socket file descriptor
    pub(crate) fn get_sock_info(&self, pid: pid_t, fd: RawFd) -> Option<&SocketInfo> {
        let table_id = self.pid_table.get(&pid)?;
        self.sock_info.get(&(*table_id, fd))
    }

    /// Get mutable socket info for a PID and socket file descriptor
    pub(crate) fn get_sock_info_mut(&mut self, pid: pid_t, fd: RawFd) -> Option<&mut SocketInfo> {
        let table_id = self.pid_table.get(&pid)?;
        self.sock_info.get_mut(&(*table_id, fd))
    }

    /// Register a child process, and wether or it shares its parent fds
    pub(crate) fn add_child_proc(
        &mut self,
        parent_pid: pid_t,
        child_pid: pid_t,
        share_fd_table: bool,
    ) {
        let parent_table_id = self.table_id_for_pid_mut(parent_pid);
        if share_fd_table {
            self.pid_table.insert(child_pid, parent_table_id);
        } else {
            let child_table_id = self.alloc_table_id();
            self.copy_sock_infos(parent_table_id, child_table_id);
            self.pid_table.insert(child_pid, child_table_id);
        }
    }

    /// Ensure a process has its own private fd table
    pub(crate) fn split_fd_table(&mut self, pid: pid_t) {
        let old_table_id = self.table_id_for_pid_mut(pid);
        let new_table_id = self.alloc_table_id();
        self.copy_sock_infos(old_table_id, new_table_id);
        self.pid_table.insert(pid, new_table_id);
    }

    fn alloc_table_id(&mut self) -> FdTableId {
        let id = self.next_table_id;
        self.next_table_id += 1;
        id
    }

    /// Get existing or new table id for a PID
    fn table_id_for_pid_mut(&mut self, pid: pid_t) -> FdTableId {
        let next = &mut self.next_table_id;
        *self.pid_table.entry(pid).or_insert_with(|| {
            let id = *next;
            *next += 1;
            id
        })
    }

    fn copy_sock_infos(&mut self, src_table: FdTableId, dst_table: FdTableId) {
        let infos_to_copy = self
            .sock_info
            .iter()
            .filter_map(|((table_id, fd), info)| {
                (*table_id == src_table).then_some((*fd, info.clone()))
            })
            .collect::<Vec<_>>();
        for (fd, info) in infos_to_copy {
            self.sock_info.insert((dst_table, fd), info);
        }
    }
}

/// Information that persists between syscalls and that we need to handle
/// Obviously, keeping this to a minimum is a goal
#[derive(Debug)]
pub(crate) struct ProgramState {
    /// Process fd-table topology and socket protocol tracking
    proc_fd: ProcessFdTracker,
    /// Current working directory
    cur_dir: PathBuf,
    /// System default for `IPV6_V6ONLY` (from net.ipv6.bindv6only sysctl)
    bindv6only_default: bool,
}

impl ProgramState {
    pub(crate) fn new<P>(cur_dir: P, bindv6only_default: bool) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            proc_fd: ProcessFdTracker::default(),
            cur_dir: cur_dir.into(),
            bindv6only_default,
        }
    }
}

/// Returns the set of syscall names that have handlers
pub(crate) fn handled_syscall_names() -> HashSet<&'static str> {
    SYSCALL_MAP.keys().copied().collect()
}

pub(crate) fn summarize<I>(
    syscalls: I,
    env_paths: &[PathBuf],
    mut program_state: ProgramState,
) -> anyhow::Result<Vec<ProgramAction>>
where
    I: IntoIterator<Item = anyhow::Result<SyscallItem>>,
{
    let mut actions = Vec::new();
    let mut stats: HashMap<SyscallName, u64> = HashMap::new();
    for item in syscalls {
        let item = item?;
        match item {
            SyscallItem::NameOnly(name) => {
                stats.entry(name).and_modify(|c| *c += 1).or_insert(1);
            }
            SyscallItem::Complete(syscall) => {
                log::trace!("{syscall:?}");
                stats
                    .entry(syscall.name.clone())
                    .and_modify(|c| *c += 1)
                    .or_insert(1);
                let name = syscall.name.as_str();

                if let Some(handler) = SYSCALL_MAP.get(name) {
                    handler
                        .handle(syscall.as_ref(), &mut actions, &mut program_state)
                        .with_context(|| format!("Failed to summarize syscall {syscall:?}"))?;
                }
            }
        }
    }

    // Almost free optimization
    actions.dedup();

    // Create single action with all syscalls for efficient handling of seccomp filters
    actions.push(ProgramAction::Syscalls(stats.keys().cloned().collect()));

    // Directories in PATH env var need to be accessible, otherwise systemd errors
    actions.extend(env_paths.iter().cloned().map(ProgramAction::Read));

    // Report stats
    if log::log_enabled!(log::Level::Debug) {
        let mut syscall_names = stats.keys().collect::<Vec<_>>();
        syscall_names.sort_unstable();
        for syscall_name in syscall_names {
            #[expect(clippy::unwrap_used)]
            let count = stats.get(syscall_name).unwrap();
            log::debug!("{:24} {: >12}", format!("{syscall_name}:"), count);
        }
    }

    Ok(actions)
}

#[cfg(test)]
pub(crate) fn program_state() -> ProgramState {
    ProgramState::new("/", false)
}

#[expect(clippy::unreadable_literal)]
#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        os::unix::{self, ffi::OsStrExt as _},
    };

    use super::{
        handlers::tests::{buf_expr, int_literal, make_syscall, named_symbol},
        *,
    };
    use crate::strace::*;

    #[test]
    fn relative_rename() {
        let _ = simple_logger::SimpleLogger::new().init();

        let env_paths = [
            PathBuf::from("/path/from/env/1"),
            PathBuf::from("/path/from/env/2"),
        ];
        let state = program_state();

        let temp_dir_src = tempfile::tempdir().unwrap();
        let temp_dir_dst = tempfile::tempdir().unwrap();
        let syscalls = [Ok(SyscallItem::Complete(Box::new(Syscall {
            pid: 1068781,
            rel_ts: 0.000083,
            name: "renameat".into(),
            args: vec![
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol("AT_FDCWD".to_owned()),
                    metadata: Some(temp_dir_src.path().as_os_str().as_bytes().to_vec()),
                }),
                Expression::Buffer(BufferExpression {
                    value: "a".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol("AT_FDCWD".to_owned()),
                    metadata: Some(temp_dir_dst.path().as_os_str().as_bytes().to_vec()),
                }),
                Expression::Buffer(BufferExpression {
                    value: "b".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol("RENAME_NOREPLACE".to_owned()),
                    metadata: None,
                }),
            ],
            ret_val: Some(IntegerExpression {
                value: IntegerExpressionValue::Literal(0),
                metadata: None,
            }),
        })))];
        assert_eq!(
            summarize(syscalls, &env_paths, state).unwrap(),
            vec![
                ProgramAction::Read(temp_dir_src.path().join("a")),
                ProgramAction::Write(temp_dir_src.path().join("a")),
                ProgramAction::Create(temp_dir_dst.path().join("b")),
                ProgramAction::Write(temp_dir_dst.path().join("b")),
                ProgramAction::Syscalls(["renameat".into()].into()),
                ProgramAction::Read("/path/from/env/1".into()),
                ProgramAction::Read("/path/from/env/2".into()),
            ]
        );
    }

    #[test]
    fn connect_uds() {
        let _ = simple_logger::SimpleLogger::new().init();

        let env_paths = [
            PathBuf::from("/path/from/env/1"),
            PathBuf::from("/path/from/env/2"),
        ];
        let state = program_state();

        let syscalls = [Ok(SyscallItem::Complete(Box::new(Syscall {
            pid: 598056,
            rel_ts: 0.000036,
            name: "connect".into(),
            args: vec![
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Literal(4),
                    metadata: Some("/run/user/1000/systemd/private".as_bytes().to_vec()),
                }),
                Expression::Struct(HashMap::from([
                    (
                        "sa_family".to_owned(),
                        Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedSymbol("AF_UNIX".to_owned()),
                            metadata: None,
                        }),
                    ),
                    (
                        "sun_path".to_owned(),
                        Expression::Buffer(BufferExpression {
                            value: "/run/user/1000/systemd/private".as_bytes().to_vec(),
                            type_: BufferType::Unknown,
                        }),
                    ),
                ])),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Literal(33),
                    metadata: None,
                }),
            ],
            ret_val: Some(IntegerExpression {
                value: IntegerExpressionValue::Literal(0),
                metadata: None,
            }),
        })))];
        assert_eq!(
            summarize(syscalls, &env_paths, state).unwrap(),
            vec![
                ProgramAction::Read("/run/user/1000/systemd/private".into()),
                ProgramAction::Syscalls(["connect".into()].into()),
                ProgramAction::Read("/path/from/env/1".into()),
                ProgramAction::Read("/path/from/env/2".into()),
            ]
        );
    }

    #[test]
    fn fstat_unknown() {
        let _ = simple_logger::SimpleLogger::new().init();

        let state = program_state();

        let syscalls = [Ok(SyscallItem::Complete(Box::new(Syscall {
            pid: 498133,
            rel_ts: 7.5e-5,
            name: "fstat".into(),
            args: vec![
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Literal(3),
                    metadata: None,
                }),
                Expression::Struct(
                    [
                        (
                            "st_dev".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Macro {
                                    name: "makedev".to_owned(),
                                    args: vec![
                                        Expression::Integer(IntegerExpression {
                                            value: IntegerExpressionValue::Literal(0),
                                            metadata: None,
                                        }),
                                        Expression::Integer(IntegerExpression {
                                            value: IntegerExpressionValue::Literal(101),
                                            metadata: None,
                                        }),
                                    ],
                                },
                                metadata: None,
                            }),
                        ),
                        (
                            "st_ctime_nsec".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(381300641),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_size".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(49962383),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_mtime".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1759308185),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_mtime_nsec".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_ctime".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1761822274),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_blksize".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(4096),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_ino".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(5369),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_uid".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1000),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_gid".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1000),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_blocks".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(97584),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_nlink".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_mode".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::BinaryOr(vec![
                                    IntegerExpressionValue::NamedSymbol("S_IFREG".to_owned()),
                                    IntegerExpressionValue::Literal(493),
                                ]),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_atime".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1761822274),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_atime_nsec".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(486303215),
                                metadata: None,
                            }),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ],
            ret_val: Some(IntegerExpression {
                value: IntegerExpressionValue::Literal(0),
                metadata: None,
            }),
        })))];
        assert_eq!(
            summarize(syscalls, &[], state).unwrap(),
            vec![ProgramAction::Syscalls(
                ["fstat".into()].into_iter().collect()
            )]
        );
    }

    fn syscall(name: &str, args: Vec<Expression>) -> SyscallItem {
        SyscallItem::Complete(Box::new(make_syscall(name, args, 0)))
    }

    #[test]
    fn unlink_removes_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let state = program_state();

        let syscalls = [Ok(syscall("unlink", vec![buf_expr(b"/var/lib/test")]))];
        assert_eq!(
            summarize(syscalls, &[], state).unwrap(),
            vec![
                ProgramAction::Remove("/var/lib/test".into()),
                ProgramAction::Syscalls(["unlink".into()].into()),
            ]
        );
    }

    #[test]
    fn utimensat_null_path_writes_fd_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let state = program_state();

        // glibc's futimens(fd, times)
        let fd = Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::Literal(3),
            metadata: Some("/var/lib/test".as_bytes().to_vec()),
        });
        let syscalls = [Ok(syscall(
            "utimensat",
            vec![
                fd,
                named_symbol("NULL"),
                named_symbol("NULL"),
                int_literal(0),
            ],
        ))];
        assert_eq!(
            summarize(syscalls, &[], state).unwrap(),
            vec![
                ProgramAction::Write("/var/lib/test".into()),
                ProgramAction::Syscalls(["utimensat".into()].into()),
            ]
        );
    }

    #[test]
    fn write_symlink_follow() {
        let _ = simple_logger::SimpleLogger::new().init();

        let state = program_state();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        let target_dir = temp_dir.path().join("target_dir");
        let link_dir = temp_dir.path().join("link_dir");
        fs::create_dir(&target_dir).unwrap();
        unix::fs::symlink(&target_dir, &link_dir).unwrap();
        let link_str = link.to_str().unwrap();
        let syscalls = [
            Ok(syscall(
                "utimensat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(link_str.as_bytes()),
                    named_symbol("NULL"),
                    named_symbol("AT_SYMLINK_NOFOLLOW"),
                ],
            )),
            Ok(syscall(
                "chmod",
                vec![buf_expr(link_str.as_bytes()), int_literal(0o644)],
            )),
            Ok(syscall("unlink", vec![buf_expr(link_str.as_bytes())])),
            // A trailing slash follows the symlink despite AT_SYMLINK_NOFOLLOW
            Ok(syscall(
                "utimensat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(format!("{}/", link_dir.to_str().unwrap()).as_bytes()),
                    named_symbol("NULL"),
                    named_symbol("AT_SYMLINK_NOFOLLOW"),
                ],
            )),
            Ok(syscall(
                "unlink",
                vec![buf_expr(link_dir.join("file").as_os_str().as_bytes())],
            )),
        ];
        assert_eq!(
            summarize(syscalls, &[], state).unwrap(),
            vec![
                ProgramAction::Write(link.clone()),
                ProgramAction::Read(link.clone()),
                ProgramAction::Write(target),
                ProgramAction::Remove(link),
                ProgramAction::Read(link_dir.clone()),
                ProgramAction::Write(target_dir.clone()),
                ProgramAction::Read(link_dir),
                ProgramAction::Remove(target_dir.join("file")),
                ProgramAction::Syscalls(
                    ["chmod".into(), "unlink".into(), "utimensat".into()].into()
                ),
            ]
        );
    }

    #[test]
    fn write_fd_symlink_no_follow() {
        let _ = simple_logger::SimpleLogger::new().init();

        let state = program_state();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        // O_PATH|O_NOFOLLOW descriptor of the symlink
        let fd = Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::Literal(3),
            metadata: Some(link.as_os_str().as_bytes().to_vec()),
        });
        let syscalls = [Ok(syscall(
            "fchownat",
            vec![
                fd,
                buf_expr(b""),
                int_literal(0),
                int_literal(0),
                named_symbol("AT_EMPTY_PATH"),
            ],
        ))];
        assert_eq!(
            summarize(syscalls, &[], state).unwrap(),
            vec![
                ProgramAction::Write(link),
                ProgramAction::Syscalls(["fchownat".into()].into()),
            ]
        );
    }

    #[test]
    fn write_at_symlink_no_follow_flag() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        let dir_fd = Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::Literal(3),
            metadata: Some(temp_dir.path().as_os_str().as_bytes().to_vec()),
        });
        for (name, args) in [
            (
                "fchmodat2",
                vec![
                    dir_fd.clone(),
                    buf_expr(b"link"),
                    int_literal(0o644),
                    named_symbol("AT_SYMLINK_NOFOLLOW"),
                ],
            ),
            (
                "fchownat",
                vec![
                    dir_fd.clone(),
                    buf_expr(b"link"),
                    int_literal(0),
                    int_literal(0),
                    named_symbol("AT_SYMLINK_NOFOLLOW"),
                ],
            ),
        ] {
            assert_eq!(
                summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                vec![
                    ProgramAction::Write(link.clone()),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }

    #[test]
    fn utimensat_null_path_closed_fd() {
        let _ = simple_logger::SimpleLogger::new().init();

        let state = program_state();

        let syscalls = [Ok(syscall(
            "utimensat",
            vec![
                int_literal(3),
                named_symbol("NULL"),
                named_symbol("NULL"),
                int_literal(0),
            ],
        ))];
        assert_eq!(
            summarize(syscalls, &[], state).unwrap(),
            vec![ProgramAction::Syscalls(["utimensat".into()].into())]
        );
    }
}
