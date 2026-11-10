//! Summarize program syscalls into higher level action

use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display},
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU16,
    os::fd::RawFd,
    path::PathBuf,
};

use anyhow::Context as _;
use nix::libc::pid_t;

use crate::{
    strace::{SyscallItem, SyscallName},
    systemd::{SocketFamily, SocketProtocol},
};

mod handlers;

use handlers::{
    AccessHandler, ChdirHandler, Clone3Handler, EpollCtlHandler, ExecHandler, FanotifyMarkHandler,
    FdWriteHandler, FollowSymlink, ForkHandler, IoctlHandler, KillHandler, LinkHandler,
    MemfdCreateHandler, MknodHandler, MmapHandler, MountHandler, NetworkHandler, OpenHandler,
    PathHandler, RenameHandler, SetSchedulerHandler, SetsockoptHandler, ShmCtlHandler,
    SocketHandler, StatFdHandler, SyscallHandler, TimerCreateHandler, UnshareHandler,
};

/// A high level program runtime action
/// This does *not* map 1-1 with a syscall, and does *not* necessarily respect chronology
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum ProgramAction {
    /// Create a path, or an unnamed file in the directory it names
    Create(PathBuf),
    /// Exec a path
    Exec(PathBuf),
    /// Act on the host's mount namespace
    HostMountNamespace,
    /// Memory mapping with huge pages
    HugePageMemoryMapping,
    /// Send signal to other process ("other" being defined as requiring `CAP_KILL`)
    KillOther,
    /// Lock memory mapping
    LockMemoryMapping,
    /// Create special files
    MknodSpecial,
    /// Network (socket) activity
    NetworkActivity(Box<NetworkActivity>),
    /// Access a path (open, stat, read...)
    Read(PathBuf),
    /// Remove a path
    Remove(PathBuf),
    /// Paths a link or rename needs on the same mount
    RequireSameMount(PathBuf, PathBuf),
    /// Set privileged timer alarm
    SetAlarm,
    /// Set scheduler to a real time one
    SetRealtimeScheduler,
    /// Names of the syscalls made by the program
    Syscalls(HashSet<SyscallName>),
    /// Inhibit suspend
    Wakeup,
    /// Write to a path (data, metadata...)
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
static SYSCALL_MAP: phf::Map<&'static str, &'static dyn SyscallHandler> = phf::phf_map! {
    "accept" => &NetworkHandler { fd: 0, sockaddr: 1 },
    "accept4" => &NetworkHandler { fd: 0, sockaddr: 1 },
    "access" => &AccessHandler {
        path: PathHandler {
            relfd: None,
            path: 0,
            follow: FollowSymlink::Always,
            action: ProgramAction::Read,
        },
        mode: 1,
    },
    "bind" => &NetworkHandler { fd: 0, sockaddr: 1 },
    "chdir" => &ChdirHandler {
        path: FdOrPath::Path(0),
    },
    "chmod" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "chown" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    // Note: strace decodes clone's arguments as a struct, like clone3
    "clone" => &Clone3Handler { args: 0 },
    "clone3" => &Clone3Handler { args: 0 },
    "connect" => &NetworkHandler { fd: 0, sockaddr: 1 },
    "creat" => &OpenHandler {
        relfd: None,
        path: 0,
        flags: None,
    },
    "epoll_ctl" => &EpollCtlHandler { op: 1, event: 3 },
    "execve" => &ExecHandler {
        relfd: None,
        path: 0,
    },
    "execveat" => &ExecHandler {
        relfd: Some(0),
        path: 1,
    },
    "faccessat" => &AccessHandler {
        path: PathHandler {
            relfd: Some(0),
            path: 1,
            follow: FollowSymlink::Always,
            action: ProgramAction::Read,
        },
        mode: 2,
    },
    "faccessat2" => &AccessHandler {
        path: PathHandler {
            relfd: Some(0),
            path: 1,
            follow: FollowSymlink::UnlessNoFollowFlag {
                flags: 3,
                no_follow_flag: "AT_SYMLINK_NOFOLLOW",
            },
            action: ProgramAction::Read,
        },
        mode: 2,
    },
    "fanotify_mark" => &FanotifyMarkHandler {
        path: PathHandler {
            relfd: Some(3),
            path: 4,
            follow: FollowSymlink::UnlessNoFollowFlag {
                flags: 1,
                no_follow_flag: "FAN_MARK_DONT_FOLLOW",
            },
            action: ProgramAction::Read,
        },
        flags: 1,
    },
    "fchdir" => &ChdirHandler {
        path: FdOrPath::Fd(0),
    },
    "fchmod" => &FdWriteHandler { fd: 0 },
    "fchmodat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "fchmodat2" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 3,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Write,
    },
    "fchown" => &FdWriteHandler { fd: 0 },
    "fchownat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 4,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Write,
    },
    "file_getattr" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 4,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Read,
    },
    "file_setattr" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 4,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Write,
    },
    "fork" => &ForkHandler,
    "fremovexattr" => &FdWriteHandler { fd: 0 },
    "fsetxattr" => &FdWriteHandler { fd: 0 },
    "fstat" => &StatFdHandler { fd: 0 },
    "futimesat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "getdents" => &StatFdHandler { fd: 0 },
    "getxattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Read,
    },
    "getxattrat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 2,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Read,
    },
    "inotify_add_watch" => &PathHandler {
        relfd: None,
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 2,
            no_follow_flag: "IN_DONT_FOLLOW",
        },
        action: ProgramAction::Read,
    },
    "ioctl" => &IoctlHandler { fd: 0, request: 1 },
    "kill" => &KillHandler { pid: 0, sig: 1 },
    "lchown" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Write,
    },
    "lgetxattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Read,
    },
    "link" => &LinkHandler {
        old: PathHandler {
            relfd: None,
            path: 0,
            follow: FollowSymlink::OnTrailingSlash,
            action: ProgramAction::Read,
        },
        new: PathHandler {
            relfd: None,
            path: 1,
            follow: FollowSymlink::Never,
            action: ProgramAction::Create,
        },
    },
    "linkat" => &LinkHandler {
        old: PathHandler {
            relfd: Some(0),
            path: 1,
            follow: FollowSymlink::IfFollowFlag(4),
            action: ProgramAction::Read,
        },
        new: PathHandler {
            relfd: Some(2),
            path: 3,
            follow: FollowSymlink::Never,
            action: ProgramAction::Create,
        },
    },
    "listxattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Read,
    },
    "listxattrat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 2,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Read,
    },
    "llistxattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Read,
    },
    "lremovexattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Write,
    },
    "lsetxattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Write,
    },
    "lstat" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Read,
    },
    "memfd_create" => &MemfdCreateHandler { flags: 1 },
    "mkdir" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Never,
        action: ProgramAction::Create,
    },
    "mkdirat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::Never,
        action: ProgramAction::Create,
    },
    "mknod" => &MknodHandler {
        path: FdOrPath::Path(0),
        mode: 1,
    },
    "mknodat" => &MknodHandler {
        path: FdOrPath::Fd(1),
        mode: 2,
    },
    "mmap" => &MmapHandler {
        prot: 2,
        flags: Some(3),
        fd: Some(4),
    },
    "mmap2" => &MmapHandler {
        prot: 2,
        flags: Some(3),
        fd: Some(4),
    },
    "mount" => &MountHandler { flags: 3 },
    "mprotect" => &MmapHandler {
        prot: 2,
        flags: None,
        fd: None,
    },
    "name_to_handle_at" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::IfFollowFlag(4),
        action: ProgramAction::Read,
    },
    "newfstatat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::Always,
        action: ProgramAction::Read,
    },
    "open" => &OpenHandler {
        relfd: None,
        path: 0,
        flags: Some(1),
    },
    "openat" => &OpenHandler {
        relfd: Some(0),
        path: 1,
        flags: Some(2),
    },
    "openat2" => &OpenHandler {
        relfd: Some(0),
        path: 1,
        flags: Some(2),
    },
    "pkey_mprotect" => &MmapHandler {
        prot: 2,
        flags: None,
        fd: None,
    },
    "readlink" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Read,
    },
    "readlinkat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::OnTrailingSlash,
        action: ProgramAction::Read,
    },
    "recvfrom" => &NetworkHandler { fd: 0, sockaddr: 4 },
    "removexattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "removexattrat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 2,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Write,
    },
    "rename" => &RenameHandler {
        relfd_src: None,
        path_src: 0,
        relfd_dst: None,
        path_dst: 1,
        flags: None,
    },
    "renameat" => &RenameHandler {
        relfd_src: Some(0),
        path_src: 1,
        relfd_dst: Some(2),
        path_dst: 3,
        flags: None,
    },
    "renameat2" => &RenameHandler {
        relfd_src: Some(0),
        path_src: 1,
        relfd_dst: Some(2),
        path_dst: 3,
        flags: Some(4),
    },
    "rmdir" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Never,
        action: ProgramAction::Remove,
    },
    "sched_setscheduler" => &SetSchedulerHandler { policy: 1 },
    "sendto" => &NetworkHandler { fd: 0, sockaddr: 4 },
    "setsockopt" => &SetsockoptHandler {
        fd: 0,
        level: 1,
        optname: 2,
        optval: 3,
    },
    "setxattr" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "setxattrat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 2,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Write,
    },
    "shmctl" => &ShmCtlHandler { op: 1 },
    "socket" => &SocketHandler { af: 0, flags: 1 },
    "stat" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Read,
    },
    "statfs" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Read,
    },
    "statx" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 2,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Read,
    },
    "symlink" => &PathHandler {
        relfd: None,
        path: 1,
        follow: FollowSymlink::Never,
        action: ProgramAction::Create,
    },
    "symlinkat" => &PathHandler {
        relfd: Some(1),
        path: 2,
        follow: FollowSymlink::Never,
        action: ProgramAction::Create,
    },
    "timer_create" => &TimerCreateHandler { clockid: 0 },
    "truncate" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "unlink" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Never,
        action: ProgramAction::Remove,
    },
    "unlinkat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::Never,
        action: ProgramAction::Remove,
    },
    "unshare" => &UnshareHandler { flags: 0 },
    "utime" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "utimensat" => &PathHandler {
        relfd: Some(0),
        path: 1,
        follow: FollowSymlink::UnlessNoFollowFlag {
            flags: 3,
            no_follow_flag: "AT_SYMLINK_NOFOLLOW",
        },
        action: ProgramAction::Write,
    },
    "utimes" => &PathHandler {
        relfd: None,
        path: 0,
        follow: FollowSymlink::Always,
        action: ProgramAction::Write,
    },
    "vfork" => &ForkHandler,
};

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
        handlers::tests::{
            binary_or_flags, buf_expr, fd_expr, int_literal, make_failed_syscall, make_syscall,
            named_symbol,
        },
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
                    value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(
                        "AT_FDCWD".to_owned(),
                    )),
                    metadata: Some(temp_dir_src.path().as_os_str().as_bytes().to_vec()),
                }),
                Expression::Buffer(BufferExpression {
                    value: "a".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(
                        "AT_FDCWD".to_owned(),
                    )),
                    metadata: Some(temp_dir_dst.path().as_os_str().as_bytes().to_vec()),
                }),
                Expression::Buffer(BufferExpression {
                    value: "b".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(
                        "RENAME_NOREPLACE".to_owned(),
                    )),
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
                ProgramAction::RequireSameMount(
                    temp_dir_src.path().to_owned(),
                    temp_dir_dst.path().to_owned()
                ),
                ProgramAction::Syscalls(["renameat".into()].into()),
                ProgramAction::Read("/path/from/env/1".into()),
                ProgramAction::Read("/path/from/env/2".into()),
            ]
        );
    }

    #[test]
    fn connect_bind_uds() {
        let _ = simple_logger::SimpleLogger::new().init();

        let env_paths = [
            PathBuf::from("/path/from/env/1"),
            PathBuf::from("/path/from/env/2"),
        ];
        let read = ProgramAction::Read("/run/test/sock".into());
        let create = ProgramAction::Create("/run/test/sock".into());
        for (name, path_actions) in [
            ("connect", vec![read.clone()]),
            ("bind", vec![read, create]),
        ] {
            let syscalls = [Ok(syscall(
                name,
                vec![
                    int_literal(3),
                    Expression::Struct(HashMap::from([
                        ("sa_family".to_owned(), named_symbol("AF_UNIX")),
                        ("sun_path".to_owned(), buf_expr(b"/run/test/sock")),
                    ])),
                    int_literal(17),
                ],
            ))];
            let other_actions = vec![
                ProgramAction::Syscalls([name.into()].into()),
                ProgramAction::Read("/path/from/env/1".into()),
                ProgramAction::Read("/path/from/env/2".into()),
            ];
            assert_eq!(
                summarize(syscalls, &env_paths, program_state()).unwrap(),
                [path_actions, other_actions].concat()
            );
        }
    }

    #[test]
    fn bind_abstract_uds() {
        let _ = simple_logger::SimpleLogger::new().init();

        let syscalls = [Ok(syscall(
            "bind",
            vec![
                int_literal(3),
                Expression::Struct(HashMap::from([
                    ("sa_family".to_owned(), named_symbol("AF_UNIX")),
                    (
                        "sun_path".to_owned(),
                        Expression::Buffer(BufferExpression {
                            value: b"/run/test/sock".to_vec(),
                            type_: BufferType::AbstractPath,
                        }),
                    ),
                ])),
                int_literal(17),
            ],
        ))];
        assert_eq!(
            summarize(syscalls, &[], program_state()).unwrap(),
            vec![ProgramAction::Syscalls(["bind".into()].into())]
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
                                    IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(
                                        "S_IFREG".to_owned(),
                                    )),
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

    fn summarize_syscall(sc: Syscall) -> Vec<ProgramAction> {
        let item = SyscallItem::Complete(Box::new(sc));
        summarize([Ok(item)], &[], program_state()).unwrap()
    }

    #[test]
    fn creat_creates_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let syscalls = [Ok(syscall(
            "creat",
            vec![buf_expr(b"/var/lib/test"), int_literal(0o644)],
        ))];
        assert_eq!(
            summarize(syscalls, &[], program_state()).unwrap(),
            vec![
                ProgramAction::Create("/var/lib/test".into()),
                ProgramAction::Write("/var/lib/test".into()),
                ProgramAction::Syscalls(["creat".into()].into()),
            ]
        );
    }

    #[test]
    fn openat2_actions_follow_flags() {
        let _ = simple_logger::SimpleLogger::new().init();

        for (flags, mode, actions) in [
            (
                &["O_RDWR", "O_CREAT", "O_CLOEXEC"][..],
                0o600,
                vec![
                    ProgramAction::Create("/var/lib/test".into()),
                    ProgramAction::Write("/var/lib/test".into()),
                    ProgramAction::Read("/var/lib/test".into()),
                ],
            ),
            (
                &["O_RDONLY"],
                0,
                vec![ProgramAction::Read("/var/lib/test".into())],
            ),
            (
                &["O_WRONLY"],
                0,
                vec![ProgramAction::Write("/var/lib/test".into())],
            ),
            (
                &["O_RDONLY", "O_TRUNC"],
                0,
                vec![
                    ProgramAction::Write("/var/lib/test".into()),
                    ProgramAction::Read("/var/lib/test".into()),
                ],
            ),
        ] {
            let syscalls = [Ok(syscall(
                "openat2",
                vec![
                    fd_expr(3, "/var/lib"),
                    buf_expr(b"test"),
                    Expression::Struct(HashMap::from([
                        ("flags".to_owned(), binary_or_flags(flags)),
                        ("mode".to_owned(), int_literal(mode)),
                        ("resolve".to_owned(), int_literal(0)),
                    ])),
                    int_literal(24),
                ],
            ))];
            assert_eq!(
                summarize(syscalls, &[], program_state()).unwrap(),
                [
                    actions,
                    vec![ProgramAction::Syscalls(["openat2".into()].into())]
                ]
                .concat()
            );
        }
    }

    #[test]
    fn open_tmpfile_creates_in_dir() {
        let _ = simple_logger::SimpleLogger::new().init();

        // glibc's tmpfile()
        let syscalls = [Ok(SyscallItem::Complete(Box::new(Syscall {
            ret_val: Some(IntegerExpression {
                value: IntegerExpressionValue::Literal(3),
                metadata: Some(b"/tmp/#80".to_vec()),
            }),
            ..make_syscall(
                "openat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(b"/tmp"),
                    binary_or_flags(&["O_RDWR", "O_CLOEXEC", "O_TMPFILE"]),
                    int_literal(0o600),
                ],
                3,
            )
        })))];
        assert_eq!(
            summarize(syscalls, &[], program_state()).unwrap(),
            vec![
                ProgramAction::Create("/tmp/#80".into()),
                ProgramAction::Syscalls(["openat".into()].into()),
            ]
        );
    }

    #[test]
    fn open_path_ignores_tmpfile() {
        let _ = simple_logger::SimpleLogger::new().init();

        let syscalls = [Ok(syscall(
            "openat",
            vec![
                named_symbol("AT_FDCWD"),
                buf_expr(b"/tmp/cache"),
                binary_or_flags(&["O_RDWR", "O_CLOEXEC", "O_PATH", "O_TMPFILE"]),
                int_literal(0o777),
            ],
        ))];
        assert_eq!(
            summarize(syscalls, &[], program_state()).unwrap(),
            vec![
                ProgramAction::Read("/tmp/cache".into()),
                ProgramAction::Syscalls(["openat".into()].into()),
            ]
        );
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
    fn unlink_absent_entry_writes_dir() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Failing with ENOENT, which the parser keeps for removals
        let sc = make_failed_syscall("unlink", vec![buf_expr(b"/var/lib/absent")], "ENOENT");
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::Write("/var/lib".into()),
                ProgramAction::Syscalls(["unlink".into()].into()),
            ]
        );
    }

    #[test]
    fn rename_absent_entry_writes_dirs() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Failing with ENOENT, which the parser keeps for renames
        let sc = make_failed_syscall(
            "rename",
            vec![
                buf_expr(b"/var/lib/apt/absent"),
                buf_expr(b"/var/lib/misc/new"),
            ],
            "ENOENT",
        );
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::Write("/var/lib/apt".into()),
                ProgramAction::Write("/var/lib/misc".into()),
                ProgramAction::RequireSameMount("/var/lib/apt".into(), "/var/lib/misc".into()),
                ProgramAction::Syscalls(["rename".into()].into()),
            ]
        );
    }

    #[test]
    fn utimensat_null_path_writes_fd_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let state = program_state();

        // glibc's futimens(fd, times)
        let fd = fd_expr(3, "/var/lib/test");
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
    fn fd_writes_write_fd_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Descriptor of a file opened read-only
        let fd = fd_expr(3, "/var/lib/test");
        for sc in [
            make_syscall("fchmod", vec![fd.clone(), int_literal(0o640)], 0),
            make_syscall(
                "fchown",
                vec![fd.clone(), int_literal(0), int_literal(0)],
                0,
            ),
            make_syscall(
                "fsetxattr",
                vec![
                    fd.clone(),
                    buf_expr(b"user.test"),
                    buf_expr(b"x"),
                    int_literal(1),
                    int_literal(0),
                ],
                0,
            ),
            // Failing with ENODATA on an absent attribute, after the mount write check
            make_failed_syscall(
                "fremovexattr",
                vec![fd.clone(), buf_expr(b"user.absent")],
                "ENODATA",
            ),
            make_syscall(
                "ioctl",
                vec![
                    fd.clone(),
                    named_symbol("FS_IOC_SETFLAGS"),
                    Expression::Collection {
                        complement: false,
                        values: vec![(None, int_literal(0))],
                    },
                ],
                0,
            ),
            make_syscall(
                "ioctl",
                vec![
                    fd.clone(),
                    named_symbol("FS_IOC_FSSETXATTR"),
                    Expression::Struct(HashMap::from([("fsx_xflags".to_owned(), int_literal(0))])),
                ],
                0,
            ),
            make_syscall(
                "ioctl",
                vec![
                    fd.clone(),
                    named_symbol("FS_IOC_SETVERSION"),
                    buf_expr(b"\x00\x00\x00\x00\x00\x00\x00\x00"),
                ],
                0,
            ),
            make_syscall(
                "ioctl",
                vec![
                    fd.clone(),
                    named_symbol("FS_IOC_ENABLE_VERITY"),
                    int_literal(0x7ffd_0e48_4cc0),
                ],
                0,
            ),
            make_syscall(
                "ioctl",
                vec![
                    fd.clone(),
                    named_symbol("FS_IOC_SET_ENCRYPTION_POLICY"),
                    int_literal(0x7ffd_0e48_4cc0),
                ],
                0,
            ),
        ] {
            let name = sc.name.clone();
            assert_eq!(
                summarize_syscall(sc),
                vec![
                    ProgramAction::Write("/var/lib/test".into()),
                    ProgramAction::Syscalls([name].into()),
                ]
            );
        }
    }

    #[test]
    fn pseudo_fd_paths_ignored() {
        let _ = simple_logger::SimpleLogger::new().init();

        let memfd = fd_expr(4, "/memfd:review");
        for sc in [
            make_syscall(
                "fchmod",
                vec![fd_expr(3, "pipe:[123]"), int_literal(0o600)],
                0,
            ),
            make_syscall("fchmod", vec![memfd.clone(), int_literal(0o600)], 0),
            make_syscall(
                "mmap",
                vec![
                    named_symbol("NULL"),
                    int_literal(4096),
                    binary_or_flags(&["PROT_READ", "PROT_EXEC"]),
                    named_symbol("MAP_SHARED"),
                    memfd,
                    int_literal(0),
                ],
                0x7f00_0000_0000,
            ),
        ] {
            let name = sc.name.clone();
            assert_eq!(
                summarize_syscall(sc),
                vec![ProgramAction::Syscalls([name].into())]
            );
        }
    }

    #[test]
    fn ioctl_other_request_writes_nothing() {
        let _ = simple_logger::SimpleLogger::new().init();

        let sc = make_syscall(
            "ioctl",
            vec![
                fd_expr(0, "/dev/pts/0"),
                named_symbol("TCGETS"),
                Expression::Struct(HashMap::from([("c_iflag".to_owned(), int_literal(0))])),
            ],
            0,
        );
        assert_eq!(
            summarize_syscall(sc),
            vec![ProgramAction::Syscalls(["ioctl".into()].into())]
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
        let fd = fd_expr(3, &link);
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
        let dir_fd = fd_expr(3, temp_dir.path());
        for (flags, path_actions) in [
            (
                named_symbol("AT_SYMLINK_NOFOLLOW"),
                vec![ProgramAction::Write(link.clone())],
            ),
            (
                int_literal(0),
                vec![
                    ProgramAction::Read(link.clone()),
                    ProgramAction::Write(target.clone()),
                ],
            ),
        ] {
            for (name, args) in [
                (
                    "fchmodat2",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        int_literal(0o644),
                        flags.clone(),
                    ],
                ),
                (
                    "fchownat",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        int_literal(0),
                        int_literal(0),
                        flags.clone(),
                    ],
                ),
                (
                    "file_setattr",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        Expression::Struct(HashMap::from([(
                            "fa_xflags".to_owned(),
                            int_literal(0),
                        )])),
                        int_literal(24),
                        flags.clone(),
                    ],
                ),
                (
                    "removexattrat",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        flags.clone(),
                        buf_expr(b"user.test"),
                    ],
                ),
                (
                    "setxattrat",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        flags.clone(),
                        buf_expr(b"user.test"),
                        Expression::Struct(HashMap::from([
                            ("value".to_owned(), buf_expr(b"value")),
                            ("size".to_owned(), int_literal(5)),
                            ("flags".to_owned(), int_literal(0)),
                        ])),
                        int_literal(16),
                    ],
                ),
                (
                    "utimensat",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        named_symbol("NULL"),
                        flags.clone(),
                    ],
                ),
            ] {
                assert_eq!(
                    summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                    [
                        path_actions.clone(),
                        vec![ProgramAction::Syscalls([name.into()].into())]
                    ]
                    .concat()
                );
            }
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

    #[test]
    fn link_creates_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_dir.path().join("target_dir");
        let link_dir = temp_dir.path().join("link_dir");
        fs::create_dir(&target_dir).unwrap();
        unix::fs::symlink(&target_dir, &link_dir).unwrap();
        let dir_fd = fd_expr(3, temp_dir.path());
        let new = link_dir.join("new");
        let new_bytes = new.as_os_str().as_bytes();
        for (name, args) in [
            ("link", vec![buf_expr(b"/src"), buf_expr(new_bytes)]),
            (
                "linkat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(b"/src"),
                    dir_fd.clone(),
                    buf_expr(b"link_dir/new"),
                    int_literal(0),
                ],
            ),
            ("symlink", vec![buf_expr(b"/src"), buf_expr(new_bytes)]),
            (
                "symlinkat",
                vec![buf_expr(b"/src"), dir_fd.clone(), buf_expr(b"link_dir/new")],
            ),
        ] {
            // A hard link also reads its source, and needs it on the mount of the new entry's directory
            let hard_link = matches!(name, "link" | "linkat");
            let old = hard_link.then(|| ProgramAction::Read("/src".into()));
            let same_mount = hard_link
                .then(|| ProgramAction::RequireSameMount("/src".into(), target_dir.clone()));
            assert_eq!(
                summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                old.into_iter()
                    .chain([
                        ProgramAction::Read(link_dir.clone()),
                        ProgramAction::Create(target_dir.join("new")),
                    ])
                    .chain(same_mount)
                    .chain([ProgramAction::Syscalls([name.into()].into())])
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn link_reads_old_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        let dir_fd = fd_expr(3, temp_dir.path());
        let target_fd = fd_expr(4, &target);
        let new = temp_dir.path().join("new");
        let linkat = |old_fd: &Expression, old: &[u8], flags| {
            vec![
                old_fd.clone(),
                buf_expr(old),
                named_symbol("AT_FDCWD"),
                buf_expr(new.as_os_str().as_bytes()),
                flags,
            ]
        };
        for (name, args, old_actions, old) in [
            (
                "link",
                vec![
                    buf_expr(link.as_os_str().as_bytes()),
                    buf_expr(new.as_os_str().as_bytes()),
                ],
                vec![ProgramAction::Read(link.clone())],
                &link,
            ),
            (
                "linkat",
                linkat(&dir_fd, b"link", int_literal(0)),
                vec![ProgramAction::Read(link.clone())],
                &link,
            ),
            (
                "linkat",
                linkat(&dir_fd, b"link", named_symbol("AT_SYMLINK_FOLLOW")),
                vec![
                    ProgramAction::Read(link.clone()),
                    ProgramAction::Read(target.clone()),
                ],
                &target,
            ),
            (
                "linkat",
                linkat(&target_fd, b"", named_symbol("AT_EMPTY_PATH")),
                vec![ProgramAction::Read(target.clone())],
                &target,
            ),
        ] {
            let mut expected = old_actions;
            expected.extend([
                ProgramAction::Create(new.clone()),
                ProgramAction::RequireSameMount(old.clone(), temp_dir.path().to_owned()),
                ProgramAction::Syscalls([name.into()].into()),
            ]);
            assert_eq!(
                summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn link_trailing_slash_follows_old_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_dir.path().join("target_dir");
        let link_dir = temp_dir.path().join("link_dir");
        let existing = temp_dir.path().join("existing");
        fs::create_dir(&target_dir).unwrap();
        unix::fs::symlink(&target_dir, &link_dir).unwrap();
        unix::fs::symlink(temp_dir.path().join("missing"), &existing).unwrap();
        let dir_fd = fd_expr(3, temp_dir.path());
        // Failing with EEXIST, which the parser keeps, as hard linking a directory never succeeds
        for (name, args) in [
            (
                "link",
                vec![
                    buf_expr(&[link_dir.as_os_str().as_bytes(), b"/"].concat()),
                    buf_expr(existing.as_os_str().as_bytes()),
                ],
            ),
            (
                "linkat",
                vec![
                    dir_fd.clone(),
                    buf_expr(b"link_dir/"),
                    dir_fd,
                    buf_expr(b"existing"),
                    int_literal(0),
                ],
            ),
        ] {
            let sc = make_syscall(name, args, -1);
            assert_eq!(
                summarize_syscall(sc),
                vec![
                    ProgramAction::Read(link_dir.clone()),
                    ProgramAction::Read(target_dir.clone()),
                    ProgramAction::Read(existing.clone()),
                    ProgramAction::Create(existing.clone()),
                    ProgramAction::RequireSameMount(target_dir.clone(), temp_dir.path().to_owned()),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }

    #[test]
    fn rename_requires_same_mount() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let src_dir = temp_dir.path().join("src_dir");
        let src_dir_link = temp_dir.path().join("src_dir_link");
        let other_dir = temp_dir.path().join("other_dir");
        fs::create_dir(&src_dir).unwrap();
        fs::create_dir(&other_dir).unwrap();
        unix::fs::symlink(&src_dir, &src_dir_link).unwrap();
        unix::fs::symlink(other_dir.join("target"), src_dir.join("old")).unwrap();
        let new = temp_dir.path().join("new");
        let args = vec![
            named_symbol("AT_FDCWD"),
            buf_expr(src_dir_link.join("old").as_os_str().as_bytes()),
            named_symbol("AT_FDCWD"),
            buf_expr(new.as_os_str().as_bytes()),
        ];
        assert_eq!(
            summarize([Ok(syscall("renameat", args))], &[], program_state()).unwrap(),
            vec![
                ProgramAction::Read(src_dir_link.clone()),
                ProgramAction::Read(src_dir.join("old")),
                ProgramAction::Read(other_dir.join("target")),
                ProgramAction::Write(other_dir.join("target")),
                ProgramAction::Create(new.clone()),
                ProgramAction::Write(new),
                ProgramAction::RequireSameMount(src_dir, temp_dir.path().to_path_buf()),
                ProgramAction::Syscalls(["renameat".into()].into()),
            ]
        );
    }

    #[test]
    fn create_symlink_no_follow() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let link = temp_dir.path().join("link");
        unix::fs::symlink(temp_dir.path().join("missing"), &link).unwrap();
        let dir_fd = fd_expr(3, temp_dir.path());
        // The entry a successful call creates is a symlink when handled if the call made one, or if one
        // replaced it since
        for (name, args) in [
            (
                "mkdir",
                vec![buf_expr(link.as_os_str().as_bytes()), int_literal(0o755)],
            ),
            (
                "symlink",
                vec![buf_expr(b"/src"), buf_expr(link.as_os_str().as_bytes())],
            ),
            (
                "symlinkat",
                vec![buf_expr(b"/src"), dir_fd.clone(), buf_expr(b"link")],
            ),
            (
                "link",
                vec![buf_expr(b"/src"), buf_expr(link.as_os_str().as_bytes())],
            ),
            (
                "linkat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(b"/src"),
                    dir_fd.clone(),
                    buf_expr(b"link"),
                    int_literal(0),
                ],
            ),
            // A trailing slash does not make the kernel follow the entry a call creates
            (
                "mkdirat",
                vec![dir_fd.clone(), buf_expr(b"link/"), int_literal(0o755)],
            ),
        ] {
            // A hard link also reads its source, and needs it on the mount of the new entry's directory
            let hard_link = matches!(name, "link" | "linkat");
            let old = hard_link.then(|| ProgramAction::Read("/src".into()));
            let same_mount = hard_link.then(|| {
                ProgramAction::RequireSameMount("/src".into(), temp_dir.path().to_owned())
            });
            assert_eq!(
                summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                old.into_iter()
                    .chain([ProgramAction::Create(link.clone())])
                    .chain(same_mount)
                    .chain([ProgramAction::Syscalls([name.into()].into())])
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn create_existing_path_reads() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path().join("dir");
        fs::create_dir(&dir).unwrap();
        let link = temp_dir.path().join("link");
        unix::fs::symlink(temp_dir.path().join("missing"), &link).unwrap();
        for path in [dir, link] {
            // Failing with EEXIST, which the parser keeps
            let mkdir = make_syscall(
                "mkdir",
                vec![buf_expr(path.as_os_str().as_bytes()), int_literal(0o755)],
                -1,
            );
            assert_eq!(
                summarize_syscall(mkdir),
                vec![
                    ProgramAction::Read(path.clone()),
                    ProgramAction::Create(path),
                    ProgramAction::Syscalls(["mkdir".into()].into()),
                ]
            );
        }
    }

    #[test]
    fn link_existing_requires_same_mount() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let existing = temp_dir.path().join("existing");
        File::create(&existing).unwrap();
        // Failing with EEXIST, which the parser keeps
        let link = make_syscall(
            "link",
            vec![buf_expr(b"/src"), buf_expr(existing.as_os_str().as_bytes())],
            -1,
        );
        assert_eq!(
            summarize_syscall(link),
            vec![
                ProgramAction::Read("/src".into()),
                ProgramAction::Read(existing.clone()),
                ProgramAction::Create(existing),
                ProgramAction::RequireSameMount("/src".into(), temp_dir.path().to_owned()),
                ProgramAction::Syscalls(["link".into()].into()),
            ]
        );
    }

    #[test]
    fn open_excl_existing_reads() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let existing = temp_dir.path().join("existing");
        File::create(&existing).unwrap();
        let existing_bytes = existing.as_os_str().as_bytes();
        let flags = ["O_RDWR", "O_CREAT", "O_EXCL"];
        // Failing with EEXIST, which the parser keeps
        for (name, args) in [
            (
                "open",
                vec![
                    buf_expr(existing_bytes),
                    binary_or_flags(&flags),
                    int_literal(0o644),
                ],
            ),
            (
                "openat",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(existing_bytes),
                    binary_or_flags(&flags),
                    int_literal(0o644),
                ],
            ),
            (
                "openat2",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(existing_bytes),
                    Expression::Struct(HashMap::from([
                        ("flags".to_owned(), binary_or_flags(&flags)),
                        ("mode".to_owned(), int_literal(0o644)),
                        ("resolve".to_owned(), int_literal(0)),
                    ])),
                    int_literal(24),
                ],
            ),
        ] {
            let sc = make_syscall(name, args, -1);
            assert_eq!(
                summarize_syscall(sc),
                vec![
                    ProgramAction::Read(existing.clone()),
                    ProgramAction::Create(existing.clone()),
                    ProgramAction::Write(existing.clone()),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }

    #[test]
    fn open_excl_existing_symlink_no_follow() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let parent = temp_dir.path().join("parent");
        fs::create_dir(&parent).unwrap();
        let alias = temp_dir.path().join("alias");
        unix::fs::symlink(&parent, &alias).unwrap();
        let target = temp_dir.path().join("target");
        let link = parent.join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        // Failing with EEXIST, which the parser keeps
        let sc = make_syscall(
            "openat",
            vec![
                named_symbol("AT_FDCWD"),
                buf_expr(alias.join("link").as_os_str().as_bytes()),
                binary_or_flags(&["O_WRONLY", "O_CREAT", "O_EXCL"]),
                int_literal(0o644),
            ],
            -1,
        );
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::Read(alias),
                ProgramAction::Read(link.clone()),
                ProgramAction::Create(link.clone()),
                ProgramAction::Write(link),
                ProgramAction::Syscalls(["openat".into()].into()),
            ]
        );
    }

    #[test]
    fn rename_noreplace_existing_reads() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let existing = temp_dir.path().join("existing");
        File::create(&existing).unwrap();
        // Failing with EEXIST, which the parser keeps
        let sc = make_syscall(
            "renameat2",
            vec![
                named_symbol("AT_FDCWD"),
                buf_expr(b"/src/file"),
                named_symbol("AT_FDCWD"),
                buf_expr(existing.as_os_str().as_bytes()),
                named_symbol("RENAME_NOREPLACE"),
            ],
            -1,
        );
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::Read("/src/file".into()),
                ProgramAction::Write("/src/file".into()),
                ProgramAction::Read(existing.clone()),
                ProgramAction::Create(existing.clone()),
                ProgramAction::Write(existing),
                ProgramAction::RequireSameMount("/src".into(), temp_dir.path().to_owned()),
                ProgramAction::Syscalls(["renameat2".into()].into()),
            ]
        );
    }

    #[test]
    fn mknod_existing_reads() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let existing = temp_dir.path().join("existing");
        File::create(&existing).unwrap();
        // Failing with EEXIST, which the parser keeps
        let sc = make_syscall(
            "mknod",
            vec![
                buf_expr(existing.as_os_str().as_bytes()),
                binary_or_flags(&["S_IFIFO"]),
                int_literal(0),
            ],
            -1,
        );
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::Read(existing.clone()),
                ProgramAction::Create(existing),
                ProgramAction::Syscalls(["mknod".into()].into()),
            ]
        );
    }

    #[test]
    fn lsetxattr_failed_symlink_writes() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let link = temp_dir.path().join("link");
        unix::fs::symlink(temp_dir.path().join("missing"), &link).unwrap();
        // Failing with EEXIST on an existing attribute, after the mount write check
        let lsetxattr = make_syscall(
            "lsetxattr",
            vec![
                buf_expr(link.as_os_str().as_bytes()),
                buf_expr(b"trusted.test"),
                buf_expr(b""),
                int_literal(0),
                named_symbol("XATTR_CREATE"),
            ],
            -1,
        );
        assert_eq!(
            summarize_syscall(lsetxattr),
            vec![
                ProgramAction::Write(link),
                ProgramAction::Syscalls(["lsetxattr".into()].into()),
            ]
        );
    }

    #[test]
    fn lchown_trailing_slash_follows() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        fs::create_dir(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        let lchown = |path: &[u8]| {
            syscall(
                "lchown",
                vec![buf_expr(path), int_literal(0), int_literal(0)],
            )
        };
        let link_bytes = link.as_os_str().as_bytes();
        assert_eq!(
            summarize([Ok(lchown(link_bytes))], &[], program_state()).unwrap(),
            vec![
                ProgramAction::Write(link.clone()),
                ProgramAction::Syscalls(["lchown".into()].into()),
            ]
        );
        for suffix in [&b"/"[..], b"/."] {
            assert_eq!(
                summarize(
                    [Ok(lchown(&[link_bytes, suffix].concat()))],
                    &[],
                    program_state()
                )
                .unwrap(),
                vec![
                    ProgramAction::Read(link.clone()),
                    ProgramAction::Write(target.clone()),
                    ProgramAction::Syscalls(["lchown".into()].into()),
                ]
            );
        }
    }

    #[test]
    fn read_path_follows_symlink() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        let link_bytes = link.as_os_str().as_bytes();
        for (name, args) in [
            ("access", vec![buf_expr(link_bytes), named_symbol("R_OK")]),
            (
                "faccessat",
                vec![
                    fd_expr(3, temp_dir.path()),
                    buf_expr(b"link"),
                    named_symbol("R_OK"),
                ],
            ),
            (
                "getxattr",
                vec![
                    buf_expr(link_bytes),
                    buf_expr(b"user.test"),
                    buf_expr(b"value"),
                    int_literal(4096),
                ],
            ),
            (
                "listxattr",
                vec![buf_expr(link_bytes), buf_expr(b""), int_literal(4096)],
            ),
            (
                "statfs",
                vec![
                    buf_expr(link_bytes),
                    Expression::Struct(HashMap::from([(
                        "f_type".to_owned(),
                        named_symbol("TMPFS_MAGIC"),
                    )])),
                ],
            ),
        ] {
            assert_eq!(
                summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                vec![
                    ProgramAction::Read(link.clone()),
                    ProgramAction::Read(target.clone()),
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }

    #[test]
    fn read_symlink_no_follow() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        fs::create_dir(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        // A trailing slash follows the link
        for (suffix, path_actions) in [
            (&b""[..], vec![ProgramAction::Read(link.clone())]),
            (
                b"/",
                vec![
                    ProgramAction::Read(link.clone()),
                    ProgramAction::Read(target.clone()),
                ],
            ),
        ] {
            let link_bytes = [link.as_os_str().as_bytes(), suffix].concat();
            for (name, args) in [
                (
                    "lgetxattr",
                    vec![
                        buf_expr(&link_bytes),
                        buf_expr(b"trusted.test"),
                        buf_expr(b"value"),
                        int_literal(4096),
                    ],
                ),
                (
                    "llistxattr",
                    vec![buf_expr(&link_bytes), buf_expr(b""), int_literal(4096)],
                ),
                (
                    "readlink",
                    vec![
                        buf_expr(&link_bytes),
                        buf_expr(b"target"),
                        int_literal(4096),
                    ],
                ),
                (
                    "readlinkat",
                    vec![
                        fd_expr(3, temp_dir.path()),
                        buf_expr(&[&b"link"[..], suffix].concat()),
                        buf_expr(b"target"),
                        int_literal(4096),
                    ],
                ),
            ] {
                // Reading the directory as a symlink fails
                let sc = if suffix.is_empty() || !name.starts_with("readlink") {
                    make_syscall(name, args, 0)
                } else {
                    make_failed_syscall(name, args, "EINVAL")
                };
                assert_eq!(
                    summarize_syscall(sc),
                    [
                        path_actions.clone(),
                        vec![ProgramAction::Syscalls([name.into()].into())]
                    ]
                    .concat()
                );
            }
        }
    }

    #[test]
    fn read_symlink_follow_flags() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        File::create(&target).unwrap();
        unix::fs::symlink(&target, &link).unwrap();
        let dir_fd = fd_expr(3, temp_dir.path());
        for (follow, path_actions) in [
            (false, vec![ProgramAction::Read(link.clone())]),
            (
                true,
                vec![
                    ProgramAction::Read(link.clone()),
                    ProgramAction::Read(target.clone()),
                ],
            ),
        ] {
            // Flags with the given flag added when enabled
            let flags_with = |base: &[&str], flag: &str, enabled: bool| {
                let mut flags = base.to_vec();
                flags.extend(enabled.then_some(flag));
                match flags.as_slice() {
                    [] => int_literal(0),
                    [single] => named_symbol(single),
                    _ => binary_or_flags(&flags),
                }
            };
            for (name, args) in [
                (
                    "faccessat2",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        named_symbol("R_OK"),
                        flags_with(&["AT_EACCESS"], "AT_SYMLINK_NOFOLLOW", !follow),
                    ],
                ),
                (
                    "fanotify_mark",
                    vec![
                        fd_expr(4, "anon_inode:[fanotify]"),
                        flags_with(&["FAN_MARK_ADD"], "FAN_MARK_DONT_FOLLOW", !follow),
                        named_symbol("FAN_MODIFY"),
                        dir_fd.clone(),
                        buf_expr(b"link"),
                    ],
                ),
                (
                    "file_getattr",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        Expression::Struct(HashMap::from([(
                            "fa_xflags".to_owned(),
                            int_literal(0),
                        )])),
                        int_literal(24),
                        flags_with(&[], "AT_SYMLINK_NOFOLLOW", !follow),
                    ],
                ),
                (
                    "getxattrat",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        flags_with(&[], "AT_SYMLINK_NOFOLLOW", !follow),
                        buf_expr(b"user.test"),
                        Expression::Struct(HashMap::from([
                            ("value".to_owned(), buf_expr(b"value")),
                            ("size".to_owned(), int_literal(4096)),
                            ("flags".to_owned(), int_literal(0)),
                        ])),
                        int_literal(16),
                    ],
                ),
                (
                    "inotify_add_watch",
                    vec![
                        fd_expr(4, "anon_inode:inotify"),
                        buf_expr(link.as_os_str().as_bytes()),
                        flags_with(&["IN_MODIFY"], "IN_DONT_FOLLOW", !follow),
                    ],
                ),
                (
                    "listxattrat",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        flags_with(&[], "AT_SYMLINK_NOFOLLOW", !follow),
                        buf_expr(b""),
                        int_literal(4096),
                    ],
                ),
                (
                    "name_to_handle_at",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        Expression::Struct(HashMap::from([(
                            "handle_type".to_owned(),
                            int_literal(1),
                        )])),
                        Expression::Collection {
                            complement: false,
                            values: vec![(None, int_literal(42))],
                        },
                        flags_with(&["AT_HANDLE_FID"], "AT_SYMLINK_FOLLOW", follow),
                    ],
                ),
                (
                    "statx",
                    vec![
                        dir_fd.clone(),
                        buf_expr(b"link"),
                        flags_with(&["AT_STATX_SYNC_AS_STAT"], "AT_SYMLINK_NOFOLLOW", !follow),
                        named_symbol("STATX_ALL"),
                        Expression::Struct(HashMap::from([(
                            "stx_mask".to_owned(),
                            named_symbol("STATX_ALL"),
                        )])),
                    ],
                ),
            ] {
                assert_eq!(
                    summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                    [
                        path_actions.clone(),
                        vec![ProgramAction::Syscalls([name.into()].into())]
                    ]
                    .concat()
                );
            }
        }
    }

    #[test]
    fn readlink_non_symlink_reads() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Failing with EINVAL on an entry that is not a symlink, which the parser keeps
        let sc = make_failed_syscall(
            "readlink",
            vec![
                buf_expr(b"/var/lib/file"),
                named_symbol("NULL"),
                int_literal(4096),
            ],
            "EINVAL",
        );
        assert_eq!(
            summarize_syscall(sc),
            vec![
                ProgramAction::Read("/var/lib/file".into()),
                ProgramAction::Syscalls(["readlink".into()].into()),
            ]
        );
    }

    #[test]
    fn access_check_modes() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path().to_owned();
        let file = dir.join("file");
        File::create(&file).unwrap();
        let dev_null = PathBuf::from("/dev/null");
        for (path, mode, path_actions) in [
            (
                &file,
                named_symbol("F_OK"),
                vec![ProgramAction::Read(file.clone())],
            ),
            (
                &file,
                named_symbol("W_OK"),
                vec![
                    ProgramAction::Read(file.clone()),
                    ProgramAction::Write(file.clone()),
                ],
            ),
            (
                &file,
                named_symbol("X_OK"),
                vec![
                    ProgramAction::Read(file.clone()),
                    ProgramAction::Exec(file.clone()),
                ],
            ),
            // Execution of a directory checks its search permission only
            (
                &dir,
                binary_or_flags(&["R_OK", "W_OK", "X_OK"]),
                vec![
                    ProgramAction::Read(dir.clone()),
                    ProgramAction::Write(dir.clone()),
                ],
            ),
            // A device stays writable on a read-only mount, and can not be executed
            (
                &dev_null,
                binary_or_flags(&["R_OK", "W_OK", "X_OK"]),
                vec![ProgramAction::Read(dev_null.clone())],
            ),
        ] {
            let path = buf_expr(path.as_os_str().as_bytes());
            for (name, args) in [
                ("access", vec![path.clone(), mode.clone()]),
                (
                    "faccessat",
                    vec![named_symbol("AT_FDCWD"), path.clone(), mode.clone()],
                ),
                (
                    "faccessat2",
                    vec![
                        named_symbol("AT_FDCWD"),
                        path.clone(),
                        mode.clone(),
                        int_literal(0),
                    ],
                ),
            ] {
                assert_eq!(
                    summarize([Ok(syscall(name, args))], &[], program_state()).unwrap(),
                    [
                        path_actions.clone(),
                        vec![ProgramAction::Syscalls([name.into()].into())]
                    ]
                    .concat()
                );
            }
        }

        // The link itself, not its target, when not followed
        let link = dir.join("link");
        unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(
            summarize_syscall(make_syscall(
                "faccessat2",
                vec![
                    named_symbol("AT_FDCWD"),
                    buf_expr(link.as_os_str().as_bytes()),
                    named_symbol("X_OK"),
                    named_symbol("AT_SYMLINK_NOFOLLOW"),
                ],
                0,
            )),
            vec![
                ProgramAction::Read(link),
                ProgramAction::Syscalls(["faccessat2".into()].into()),
            ]
        );
    }

    #[test]
    fn fanotify_mark_flush_ignores_path() {
        let _ = simple_logger::SimpleLogger::new().init();

        // An unreadable path is printed as its address
        for path in [buf_expr(b"/etc"), int_literal(0x1234)] {
            assert_eq!(
                summarize_syscall(make_syscall(
                    "fanotify_mark",
                    vec![
                        fd_expr(3, "anon_inode:[fanotify]"),
                        named_symbol("FAN_MARK_FLUSH"),
                        int_literal(0),
                        named_symbol("AT_FDCWD"),
                        path,
                    ],
                    0,
                )),
                vec![ProgramAction::Syscalls(["fanotify_mark".into()].into())]
            );
        }
    }

    #[test]
    fn fanotify_mark_mount_acts_on_host_mount_namespace() {
        let _ = simple_logger::SimpleLogger::new().init();

        for (flags, mut expected) in [
            (
                &["FAN_MARK_ADD", "FAN_MARK_MOUNT"][..],
                vec![ProgramAction::HostMountNamespace],
            ),
            // FAN_MARK_MNTNS, as printed by strace 6.13
            (
                &["FAN_MARK_ADD", "FAN_MARK_MOUNT", "FAN_MARK_FILESYSTEM"],
                vec![],
            ),
            (&["FAN_MARK_ADD", "FAN_MARK_MNTNS"], vec![]),
        ] {
            expected.extend([
                ProgramAction::Read("/etc".into()),
                ProgramAction::Syscalls(["fanotify_mark".into()].into()),
            ]);
            assert_eq!(
                summarize_syscall(make_syscall(
                    "fanotify_mark",
                    vec![
                        fd_expr(3, "anon_inode:[fanotify]"),
                        binary_or_flags(flags),
                        named_symbol("FAN_MODIFY"),
                        named_symbol("AT_FDCWD"),
                        buf_expr(b"/etc"),
                    ],
                    0,
                )),
                expected
            );
        }
    }
}
