//! Summarize program syscalls into higher level action

use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fmt::{self, Display},
    num::NonZeroU16,
    ops::{Add, RangeInclusive, Sub},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    slice,
    sync::LazyLock,
};

use crate::{
    strace::{
        BufferExpression, BufferType, Expression, IntegerExpression, IntegerExpressionValue,
        Syscall,
    },
    systemd::{SocketFamily, SocketProtocol},
};

/// A high level program runtime action
/// This does *not* map 1-1 with a syscall, and does *not* necessarily respect chronology
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum ProgramAction {
    /// Path was accessed (open, stat'ed, read...)
    Read(PathBuf),
    /// Path was written to (data, metadata, path removal...)
    Write(PathBuf),
    /// Path was created
    Create(PathBuf),
    /// Network (socket) activity
    NetworkActivity(NetworkActivity),
    /// Memory mapping with write and execute bits
    WriteExecuteMemoryMapping,
    /// Set scheduler to a real time one
    SetRealtimeScheduler,
    /// Inhibit suspend
    Wakeup,
    /// Create special files
    MknodSpecial,
    /// Set privileged timer alarm
    SetAlarm,
    /// Names of the syscalls made by the program
    Syscalls(HashSet<String>),
}

/// Network (socket) activity
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkActivity {
    pub af: SetSpecifier<SocketFamily>,
    pub proto: SetSpecifier<SocketProtocol>,
    pub kind: SetSpecifier<NetworkActivityKind>,
    pub local_port: CountableSetSpecifier<NetworkPort>,
}

/// Quantify something that is done or denied
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum SetSpecifier<T> {
    None,
    One(T),
    Some(Vec<T>),
    All,
}

impl<T: Eq + Clone> SetSpecifier<T> {
    fn contains_one(&self, needle: &T) -> bool {
        match self {
            Self::None => false,
            Self::One(e) => e == needle,
            Self::Some(es) => es.contains(needle),
            Self::All => true,
        }
    }

    pub(crate) fn intersects(&self, other: &Self) -> bool {
        match self {
            Self::None => false,
            Self::One(e) => other.contains_one(e),
            Self::Some(es) => es.iter().any(|e| other.contains_one(e)),
            Self::All => !matches!(other, Self::None),
        }
    }

    pub(crate) fn elements(&self) -> &[T] {
        match self {
            SetSpecifier::None => &[],
            SetSpecifier::One(e) => slice::from_ref(e),
            SetSpecifier::Some(es) => es.as_slice(),
            SetSpecifier::All => unimplemented!(),
        }
    }
}

pub(crate) trait ValueCounted {
    fn value_count() -> usize;

    fn min_value() -> Self;

    fn max_value() -> Self;

    fn one() -> Self;
}

/// Quantify something that is done or denied
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum CountableSetSpecifier<T> {
    None,
    One(T),
    // Elements must be ordered
    Some(Vec<T>),
    // Elements must be ordered
    AllExcept(Vec<T>),
    All,
}

impl<T: Eq + Ord + Clone + Display + ValueCounted + Sub<Output = T> + Add<Output = T>>
    CountableSetSpecifier<T>
{
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
                Self::All => excs.len() < T::value_count(),
            },
            Self::All => !matches!(other, Self::None),
        }
    }

    /// Remove a single element from the set
    /// The element to remove **must** be in the set, otherwise may panic
    #[expect(clippy::unwrap_used)]
    pub(crate) fn remove(&mut self, to_rm: &T) {
        debug_assert!(self.contains_one(to_rm));
        match self {
            Self::None => unreachable!(),
            Self::One(_) => {
                *self = Self::None;
            }
            Self::Some(es) => {
                let idx = es.iter().position(|e| e == to_rm).unwrap();
                es.remove(idx);
            }
            Self::AllExcept(excs) => {
                let idx = excs.binary_search(to_rm).unwrap_err();
                excs.insert(idx, to_rm.to_owned());
            }
            Self::All => {
                *self = Self::AllExcept(vec![to_rm.to_owned()]);
            }
        }
    }

    pub(crate) fn ranges(&self) -> Vec<RangeInclusive<T>> {
        match self {
            CountableSetSpecifier::None => vec![],
            CountableSetSpecifier::One(e) => vec![e.to_owned()..=e.to_owned()],
            CountableSetSpecifier::Some(es) => {
                // Build single element ranges, we could merge adjacent elements, but
                // the effort has very little upsides
                es.iter().map(|e| e.to_owned()..=e.to_owned()).collect()
            }
            CountableSetSpecifier::AllExcept(excs) => {
                let mut ranges = Vec::with_capacity(excs.len() + 1);
                let mut start = None;
                for exc in excs {
                    if *exc != T::min_value() {
                        let cur_start = start.unwrap_or_else(|| T::min_value());
                        let cur_end = exc.to_owned() - T::one();
                        let r = cur_start..=cur_end;
                        if !r.is_empty() {
                            ranges.push(r);
                        }
                    }
                    if *exc == T::max_value() {
                        start = None;
                    } else {
                        start = Some(exc.to_owned() + T::one());
                    }
                }
                if let Some(start) = start {
                    let r = start..=T::max_value();
                    if !r.is_empty() {
                        ranges.push(r);
                    }
                }
                ranges
            }
            CountableSetSpecifier::All => vec![T::min_value()..=T::max_value()],
        }
    }
}

/// Socket activity
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum NetworkActivityKind {
    SocketCreation,
    Bind,
    // TODO
    // Connect,
    // Send,
    // Recv,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NetworkPort(NonZeroU16);

impl ValueCounted for NetworkPort {
    fn value_count() -> usize {
        // 0 is excluded
        u16::MAX as usize - u16::MIN as usize
    }

    fn one() -> Self {
        #[expect(clippy::unwrap_used)]
        Self(1_u16.try_into().unwrap())
    }

    fn min_value() -> Self {
        #[expect(clippy::unwrap_used)]
        Self(1_u16.try_into().unwrap())
    }

    fn max_value() -> Self {
        #[expect(clippy::unwrap_used)]
        Self(u16::MAX.try_into().unwrap())
    }
}

impl Sub<NetworkPort> for NetworkPort {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        #[expect(clippy::unwrap_used)]
        Self(self.0.get().sub(rhs.0.get()).try_into().unwrap())
    }
}

impl Add<NetworkPort> for NetworkPort {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        #[expect(clippy::unwrap_used)]
        Self(self.0.get().add(rhs.0.get()).try_into().unwrap())
    }
}

impl Display for NetworkPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Meta structure to group syscalls that have similar summary handling
/// and store argument indexes
enum SyscallInfo {
    Mknod {
        mode_idx: usize,
    },
    Mmap {
        prot_idx: usize,
    },
    Network {
        sockaddr_idx: usize,
    },
    Open {
        relfd_idx: Option<usize>,
        path_idx: usize,
        flags_idx: usize,
    },
    Rename {
        relfd_src_idx: Option<usize>,
        path_src_idx: usize,
        relfd_dst_idx: Option<usize>,
        path_dst_idx: usize,
        flags_idx: Option<usize>,
    },
    SetScheduler,
    Socket,
    StatFd {
        fd_idx: usize,
    },
    StatPath {
        relfd_idx: Option<usize>,
        path_idx: usize,
    },
}

//
// For some reference on syscalls, see:
// - https://man7.org/linux/man-pages/man2/syscalls.2.html
// - https://filippo.io/linux-syscall-table/
// - https://linasm.sourceforge.net/docs/syscalls/filesystem.php
//
static SYSCALL_MAP: LazyLock<HashMap<&'static str, SyscallInfo>> = LazyLock::new(|| {
    HashMap::from([
        // mknod
        ("mknod", SyscallInfo::Mknod { mode_idx: 1 }),
        ("mknodat", SyscallInfo::Mknod { mode_idx: 2 }),
        // mmap
        ("mmap", SyscallInfo::Mmap { prot_idx: 2 }),
        ("mmap2", SyscallInfo::Mmap { prot_idx: 2 }),
        ("shmat", SyscallInfo::Mmap { prot_idx: 2 }),
        ("mprotect", SyscallInfo::Mmap { prot_idx: 2 }),
        ("pkey_mprotect", SyscallInfo::Mmap { prot_idx: 2 }),
        // network
        ("connect", SyscallInfo::Network { sockaddr_idx: 1 }),
        ("bind", SyscallInfo::Network { sockaddr_idx: 1 }),
        ("recvfrom", SyscallInfo::Network { sockaddr_idx: 4 }),
        ("sendto", SyscallInfo::Network { sockaddr_idx: 4 }),
        // TODO recvmsg/sendmsg

        // open
        (
            "open",
            SyscallInfo::Open {
                relfd_idx: None,
                path_idx: 0,
                flags_idx: 1,
            },
        ),
        (
            "openat",
            SyscallInfo::Open {
                relfd_idx: Some(0),
                path_idx: 1,
                flags_idx: 2,
            },
        ),
        // rename
        (
            "rename",
            SyscallInfo::Rename {
                relfd_src_idx: None,
                path_src_idx: 0,
                relfd_dst_idx: None,
                path_dst_idx: 1,
                flags_idx: None,
            },
        ),
        (
            "renameat",
            SyscallInfo::Rename {
                relfd_src_idx: Some(0),
                path_src_idx: 1,
                relfd_dst_idx: Some(2),
                path_dst_idx: 3,
                flags_idx: None,
            },
        ),
        (
            "renameat2",
            SyscallInfo::Rename {
                relfd_src_idx: Some(0),
                path_src_idx: 1,
                relfd_dst_idx: Some(2),
                path_dst_idx: 3,
                flags_idx: Some(4),
            },
        ),
        // set scheduler
        ("sched_setscheduler", SyscallInfo::SetScheduler),
        // socket
        ("socket", SyscallInfo::Socket),
        // stat fd
        ("fstat", SyscallInfo::StatFd { fd_idx: 0 }),
        ("getdents", SyscallInfo::StatFd { fd_idx: 0 }),
        // stat path
        (
            "stat",
            SyscallInfo::StatPath {
                relfd_idx: None,
                path_idx: 0,
            },
        ),
        (
            "lstat",
            SyscallInfo::StatPath {
                relfd_idx: None,
                path_idx: 0,
            },
        ),
        (
            "newfstatat",
            SyscallInfo::StatPath {
                relfd_idx: Some(0),
                path_idx: 1,
            },
        ),
    ])
});

/// Resolve relative path if possible, and normalize it
fn resolve_path(path: &Path, relfd_idx: Option<usize>, syscall: &Syscall) -> Option<PathBuf> {
    let path = if path.is_relative() {
        let metadata = relfd_idx
            .and_then(|idx| syscall.args.get(idx))
            .and_then(|a| a.metadata());
        if let Some(metadata) = metadata {
            if is_fd_pseudo_path(metadata) {
                return None;
            }
            let rel_path = PathBuf::from(OsStr::from_bytes(metadata));
            rel_path.join(path)
        } else {
            return None;
        }
    } else {
        path.to_path_buf()
    };
    // TODO APPROXIMATION
    // canonicalize relies on the FS state at profiling time which may have changed
    // and may follow links, therefore lead to different filesystem actions
    Some(path.canonicalize().unwrap_or(path))
}

#[expect(clippy::unwrap_used)]
static FD_PSEUDO_PATH_REGEX: LazyLock<regex::bytes::Regex> =
    LazyLock::new(|| regex::bytes::Regex::new(r"^[a-z]+:\[[0-9a-z]+\]/?$").unwrap());

fn is_fd_pseudo_path(path: &[u8]) -> bool {
    FD_PSEUDO_PATH_REGEX.is_match(path)
}

/// Extract path for socket address structure if it's a non abstract one
fn socket_address_uds_path(
    members: &HashMap<String, Expression>,
    syscall: &Syscall,
) -> Option<PathBuf> {
    if let Some(Expression::Buffer(BufferExpression {
        value: b,
        type_: BufferType::Unknown,
    })) = members.get("sun_path")
    {
        resolve_path(&PathBuf::from(OsStr::from_bytes(b)), None, syscall)
    } else {
        None
    }
}

#[expect(clippy::too_many_lines)]
pub(crate) fn summarize<I>(syscalls: I) -> anyhow::Result<Vec<ProgramAction>>
where
    I: IntoIterator<Item = anyhow::Result<Syscall>>,
{
    let mut actions = Vec::new();
    let mut stats: HashMap<String, u64> = HashMap::new();
    // Keep known socket protocols (per process) for bind handling, we don't care for the socket closings
    // because the fd will be reused or never bound again
    let mut known_sockets_proto: HashMap<(u32, i128), SocketProtocol> = HashMap::new();
    for syscall in syscalls {
        let syscall = syscall?;
        log::trace!("{syscall:?}");
        stats
            .entry(syscall.name.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        let name = syscall.name.as_str();

        match SYSCALL_MAP.get(name) {
            Some(SyscallInfo::Open {
                relfd_idx,
                path_idx,
                flags_idx,
            }) => {
                let (mut path, flags) = if let (
                    Some(Expression::Buffer(BufferExpression {
                        value: b,
                        type_: BufferType::Unknown,
                    })),
                    Some(Expression::Integer(IntegerExpression { value: e, .. })),
                ) =
                    (syscall.args.get(*path_idx), syscall.args.get(*flags_idx))
                {
                    (PathBuf::from(OsStr::from_bytes(b)), e)
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };

                path = if let Some(path) = resolve_path(&path, *relfd_idx, &syscall) {
                    path
                } else {
                    continue;
                };

                if flags.is_flag_set("O_CREAT") {
                    actions.push(ProgramAction::Create(path.clone()));
                }
                if flags.is_flag_set("O_WRONLY")
                    || flags.is_flag_set("O_RDWR")
                    || flags.is_flag_set("O_TRUNC")
                {
                    actions.push(ProgramAction::Write(path.clone()));
                }
                if !flags.is_flag_set("O_WRONLY") {
                    actions.push(ProgramAction::Read(path));
                }
            }
            Some(SyscallInfo::Rename {
                relfd_src_idx,
                path_src_idx,
                relfd_dst_idx,
                path_dst_idx,
                flags_idx,
            }) => {
                let (path_src, path_dst) = if let (
                    Some(Expression::Buffer(BufferExpression {
                        value: b1,
                        type_: BufferType::Unknown,
                    })),
                    Some(Expression::Buffer(BufferExpression {
                        value: b2,
                        type_: BufferType::Unknown,
                    })),
                ) = (
                    syscall.args.get(*path_src_idx),
                    syscall.args.get(*path_dst_idx),
                ) {
                    (
                        PathBuf::from(OsStr::from_bytes(b1)),
                        PathBuf::from(OsStr::from_bytes(b2)),
                    )
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };

                let (Some(path_src), Some(path_dst)) = (
                    resolve_path(&path_src, *relfd_src_idx, &syscall),
                    resolve_path(&path_dst, *relfd_dst_idx, &syscall),
                ) else {
                    continue;
                };

                let exchange = if let Some(flags_idx) = flags_idx {
                    let Some(Expression::Integer(IntegerExpression { value: flags, .. })) =
                        syscall.args.get(*flags_idx)
                    else {
                        anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                    };

                    flags.is_flag_set("RENAME_EXCHANGE")
                } else {
                    false
                };

                actions.push(ProgramAction::Read(path_src.clone()));
                actions.push(ProgramAction::Write(path_src.clone()));
                if exchange {
                    actions.push(ProgramAction::Read(path_dst.clone()));
                } else {
                    actions.push(ProgramAction::Create(path_dst.clone()));
                }
                actions.push(ProgramAction::Write(path_dst.clone()));
            }
            Some(SyscallInfo::StatFd { fd_idx }) => {
                let mut path = syscall
                    .args
                    .get(*fd_idx)
                    .and_then(|a| a.metadata())
                    .map(|m| PathBuf::from(OsStr::from_bytes(m)))
                    .ok_or_else(|| anyhow::anyhow!("Unexpected args for {name}"))?;
                path = if let Some(path) = resolve_path(&path, None, &syscall) {
                    path
                } else {
                    continue;
                };
                actions.push(ProgramAction::Read(path));
            }
            Some(SyscallInfo::StatPath {
                relfd_idx,
                path_idx,
            }) => {
                let mut path = if let Some(Expression::Buffer(BufferExpression {
                    value: b,
                    type_: BufferType::Unknown,
                })) = syscall.args.get(*path_idx)
                {
                    PathBuf::from(OsStr::from_bytes(b))
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };
                path = if let Some(path) = resolve_path(&path, *relfd_idx, &syscall) {
                    path
                } else {
                    continue;
                };
                actions.push(ProgramAction::Read(path));
            }
            Some(SyscallInfo::Network { sockaddr_idx }) => {
                let (af, addr) =
                    if let Some(Expression::Struct(members)) = syscall.args.get(*sockaddr_idx) {
                        let Some(Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedConst(af),
                            ..
                        })) = members.get("sa_family")
                        else {
                            anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                        };
                        (af.as_str(), members)
                    } else {
                        // Can be NULL in some cases, ie AF_NETLINK sockets
                        continue;
                    };

                #[expect(clippy::single_match)]
                match af {
                    "AF_UNIX" => {
                        if let Some(path) = socket_address_uds_path(addr, &syscall) {
                            actions.push(ProgramAction::Read(path));
                        };
                    }
                    _ => (),
                }

                if name == "bind" {
                    let Some(Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(fd),
                        ..
                    })) = syscall.args.first()
                    else {
                        anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                    };
                    let af = af
                        .parse()
                        .map_err(|()| anyhow::anyhow!("Unable to parse socket family {af:?}"))?;
                    let local_port = match addr
                        .iter()
                        .find_map(|(k, v)| k.ends_with("_port").then_some(v))
                    {
                        Some(Expression::Macro {
                            name: macro_name,
                            args,
                        }) if macro_name == "htons" => match args.first() {
                            Some(Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(port_val),
                                ..
                            })) =>
                            {
                                #[expect(
                                    clippy::cast_possible_truncation,
                                    clippy::cast_sign_loss,
                                    clippy::unwrap_used
                                )]
                                CountableSetSpecifier::One(NetworkPort(
                                    (*port_val as u16).try_into().unwrap(),
                                ))
                            }
                            _ => todo!(),
                        },
                        _ => CountableSetSpecifier::None,
                    };
                    if let Some(proto) = known_sockets_proto.get(&(syscall.pid, *fd)) {
                        actions.push(ProgramAction::NetworkActivity(NetworkActivity {
                            af: SetSpecifier::One(af),
                            proto: SetSpecifier::One(proto.to_owned()),
                            kind: SetSpecifier::One(NetworkActivityKind::Bind),
                            local_port,
                        }));
                    }
                }
            }
            Some(SyscallInfo::SetScheduler) => {
                let Some(Expression::Integer(IntegerExpression { value: policy, .. })) =
                    syscall.args.get(1)
                else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };
                if policy.is_flag_set("SCHED_FIFO") | policy.is_flag_set("SCHED_RR") {
                    actions.push(ProgramAction::SetRealtimeScheduler);
                }
            }
            Some(SyscallInfo::Socket) => {
                let af = if let Some(Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedConst(af),
                    ..
                })) = syscall.args.first()
                {
                    af.parse()
                        .map_err(|()| anyhow::anyhow!("Unable to parse socket family {af:?}"))?
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };

                let flags = if let Some(Expression::Integer(IntegerExpression { value, .. })) =
                    syscall.args.get(1)
                {
                    value.flags()
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };
                let proto_flag =
                    flags
                        .iter()
                        .find(|f| f.starts_with("SOCK_"))
                        .ok_or_else(|| {
                            anyhow::anyhow!("Unable to parse socket protocol from flags {flags:?}")
                        })?;
                let proto = proto_flag.parse::<SocketProtocol>().map_err(|_e| {
                    anyhow::anyhow!("Unable to parse socket protocol {proto_flag:?}")
                })?;
                known_sockets_proto.insert((syscall.pid, syscall.ret_val), proto.clone());

                actions.push(ProgramAction::NetworkActivity(NetworkActivity {
                    af: SetSpecifier::One(af),
                    proto: SetSpecifier::One(proto),
                    kind: SetSpecifier::One(NetworkActivityKind::SocketCreation),
                    local_port: CountableSetSpecifier::All,
                }));
            }
            Some(SyscallInfo::Mknod { mode_idx }) => {
                const PRIVILEGED_ST_MODES: [&str; 2] = ["S_IFBLK", "S_IFCHR"];
                if let Some(Expression::Integer(mode)) = syscall.args.get(*mode_idx) {
                    if PRIVILEGED_ST_MODES
                        .iter()
                        .any(|pm| mode.value.is_flag_set(pm))
                    {
                        actions.push(ProgramAction::MknodSpecial);
                    }
                } else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                }
            }
            Some(SyscallInfo::Mmap { prot_idx }) => {
                let Some(Expression::Integer(IntegerExpression { value: prot, .. })) =
                    syscall.args.get(*prot_idx)
                else {
                    anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                };
                if prot.is_flag_set("PROT_WRITE") && prot.is_flag_set("PROT_EXEC") {
                    actions.push(ProgramAction::WriteExecuteMemoryMapping);
                }
            }
            None => match name {
                "epoll_ctl" => {
                    if syscall.args.get(1).is_some_and(|op| {
                        matches!(op, Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedConst(op_name),
                            ..
                        }) if op_name == "EPOLL_CTL_ADD")
                    }) {
                        // Get the event
                        let evt_arg = syscall
                            .args
                            .get(3)
                            .ok_or_else(|| anyhow::anyhow!("Missing epoll event argument"))?;
                        let evt_flags = if let Expression::Struct(evt_struct) = evt_arg {
                            let evt_member = evt_struct.get("events").ok_or_else(|| {
                                anyhow::anyhow!("Missing epoll events struct member")
                            })?;
                            if let Expression::Integer(ie) = evt_member {
                                ie
                            } else {
                                anyhow::bail!("Invalid epoll struct member");
                            }
                        } else {
                            anyhow::bail!("Invalid epoll event argument");
                        };
                        if evt_flags.value.is_flag_set("EPOLLWAKEUP") {
                            actions.push(ProgramAction::Wakeup);
                        }
                    }
                }
                "timer_create" => {
                    const PRIVILEGED_CLOCK_NAMES: [&str; 2] =
                        ["CLOCK_REALTIME_ALARM", "CLOCK_BOOTTIME_ALARM"];
                    let Some(Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst(clock_name),
                        ..
                    })) = syscall.args.first()
                    else {
                        anyhow::bail!("Unexpected args for {}: {:?}", name, syscall.args);
                    };
                    if PRIVILEGED_CLOCK_NAMES.contains(&clock_name.as_str()) {
                        actions.push(ProgramAction::SetAlarm);
                    }
                }
                _ => {}
            },
        }
    }

    // Almost free optimization
    actions.dedup();

    // Create single action with all syscalls for efficient handling of seccomp filters
    actions.push(ProgramAction::Syscalls(stats.keys().cloned().collect()));

    // Report stats
    let mut syscall_names = stats.keys().collect::<Vec<_>>();
    syscall_names.sort();
    for syscall_name in syscall_names {
        #[expect(clippy::unwrap_used)]
        let count = stats.get(syscall_name).unwrap();
        log::debug!("{:24} {: >12}", format!("{syscall_name}:"), count);
    }

    Ok(actions)
}

#[expect(clippy::unreadable_literal, clippy::shadow_unrelated)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::strace::*;

    #[test]
    fn test_is_socket_or_pipe_pseudo_path() {
        assert!(!is_fd_pseudo_path("plop".as_bytes()));
        assert!(is_fd_pseudo_path("pipe:[12334]".as_bytes()));
        assert!(is_fd_pseudo_path("socket:[1234]/".as_bytes()));
    }

    #[test]
    fn test_relative_rename() {
        let _ = simple_logger::SimpleLogger::new().init();

        let temp_dir_src = tempfile::tempdir().unwrap();
        let temp_dir_dst = tempfile::tempdir().unwrap();
        let syscalls = [Ok(Syscall {
            pid: 1068781,
            rel_ts: 0.000083,
            name: "renameat".to_owned(),
            args: vec![
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedConst("AT_FDCWD".to_owned()),
                    metadata: Some(temp_dir_src.path().as_os_str().as_bytes().to_vec()),
                }),
                Expression::Buffer(BufferExpression {
                    value: "a".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedConst("AT_FDCWD".to_owned()),
                    metadata: Some(temp_dir_dst.path().as_os_str().as_bytes().to_vec()),
                }),
                Expression::Buffer(BufferExpression {
                    value: "b".as_bytes().to_vec(),
                    type_: BufferType::Unknown,
                }),
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedConst("RENAME_NOREPLACE".to_owned()),
                    metadata: None,
                }),
            ],
            ret_val: 0,
        })];
        assert_eq!(
            summarize(syscalls).unwrap(),
            vec![
                ProgramAction::Read(temp_dir_src.path().join("a")),
                ProgramAction::Write(temp_dir_src.path().join("a")),
                ProgramAction::Create(temp_dir_dst.path().join("b")),
                ProgramAction::Write(temp_dir_dst.path().join("b")),
                ProgramAction::Syscalls(["renameat".to_owned()].into())
            ]
        );
    }

    #[test]
    fn test_connect_uds() {
        let _ = simple_logger::SimpleLogger::new().init();

        let syscalls = [Ok(Syscall {
            pid: 598056,
            rel_ts: 0.000036,
            name: "connect".to_owned(),
            args: vec![
                Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::Literal(4),
                    metadata: Some("/run/user/1000/systemd/private".as_bytes().to_vec()),
                }),
                Expression::Struct(HashMap::from([
                    (
                        "sa_family".to_owned(),
                        Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedConst("AF_UNIX".to_owned()),
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
            ret_val: 0,
        })];
        assert_eq!(
            summarize(syscalls).unwrap(),
            vec![
                ProgramAction::Read("/run/user/1000/systemd/private".into()),
                ProgramAction::Syscalls(["connect".to_owned()].into())
            ]
        );
    }

    #[test]
    fn test_set_ranges() {
        let port = |p: u16| NetworkPort(p.try_into().unwrap());
        let set: CountableSetSpecifier<NetworkPort> = CountableSetSpecifier::None;
        assert_eq!(set.ranges(), vec![]);

        for v in [1, 1234, u16::MAX] {
            let set: CountableSetSpecifier<NetworkPort> = CountableSetSpecifier::One(port(v));
            assert_eq!(set.ranges(), vec![port(v)..=port(v)]);
        }

        for v in [1, 1234, u16::MAX] {
            let set: CountableSetSpecifier<NetworkPort> =
                CountableSetSpecifier::Some(vec![port(v)]);
            assert_eq!(set.ranges(), vec![port(v)..=port(v)]);
        }

        let set: CountableSetSpecifier<NetworkPort> =
            CountableSetSpecifier::Some(vec![port(1234), port(5678)]);
        assert_eq!(
            set.ranges(),
            vec![port(1234)..=port(1234), port(5678)..=port(5678)]
        );

        let set: CountableSetSpecifier<NetworkPort> =
            CountableSetSpecifier::AllExcept(vec![port(1)]);
        assert_eq!(set.ranges(), vec![port(2)..=port(u16::MAX)]);

        let set: CountableSetSpecifier<NetworkPort> =
            CountableSetSpecifier::AllExcept(vec![port(u16::MAX)]);
        assert_eq!(set.ranges(), vec![port(1)..=port(u16::MAX - 1)]);

        let set: CountableSetSpecifier<NetworkPort> =
            CountableSetSpecifier::AllExcept(vec![port(1), port(u16::MAX)]);
        assert_eq!(set.ranges(), vec![port(2)..=port(u16::MAX - 1)]);

        let set: CountableSetSpecifier<NetworkPort> =
            CountableSetSpecifier::AllExcept(vec![port(1234), port(5678)]);
        assert_eq!(
            set.ranges(),
            vec![
                port(1)..=port(1233),
                port(1235)..=port(5677),
                port(5679)..=port(65535)
            ]
        );

        let set: CountableSetSpecifier<NetworkPort> =
            CountableSetSpecifier::AllExcept(vec![port(1), port(1234), port(5678), port(u16::MAX)]);
        assert_eq!(
            set.ranges(),
            vec![
                port(2)..=port(1233),
                port(1235)..=port(5677),
                port(5679)..=port(65534)
            ]
        );

        let set: CountableSetSpecifier<NetworkPort> = CountableSetSpecifier::All;
        assert_eq!(set.ranges(), vec![port(1)..=port(u16::MAX)]);
    }
}
