//! Strace output parser

use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, Write as _},
    path::Path,
};

use crate::strace::{Syscall, SyscallName};

mod combinator;
use combinator::parse_line;
use nix::libc::pid_t;

use super::{Expression, IntegerExpression};

/// Result of parsing a syscall line, for the summarize pipeline
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) enum SyscallItem {
    /// Fully parsed syscall (has a handler)
    Complete(Box<Syscall>),
    /// Only the syscall name was parsed (no handler needed)
    NameOnly(SyscallName),
}

pub(crate) struct LogParser {
    reader: Box<dyn BufRead>,
    log: Option<File>,
    buf: String,
    unfinished_syscalls: Vec<SyscallStart>,
    handled_syscalls: HashSet<&'static str>,
}

impl LogParser {
    pub(crate) fn new(
        reader: Box<dyn BufRead>,
        log_path: Option<&Path>,
        handled_syscalls: HashSet<&'static str>,
    ) -> anyhow::Result<Self> {
        let log = log_path
            .map(|p| File::options().create(true).append(true).open(p))
            .transpose()?;
        Ok(Self {
            reader,
            log,
            buf: String::new(),
            unfinished_syscalls: Vec::new(),
            handled_syscalls,
        })
    }
}

#[expect(clippy::large_enum_variant)]
#[derive(Debug, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
enum ParseLineResult {
    /// Successfully parsed syscall
    Parsed(ParsedSyscall),
    /// This line was ignored
    /// (strace sometimes outputs complete garbage like '1008333      0.000045 ???( <unfinished ...>')
    Ignored,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
enum ParsedSyscall {
    /// Unfinished syscall
    SyscallStart(SyscallStart),
    /// Previously unfinished syscall that is now finished
    SyscallEnd(SyscallEnd),
    /// Complete syscall
    Syscall(Syscall),
    /// Syscall name and return value only
    NameOnly {
        name: SyscallName,
        ret_val: Option<IntegerExpression>,
    },
}

/// A syscall started that did not yet return
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct SyscallStart {
    pub pid: pid_t,
    pub rel_ts: f64,
    pub name: SyscallName,
    pub args: Vec<Expression>,
}

impl SyscallStart {
    /// Merge syscall start and end to build a complete syscall invocation description
    pub(crate) fn end(self, end: &SyscallEnd) -> Syscall {
        debug_assert_eq!(self.pid, end.pid);
        debug_assert_eq!(self.name, end.name);
        Syscall {
            pid: self.pid,
            rel_ts: end.rel_ts,
            name: self.name,
            args: self.args,
            ret_val: end.ret_val.clone(),
        }
    }
}

/// A syscall that ended
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct SyscallEnd {
    pub pid: pid_t,
    pub rel_ts: f64,
    pub name: SyscallName,
    pub ret_val: Option<IntegerExpression>,
}

impl Iterator for LogParser {
    type Item = anyhow::Result<SyscallItem>;

    /// Parse strace output lines and yield syscalls
    /// Ignore invalid lines, but bubble up errors if the parsing matches and we fail subsequent parsing
    fn next(&mut self) -> Option<Self::Item> {
        let item = loop {
            self.buf.clear();
            let line = match self.reader.read_line(&mut self.buf) {
                Ok(0) => return None, // EOF
                Ok(_) => self.buf.trim_end(),
                Err(e) => return Some(Err(anyhow::Error::new(e).context("Failed to read line"))),
            };

            if line.ends_with(" +++") || line.ends_with(" ---") {
                // Process exited, or signal received, not a syscall
                continue;
            }

            if let Some(log) = self.log.as_mut()
                && let Err(e) = writeln!(log, "{line}")
            {
                return Some(Err(e.into()));
            }

            match parse_line(line, &self.handled_syscalls) {
                Ok(ParseLineResult::Parsed(parsed)) => {
                    log::trace!("Parsed line: {line:?}");
                    match parsed {
                        ParsedSyscall::Syscall(sc) => {
                            if sc.should_retain() {
                                break SyscallItem::Complete(Box::new(sc));
                            }
                        }
                        ParsedSyscall::SyscallStart(sc) => {
                            self.unfinished_syscalls.push(sc);
                        }
                        ParsedSyscall::SyscallEnd(sc_end) => {
                            if let Some(unfinished_index) = self
                                .unfinished_syscalls
                                .iter()
                                .position(|sc| (sc.name == sc_end.name) && (sc.pid == sc_end.pid))
                            {
                                let sc_start =
                                    self.unfinished_syscalls.swap_remove(unfinished_index); // I fucking love Rust <3
                                let sc = sc_start.end(&sc_end);
                                if sc.should_retain() {
                                    break SyscallItem::Complete(Box::new(sc));
                                }
                            } else {
                                log::warn!("Unable to find first part of syscall");
                            }
                        }
                        ParsedSyscall::NameOnly { name, ret_val } => {
                            if ret_val.as_ref().is_none_or(Syscall::should_retain_ret_val) {
                                break SyscallItem::NameOnly(name);
                            }
                        }
                    }
                }
                Ok(ParseLineResult::Ignored) => {
                    log::warn!("Ignored line: {line:?}");
                }
                Err(e) => {
                    // Unfortunately, some versions of strace output inconsistent line format,
                    // so we have to ignore some parsing errors
                    // log::error!("Failed to parse line: {line:?}");
                    // return Some(Err(e));
                    log::warn!("Failed to parse line ({e}): {line:?}");
                }
            }
        };
        Some(Ok(item))
    }
}

#[expect(clippy::shadow_unrelated)]
#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use pretty_assertions::assert_eq;

    use super::*;

    macro_rules! assert_snapshot {
        ($e:expr) => {
            insta::with_settings!({sort_maps => true}, {
                insta::assert_ron_snapshot!($e);
            });
        };
    }

    #[test]
    fn mmap() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "382944      0.000054 mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f52a332e000",
                &HashSet::from(["mmap"]),
            ).unwrap()
        );

        assert_snapshot!(
            parse_line(
                "601646      0.000011 mmap(0x7f2fce8dc000, 1396736, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x26000) = 0x7f2fce8dc000",
                &HashSet::from(["mmap"]),
            ).unwrap()
        );
    }

    #[test]
    fn access() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "382944      0.000036 access(\"\\x2f\\x65\\x74\\x63\\x2f\\x6c\\x64\\x2e\\x73\\x6f\\x2e\\x70\\x72\\x65\\x6c\\x6f\\x61\\x64\", R_OK) = -1 ENOENT (No such file or directory)",
                &HashSet::from(["access"]),
            ).unwrap()
        );
    }

    #[test]
    fn rt_sigaction() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "720313      0.000064 rt_sigaction(SIGTERM, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7f6da716c510}, NULL, 8) = 0",
                &HashSet::from(["rt_sigaction"]),
            ).unwrap()
        );
    }

    #[test]
    fn rt_sigprocmask() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "440663      0.002174 rt_sigprocmask(SIG_SETMASK, [], ~[KILL STOP RTMIN RT_1], 8) = 0",
                &HashSet::from(["rt_sigprocmask"]),
            )
            .unwrap()
        );
    }

    #[test]
    fn kill_no_sig() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "51667      0.000002 kill(51668, 0)      = 0",
                &HashSet::from(["kill"])
            )
            .unwrap()
        );
    }

    #[test]
    fn newfstatat() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "772627      0.000010 newfstatat(AT_FDCWD, \"\\x2f\\x61\\x2f\\x70\\x61\\x74\\x68\", {st_dev=makedev(0xfd, 0x1), st_ino=26427782, st_mode=S_IFDIR|0755, st_nlink=2, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=112, st_size=53248, st_atime=1689948680 /* 2023-07-21T16:11:20.028467954+0200 */, st_atime_nsec=28467954, st_mtime=1692975712 /* 2023-08-25T17:01:52.252908565+0200 */, st_mtime_nsec=252908565, st_ctime=1692975712 /* 2023-08-25T17:01:52.252908565+0200 */, st_ctime_nsec=252908565}, 0) = 0",
                &HashSet::from(["newfstatat"]),
            ).unwrap()
        );
    }

    #[test]
    fn getrandom() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "815537      0.000017 getrandom(\"\\x42\\x18\\x81\\x90\\x40\\x63\\x1a\\x2c\", 8, GRND_NONBLOCK) = 8",
                &HashSet::from(["getrandom"]),
            ).unwrap()
        );
    }

    #[test]
    fn fstatfs() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "244841      0.000033 fstatfs(6, {f_type=EXT2_SUPER_MAGIC, f_bsize=4096, f_blocks=231830864, f_bfree=38594207, f_bavail=26799417, f_files=58957824, f_ffree=54942232, f_fsid={val=[0x511787a8, 0x92a74a52]}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOATIME}) = 0",
                &HashSet::from(["fstatfs"]),
            ).unwrap()
        );

        assert_snapshot!(
            parse_line(
                "895683      0.000028 fstatfs(3, {f_type=PROC_SUPER_MAGIC, f_bsize=4096, f_blocks=0, f_bfree=0, f_bavail=0, f_files=0, f_ffree=0, f_fsid={val=[0, 0]}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOSUID|ST_NODEV|ST_NOEXEC|ST_RELATIME}) = 0",
                &HashSet::from(["fstatfs"]),
            ).unwrap()
        );
    }

    #[test]
    fn open_relative() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "998518      0.000033 openat(AT_FDCWD<\\x2f\\x68\\x6f\\x6d\\x65\\x2f\\x6d\\x64\\x65\\x2f\\x73\\x72\\x63\\x2f\\x73\\x68\\x68>, \"\\x2e\\x2e\", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3<\\x2f\\x68\\x6f\\x6d\\x65\\x2f\\x6d\\x64\\x65\\x2f\\x73\\x72\\x63>",
                &HashSet::from(["openat"]),
            ).unwrap()
        );
    }

    #[test]
    fn truncated() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "28707      0.000194 sendto(15<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x35\\x34\\x31\\x38\\x32\\x31\\x33\\x5d>, [{nlmsg_len=20, nlmsg_type=RTM_GETADDR, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=1694010548, nlmsg_pid=0}, {ifa_family=AF_UNSPEC, ...}], 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 20",
                &HashSet::from(["sendto"]),
            ).unwrap()
        );

        assert_snapshot!(
            parse_line(
                "215947      0.000022 read(3, \"\\x12\\xef\"..., 832) = 832",
                &HashSet::from(["read"]),
            )
            .unwrap()
        );
    }

    #[test]
    fn invalid() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Bogus output ('{{', note the missing field name) that strace 5.10 can generate
        let res = parse_line(
            "57652      0.000071 sendto(19<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x38\\x34\\x38\\x36\\x39\\x32\\x5d>, {{len=20, type=0x16 /* NLMSG_??? */, flags=NLM_F_REQUEST|0x300, seq=1697715709, pid=0}, \"\\x00\\x00\\x00\\x00\"}, 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 20",
            &HashSet::from(["sendto"]),
        );
        assert_eq!(res.unwrap(), ParseLineResult::Ignored);
    }

    #[test]
    fn bind() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "688129      0.000023 bind(4<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x34\\x31\\x38\\x34\\x35\\x32\\x32\\x5d>, {sa_family=AF_UNIX, sun_path=@\"\\x62\\x31\\x39\\x33\\x64\\x30\\x62\\x30\\x63\\x63\\x64\\x37\\x30\\x35\\x66\\x39\\x2f\\x62\\x75\\x73\\x2f\\x73\\x79\\x73\\x74\\x65\\x6d\\x63\\x74\\x6c\\x2f\"}, 34) = 0",
                &HashSet::from(["bind"]),
            ).unwrap()
        );

        assert_snapshot!(
            parse_line(
                "132360      0.000022 bind(6<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x38\\x31\\x35\\x36\\x39\\x33\\x5d>, {sa_family=AF_INET, sin_port=htons(8025), sin_addr=inet_addr(\"\\x31\\x32\\x37\\x2e\\x30\\x2e\\x30\\x2e\\x31\")}, 16) = 0",
                &HashSet::from(["bind"]),
            ).unwrap()
        );
    }

    #[test]
    fn multiplication() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "85195      0.000038 prlimit64(0, RLIMIT_NOFILE, {rlim_cur=512*1024, rlim_max=512*1024}, NULL) = 0",
                &HashSet::from(["prlimit64"]),
            ).unwrap()
        );
    }

    #[test]
    fn epoll() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "114586      0.000075 epoll_ctl(3<\\x61\\x6e\\x6f\\x6e\\x5f\\x69\\x6e\\x6f\\x64\\x65\\x3a\\x5b\\x65\\x76\\x65\\x6e\\x74\\x70\\x6f\\x6c\\x6c\\x5d>, EPOLL_CTL_ADD, 4<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x37\\x33\\x31\\x35\\x39\\x38\\x5d>, {events=EPOLLIN, data={u32=4, u64=4}}) = 0",
                &HashSet::from(["epoll_ctl"]),
            ).unwrap()
        );

        assert_snapshot!(
            parse_line(
                "3487       0.000130 epoll_pwait(4<\\x61\\x6e\\x6f\\x6e\\x5f\\x69\\x6e\\x6f\\x64\\x65\\x3a\\x5b\\x65\\x76\\x65\\x6e\\x74\\x70\\x6f\\x6c\\x6c\\x5d>, [{events=EPOLLOUT, data={u32=833093633, u64=9163493471957811201}}, {events=EPOLLOUT, data={u32=800587777, u64=9163493471925305345}}], 128, 0, NULL, 0) = 2",
                &HashSet::from(["epoll_pwait"]),
            ).unwrap()
        );
    }

    #[test]
    fn interleave() {
        let _ = simple_logger::SimpleLogger::new().init();

        let lines = Cursor::new(
            "1       0.000001 select(4, [3], NULL, NULL, NULL <unfinished ...>
2       0.000002 clock_gettime(CLOCK_REALTIME, {tv_sec=1130322148, tv_nsec=3977000}) = 0
1       0.000003 <... select resumed> )      = 1 (in [3])"
                .as_bytes()
                .to_vec(),
        );
        let handled = HashSet::from(["select", "clock_gettime"]);
        let parser = LogParser::new(Box::new(lines), None, handled).unwrap();
        let syscalls: Vec<Syscall> = parser
            .into_iter()
            .map(|r| match r.unwrap() {
                SyscallItem::Complete(sc) => *sc,
                SyscallItem::NameOnly(_) => panic!(),
            })
            .collect();

        assert_snapshot!(syscalls);
    }

    #[test]
    fn name_only() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Complete syscall with unhandled name
        let result = parse_line(
            "382944      0.000054 sched_yield() = 0",
            &HashSet::from(["openat"]),
        )
        .unwrap();
        assert_snapshot!(result);

        // Resumed syscall with unhandled name
        let result = parse_line(
            "1       0.000003 <... select resumed> )      = 1 (in [3])",
            &HashSet::from(["openat"]),
        )
        .unwrap();
        assert_snapshot!(result);

        // Complete syscall with handled name still fully parsed
        let result = parse_line(
            "641342      0.000022 openat(AT_FDCWD, \"\\x2f\\x61\", O_RDONLY) = 3",
            &HashSet::from(["openat"]),
        )
        .unwrap();
        assert_snapshot!(result);
    }

    #[test]
    fn failed_unhandled_syscall_filtered_by_iterator() {
        let _ = simple_logger::SimpleLogger::new().init();

        // A failed unhandled syscall (access returning -1 ENOENT) should be filtered out
        // by the iterator, just like failed handled syscalls are
        let lines = Cursor::new(
            "382944      0.000036 access(\"/etc/ld.so.preload\", R_OK) = -1 ENOENT (No such file or directory)\n"
                .as_bytes()
                .to_vec(),
        );
        let handled = HashSet::from(["openat"]);
        let parser = LogParser::new(Box::new(lines), None, handled).unwrap();
        let items: Vec<SyscallItem> = parser.into_iter().collect::<Result<_, _>>().unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn failed_unhandled_resumed_syscall_filtered_by_iterator() {
        let _ = simple_logger::SimpleLogger::new().init();

        // A failed unhandled resumed syscall should also be filtered out
        let lines = Cursor::new(
            "1       0.000001 connect(3, {sa_family=AF_INET}, 16 <unfinished ...>\n\
             1       0.000003 <... connect resumed> ) = -1 ECONNREFUSED (Connection refused)\n"
                .as_bytes()
                .to_vec(),
        );
        // connect is not in the handled set
        let handled = HashSet::from(["openat"]);
        let parser = LogParser::new(Box::new(lines), None, handled).unwrap();
        let items: Vec<SyscallItem> = parser.into_iter().collect::<Result<_, _>>().unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn failure_on_existing_entry_kept_by_iterator() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Failures on an existing entry are kept, complete or resumed, unlike a creation in an absent directory
        let lines = Cursor::new(
            "1       0.000001 rmdir(\"\\x2f\\x74\\x6d\\x70\\x2f\\x64\\x69\\x72\") = -1 ENOTEMPTY (Directory not empty)\n\
             1       0.000002 mkdir(\"\\x2f\\x74\\x6d\\x70\\x2f\\x61\\x62\\x73\\x65\\x6e\\x74\", 0777) = -1 ENOENT (No such file or directory)\n\
             1       0.000003 bind(3, {sa_family=AF_UNIX, sun_path=\"\\x2f\\x74\\x6d\\x70\\x2f\\x73\\x6f\\x63\\x6b\"}, 110 <unfinished ...>\n\
             1       0.000004 <... bind resumed> ) = -1 EADDRINUSE (Address already in use)\n\
             1       0.000005 removexattr(\"\\x2f\\x74\\x6d\\x70\\x2f\\x66\", \"\\x75\\x73\\x65\\x72\\x2e\\x78\") = -1 ENODATA (No data available)\n"
                .as_bytes()
                .to_vec(),
        );
        let handled = HashSet::from(["bind", "mkdir", "removexattr", "rmdir"]);
        let parser = LogParser::new(Box::new(lines), None, handled).unwrap();
        let syscalls: Vec<Syscall> = parser
            .into_iter()
            .map(|r| match r.unwrap() {
                SyscallItem::Complete(sc) => *sc,
                SyscallItem::NameOnly(_) => panic!(),
            })
            .collect();

        assert_snapshot!(syscalls);
    }

    #[test]
    fn absent_entry_removal_kept_by_iterator() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Removals and renames of an absent entry are kept, unlike other calls failing on one
        let lines = Cursor::new(
            "1       0.000001 unlink(\"\\x2f\\x61\") = -1 ENOENT (No such file or directory)\n\
             1       0.000002 unlinkat(AT_FDCWD, \"\\x2f\\x61\", AT_REMOVEDIR) = -1 ENOENT (No such file or directory)\n\
             1       0.000003 mkdir(\"\\x2f\\x61\\x2f\\x62\", 0777) = -1 ENOENT (No such file or directory)\n\
             1       0.000004 rmdir(\"\\x2f\\x61\") = -1 ENOENT (No such file or directory)\n\
             1       0.000005 rename(\"\\x2f\\x61\", \"\\x2f\\x62\") = -1 ENOENT (No such file or directory)\n\
             1       0.000006 stat(\"\\x2f\\x61\", 0x7ffd5e4b8c10) = -1 ENOENT (No such file or directory)\n\
             1       0.000007 renameat(AT_FDCWD, \"\\x2f\\x61\", AT_FDCWD, \"\\x2f\\x62\") = -1 ENOENT (No such file or directory)\n\
             1       0.000008 renameat2(AT_FDCWD, \"\\x2f\\x61\", AT_FDCWD, \"\\x2f\\x62\", RENAME_NOREPLACE <unfinished ...>\n\
             1       0.000009 <... renameat2 resumed> ) = -1 ENOENT (No such file or directory)\n\
             1       0.000010 unlink(\"\\x2f\\x61\") = -1 EACCES (Permission denied)\n"
                .as_bytes()
                .to_vec(),
        );
        let retained = [
            "unlink",
            "unlinkat",
            "rmdir",
            "rename",
            "renameat",
            "renameat2",
        ];
        let handled = retained.into_iter().chain(["mkdir", "stat"]).collect();
        let parser = LogParser::new(Box::new(lines), None, handled).unwrap();
        let names: Vec<SyscallName> = parser
            .into_iter()
            .map(|r| match r.unwrap() {
                SyscallItem::Complete(sc) => sc.name,
                SyscallItem::NameOnly(_) => panic!(),
            })
            .collect();

        assert_eq!(names, retained.map(SyscallName::from));
    }

    #[test]
    fn existing_path_query_failures_kept_by_iterator() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Path queries failing after their lookup are kept, unlike other calls failing with the same errors
        let lines = Cursor::new(
            "1       0.000001 readlink(\"\\x2f\\x61\", 0x7ffd5e4b8c10, 4096) = -1 EINVAL (Invalid argument)\n\
             1       0.000002 readlinkat(AT_FDCWD, \"\\x2f\\x61\", 0x7ffd5e4b8c10, 4096) = -1 EINVAL (Invalid argument)\n\
             1       0.000003 name_to_handle_at(AT_FDCWD, \"\\x2f\\x61\", {handle_bytes=0 => 12}, 0x7ffd5e4b8c0c, AT_HANDLE_FID) = -1 EOVERFLOW (Value too large for defined data type)\n\
             1       0.000004 openat(AT_FDCWD, \"\\x2f\\x61\", O_RDONLY|O_TMPFILE) = -1 EINVAL (Invalid argument)\n\
             1       0.000005 openat(AT_FDCWD, \"\\x2f\\x61\", O_RDONLY) = -1 EOVERFLOW (Value too large for defined data type)\n"
                .as_bytes()
                .to_vec(),
        );
        let retained = ["readlink", "readlinkat", "name_to_handle_at"];
        let handled = retained.into_iter().chain(["openat"]).collect();
        let parser = LogParser::new(Box::new(lines), None, handled).unwrap();
        let names: Vec<SyscallName> = parser
            .into_iter()
            .map(|r| match r.unwrap() {
                SyscallItem::Complete(sc) => sc.name,
                SyscallItem::NameOnly(_) => panic!(),
            })
            .collect();

        assert_eq!(names, retained.map(SyscallName::from));
    }

    #[test]
    fn successful_unhandled_syscall_yielded_by_iterator() {
        let _ = simple_logger::SimpleLogger::new().init();

        // A successful unhandled syscall should still be yielded as NameOnly
        let lines = Cursor::new(
            "382944      0.000054 sched_yield() = 0\n"
                .as_bytes()
                .to_vec(),
        );
        let handled = HashSet::from(["openat"]);
        let parser = LogParser::new(Box::new(lines), None, handled).unwrap();
        let items: Vec<SyscallItem> = parser.into_iter().collect::<Result<_, _>>().unwrap();
        assert_eq!(items, vec![SyscallItem::NameOnly("sched_yield".into())]);
    }

    #[test]
    fn getpid() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "641342      0.000022 getpid()           = 641314",
                &HashSet::from(["getpid"])
            )
            .unwrap()
        );
    }

    #[test]
    fn close() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "246722      0.000003 close(39<\\x2f\\x6d\\x65\\x6d\\x66\\x64\\x3a\\x6d\\x6f\\x7a\\x69\\x6c\\x6c\\x61\\x2d\\x69\\x70\\x63>(deleted)) = 0",
                &HashSet::from(["close"]),
            )
            .unwrap()
        );
    }

    #[test]
    fn sched_getaffinity() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "231196      0.000017 sched_getaffinity(0, 512, [0 1 2 3 4 5 6 7]) = 8",
                &HashSet::from(["sched_getaffinity"]),
            )
            .unwrap()
        );
    }

    #[test]
    fn execve() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "1234      0.000000 execve(\"\\x12\", [\"\\x34\"], [\"\\x56\"]) = 0",
                &HashSet::from(["execve"]),
            )
            .unwrap()
        );
    }

    #[test]
    fn ioctl() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "34274      0.000058 ioctl(1<\\x2f\\x64\\x65\\x76\\x2f\\x70\\x74\\x73\\x2f\\x30>, TCSETSW, {c_iflag=ICRNL|IXON|IUTF8, c_oflag=NL0|CR0|TAB0|BS0|VT0|FF0|OPOST|ONLCR, c_cflag=B38400|CS8|CREAD, c_lflag=ISIG|ICANON|ECHO|ECHOE|ECHOK|IEXTEN|ECHOCTL|ECHOKE, c_line=N_TTY, c_cc=[[VINTR]=0x3, [VQUIT]=0x1c, [VERASE]=0x7f, [VKILL]=0x15, [VEOF]=0x4, [VTIME]=0, [VMIN]=0x1, [VSWTC]=0, [VSTART]=0x11, [VSTOP]=0x13, [VSUSP]=0x1a, [VEOL]=0, [VREPRINT]=0x12, [VDISCARD]=0xf, [VWERASE]=0x17, [VLNEXT]=0x16, [VEOL2]=0, [17]=0, [18]=0]}) = 0",
                &HashSet::from(["ioctl"]),
            )
            .unwrap()
        );
    }

    #[test]
    fn in_out_args() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "664767      0.000014 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f3b7c000990, parent_tid=0x7f3b7c000990, exit_signal=0, stack=0x7f3b7b800000, stack_size=0x7ff880, tls=0x7f3b7c0006c0} => {parent_tid=[664773]}, 88) = 664773",
                &HashSet::from(["clone3"]),
            )
            .unwrap()
        );

        assert_snapshot!(
            parse_line(
                "237494      0.000026 getpeername(3, {sa_family=AF_UNIX, sun_path=@\"\\x6e\\x6f\\x70\\x65\"}, [124 => 20]) = 0",
                &HashSet::from(["getpeername"]),
            )
            .unwrap()
        );

        // Note: not a real strace line
        assert_snapshot!(
            parse_line(
                "176051      0.000020 recvmsg(3, {msg_namelen=128 => 16, msg_controllen=56, msg_flags=0}, 0) = 64",
                &HashSet::from(["recvmsg"]),
            )
            .unwrap()
        );
    }

    #[test]
    fn named_args() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "714433      0.000035 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3f3c2f5090) = 714434",
                &HashSet::from(["clone"]),
            )
            .unwrap()
        );
    }

    #[test]
    fn bitshift() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "794046      0.000024 capset({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, {effective=1<<CAP_SYS_CHROOT, permitted=1<<CAP_SYS_CHROOT, inheritable=0}) = 0",
                &HashSet::from(["capset"]),
            )
            .unwrap()
        );
    }

    #[test]
    fn macro_addr_arg() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "813299      0.000023 connect(93, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, \"\\x12\\x34\", &sin6_addr), sin6_scope_id=0}, 28) = 0",
                &HashSet::from(["connect"]),
            )
            .unwrap()
        );
    }

    #[test]
    fn wait() {
        let _ = simple_logger::SimpleLogger::new().init();
        assert_snapshot!(
            parse_line(
                "30192      0.000010 wait4(30247, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 30247",
                &HashSet::from(["wait4"]),
            )
            .unwrap()
        );
    }

    #[test]
    fn ret_code() {
        let _ = simple_logger::SimpleLogger::new().init();
        assert_snapshot!(
            parse_line(
                r#"39270      0.000020 connect(11<\x73\x6f\x63\x6b\x65\x74\x3a\x5b\x32\x31\x34\x31\x30\x37\x5d>, {sa_family=AF_INET, sin_port=htons(4321), sin_addr=inet_addr("\x31\x2e\x32\x2e\x33\x2e\x34")}, 16) = -1 EINPROGRESS (Operation now in progress)"#,
                &HashSet::from(["connect"]),
            )
            .unwrap()
        );
    }

    #[test]
    fn erestartsys() {
        let _ = simple_logger::SimpleLogger::new().init();
        assert_snapshot!(
            parse_line(
                "121009      0.000004 futex(0x574cd7b0cd00, FUTEX_WAIT_PRIVATE, 6, NULL) = ? ERESTARTSYS (To be restarted if SA_RESTART is set)",
                &HashSet::new(),
            )
            .unwrap()
        );
    }
}

#[cfg(all(feature = "nightly", test))]
#[expect(clippy::tests_outside_test_module)]
mod benchs {
    extern crate test;

    use std::io::BufReader;

    use test::Bencher;

    use super::*;

    #[bench]
    fn bench_parse_line(b: &mut Bencher) {
        let log_path = Path::new("strace.log");
        if !log_path.is_file() {
            return;
        }
        let log_lines: Vec<_> = BufReader::new(File::open(log_path).unwrap())
            .lines()
            .take(5000)
            .collect::<Result<_, _>>()
            .unwrap();

        let handled = crate::summarize::handled_syscall_names();

        b.iter(|| {
            log_lines
                .iter()
                .map(|l| parse_line(l, &handled))
                .for_each(drop);
        });
    }
}
