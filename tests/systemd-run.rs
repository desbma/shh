//! These tests run generated options with systemd-run to ensure they are valid
//! and allow the program to execute normally

#[cfg(test)]
#[cfg(feature = "test-env-vm")]
mod tests {
    use std::{
        env,
        fs::{self, Permissions},
        io::{BufRead as _, Write as _},
        iter,
        net::TcpListener,
        os::unix::{
            self,
            fs::{FileTypeExt as _, PermissionsExt as _},
            net::UnixListener,
        },
        path::Path,
        process,
        sync::LazyLock,
    };

    use assert_cmd::{
        Command,
        assert::{Assert, OutputAssertExt as _},
    };
    use nix::{sys::stat, unistd};
    use predicates::prelude::predicate;

    static ALL_SHH_RUN_OPTS: LazyLock<Vec<Vec<&'static str>>> = LazyLock::new(all_shh_run_opts);
    const KERNEL_LOG_REGEX: &str = r"\[\ *[0-9]+\.[0-9]+\] ";
    /// Python script attempting to create an entry, existing or not
    const CREATE_ENTRY_SCRIPT: &str = "
import ctypes, os, stat, sys

# Values from <fcntl.h>, <stdio.h> and x86_64 <sys/syscall.h>
AT_FDCWD = -100
RENAME_NOREPLACE = 1
SYS_mknod = 133

kind, path, src, held = sys.argv[1:]
libc = ctypes.CDLL(None, use_errno=True)


def check(ret):
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), path)


if kind in ('link', 'rename'):
    open(src, 'w').close()
try:
    if kind in ('open', 'open-replace'):
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL))
    elif kind in ('mkdir', 'mkdir-p'):
        os.mkdir(path)
    elif kind == 'symlink':
        os.symlink('/dev/null', path)
    elif kind == 'link':
        os.link(src, path)
    elif kind == 'rename':
        check(libc.renameat2(AT_FDCWD, src.encode(), AT_FDCWD, path.encode(), RENAME_NOREPLACE))
    elif kind == 'mknod':
        # mknod syscall on x86_64, glibc's mkfifo calls mknodat
        check(libc.syscall(SYS_mknod, path.encode(), stat.S_IFIFO | 0o644, 0))
    else:
        raise ValueError(kind)
except FileExistsError:
    if kind == 'open-replace':
        os.unlink(path)
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL))
else:
    # A held entry the service creates is one it does not see
    if held == 'held':
        sys.exit(1)
if kind == 'mkdir-p':
    open(os.path.join(path, 'file'), 'w').close()
";

    /// Python script making a syscall of a given kind on a path
    const PATH_SYSCALL_SCRIPT: &str = include_str!("path_syscall.py");

    /// Run `shh run` for a given command, and return generated systemd options
    fn generate_options(cmd: &[&str], run_opts: &[&str]) -> Vec<String> {
        const START_OPTION_OUTPUT_SNIPPET_PREFIX: &str =
            "-------- Start of suggested service options ";
        const END_OPTION_OUTPUT_SNIPPET_PREFIX: &str = "-------- End of suggested service options ";
        let bin =
            env::var("CARGO_BIN_EXE_shh").unwrap_or_else(|_| env!("CARGO_BIN_EXE_shh").to_owned());
        let output = Command::new(bin)
            .arg("run")
            .args(run_opts)
            .arg("--")
            .args(cmd)
            .unwrap();
        let mut has_end_marker = false;
        let opts: Vec<_> = output
            .stdout
            .lines()
            // Filter out delimiting lines while letting errors bubble up
            .skip_while(|r| {
                r.as_ref()
                    .is_ok_and(|l| !l.starts_with(START_OPTION_OUTPUT_SNIPPET_PREFIX))
            })
            .skip(1)
            .inspect(|r| {
                if r.as_ref()
                    .is_ok_and(|l| l.starts_with(END_OPTION_OUTPUT_SNIPPET_PREFIX))
                {
                    has_end_marker = true;
                }
            })
            .take_while(|r| {
                r.as_ref()
                    .map_or(true, |l| !l.starts_with(END_OPTION_OUTPUT_SNIPPET_PREFIX))
            })
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(has_end_marker);

        output.assert().success();
        opts
    }

    /// Run systemd-run for given command, with options
    fn systemd_run(cmd: &[&str], sd_opts: &[String], user: bool) -> Assert {
        let mut sd_cmd = vec!["systemd-run".to_owned()];
        if user {
            sd_cmd.extend([
                "--user".to_owned(),
                "-M".to_owned(),
                format!("{}@.host", env::var("TEST_USER").unwrap()),
            ]);
        }
        sd_cmd.extend(["-P", "-G", "--wait"].into_iter().map(ToOwned::to_owned));
        for sd_opt in sd_opts {
            // Some options are supported in systemd unit files but not by systemd-run, work around that
            let sd_opt = match sd_opt.as_str() {
                // https://github.com/systemd/systemd/issues/36222#issuecomment-2623967515
                "PrivateTmp=disconnected" => "PrivateTmpEx=disconnected",
                "RestrictAddressFamilies=none" => "RestrictAddressFamilies=",
                s => s,
            };
            sd_cmd.extend(["-p", sd_opt].into_iter().map(ToOwned::to_owned));
        }
        sd_cmd.extend(
            ["-p", "Environment=LANG=C", "--"]
                .into_iter()
                .map(ToOwned::to_owned),
        );
        sd_cmd.extend(cmd.iter().map(|s| (*s).to_owned()));
        eprintln!(
            "{}",
            shlex::try_join(sd_cmd.iter().map(AsRef::as_ref)).unwrap()
        );
        let assrt = Command::new(&sd_cmd[0])
            .args(&sd_cmd[1..])
            .unwrap()
            .assert();
        // eprintln!("{}", String::from_utf8_lossy(&assrt.get_output().stdout));
        // eprintln!("{}", String::from_utf8_lossy(&assrt.get_output().stderr));
        assrt.success()
    }

    /// Generate all combinations of `shh run` args to test
    fn all_shh_run_opts() -> Vec<Vec<&'static str>> {
        let args_mode = vec![vec!["-m", "generic"], vec![], vec!["-m", "aggressive"]];
        let args_fs = vec![
            vec![],
            vec!["-w"],
            vec!["-w", "--merge-paths-threshold", "1"],
            vec!["-w", "--merge-paths-threshold", "2"],
            vec!["-w", "--merge-paths-threshold", "10"],
            vec!["-w", "--merge-paths-threshold", "100"],
        ];
        let args_fw = vec![vec![], vec!["-f"]];
        let mut combinations = Vec::with_capacity(args_mode.len() * args_fs.len() * args_fw.len());
        for arg_mode in &args_mode {
            for arg_fs in &args_fs {
                for arg_fw in &args_fw {
                    if arg_mode.get(1).is_some_and(|m| *m == "generic")
                        && (!arg_fs.is_empty() || !arg_fw.is_empty())
                    {
                        // Generic mode is incompatible with those
                        continue;
                    }
                    let mut args = Vec::with_capacity(arg_mode.len() + arg_fs.len() + arg_fw.len());
                    args.extend(arg_mode);
                    args.extend(arg_fs);
                    args.extend(arg_fw);
                    combinations.push(args);
                }
            }
        }
        combinations
    }

    /// Profile a command with every `shh run` option set, and run it with the generated options as a
    /// system or user service
    fn profile_and_run(cmd: &[&str], user: bool) {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(cmd, &shh_opts);
            let _ = systemd_run(cmd, &sd_opts, user);
        }
    }

    /// Create an entry of a type: `file`, `dir`, `fifo`, or `symlink` to `/dev/null`
    fn create_entry(type_: &str, path: &Path) {
        match type_ {
            "file" => fs::write(path, "").unwrap(),
            "dir" => fs::create_dir(path).unwrap(),
            "fifo" => unistd::mkfifo(path, stat::Mode::from_bits(0o666).unwrap()).unwrap(),
            "symlink" => unix::fs::symlink("/dev/null", path).unwrap(),
            _ => unreachable!(),
        }
    }

    /// Remove an entry, a directory or not
    fn remove_entry(path: &Path) {
        if fs::symlink_metadata(path).unwrap().is_dir() {
            fs::remove_dir_all(path).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
    }

    /// Profile a command creating a path with every `shh run` option set, and run it as a system service with
    /// the generated options, removing the path after each step
    fn profile_and_run_creating_path(cmd: &[&str], path: &Path) {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(cmd, shh_opts);
            fs::remove_file(path).unwrap();
            let _ = systemd_run(cmd, &sd_opts, false);
            fs::remove_file(path).unwrap();
        }
    }

    /// Parse the major and minor numbers of a version, like `6.12.48+deb13-amd64`
    fn major_minor(version: &str) -> (u32, u32) {
        let mut numbers = version.split('.').map(|n| n.parse().unwrap());
        (numbers.next().unwrap(), numbers.next().unwrap())
    }

    /// Read the major and minor version of the running kernel
    fn kernel_version() -> (u32, u32) {
        major_minor(&fs::read_to_string("/proc/sys/kernel/osrelease").unwrap())
    }

    /// Read the major and minor version of strace
    fn strace_version() -> (u32, u32) {
        let output = Command::new("strace").arg("-V").unwrap();
        // Like `strace -- version 6.13`
        let first_line = output.stdout.lines().next().unwrap().unwrap();
        major_minor(first_line.rsplit(' ').next().unwrap())
    }

    #[test]
    fn systemd_run_true() {
        let cmd = ["true"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_write_dev_null() {
        let cmd = ["sh", "-c", ": > /dev/null"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_ls_dev() {
        let cmd = ["ls", "/dev/"];
        for user in [false, true] {
            for shh_opts in &*ALL_SHH_RUN_OPTS {
                let mut shh_opts = shh_opts.clone();
                if user {
                    shh_opts.extend(["-i", "user"]);
                }
                eprintln!("shh run option: {}", shh_opts.join(" "));
                let sd_opts = generate_options(&cmd, &shh_opts);
                let asrt = systemd_run(&cmd, &sd_opts, user);
                asrt.stdout(predicate::str::contains("char"))
                    .stdout(predicate::str::contains("log"));
            }
        }
    }

    #[test]
    fn systemd_run_ls_proc() {
        let cmd = ["ls", "/proc/1"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_read_kallsyms() {
        let cmd = ["head", "/proc/kallsyms"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_ls_modules() {
        let cmd = ["ls", "/usr/lib/modules/"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_dmesg() {
        let cmd = ["dmesg"];
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, shh_opts);
            let asrt = systemd_run(&cmd, &sd_opts, false);
            asrt.stdout(predicate::str::is_match(KERNEL_LOG_REGEX).unwrap());
        }
    }

    #[test]
    fn systemd_run_systemctl() {
        let cmd = ["systemctl"];
        for user in [false, true] {
            for shh_opts in &*ALL_SHH_RUN_OPTS {
                if shh_opts.contains(&"aggressive") {
                    // This one breaks systemctl under load,
                    // due to divergent code path that makes us deny `@io-event`
                    continue;
                }
                let mut shh_opts = shh_opts.clone();
                if user {
                    shh_opts.extend(["-i", "user"]);
                }
                eprintln!("shh run option: {}", shh_opts.join(" "));
                let sd_opts = generate_options(&cmd, &shh_opts);
                let _ = systemd_run(&cmd, &sd_opts, user);
            }
        }
    }

    #[test]
    fn systemd_run_ss() {
        let cmd = ["ss", "-l"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_mmap_wx() {
        let cmd = [
            "python3",
            "-c",
            "import mmap; mmap.mmap(-1, 4096, prot=mmap.PROT_WRITE|mmap.PROT_EXEC)",
        ];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_sched_realtime() {
        let cmd = [
            "python3",
            "-c",
            "import os; os.sched_setscheduler(0, os.SCHED_RR, os.sched_param(os.sched_get_priority_min(os.SCHED_RR)))",
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_bind() {
        let cmd = [
            "python3",
            "-c",
            "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind((\"127.0.0.1\", 1234))",
        ];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_bind_unix() {
        // Bind a Unix socket, a write to its directory, that clients outside the service reach
        for dir in ["/var/lib", "/tmp"] {
            let path = format!("{dir}/shh-test-{id}.sock", id = rand::random::<u16>());
            let code = format!("import socket; socket.socket(socket.AF_UNIX).bind({path:?})");
            let cmd = ["python3", "-c", &code];
            for shh_opts in &*ALL_SHH_RUN_OPTS {
                eprintln!("shh run option: {}", shh_opts.join(" "));
                let _ = fs::remove_file(&path);
                let sd_opts = generate_options(&cmd, shh_opts);
                let _ = fs::remove_file(&path);
                let _ = systemd_run(&cmd, &sd_opts, false);
                assert!(fs::exists(&path).unwrap());
                fs::remove_file(&path).unwrap();
            }
        }
    }

    #[test]
    fn systemd_run_sock_packet() {
        let cmd = [
            "python3",
            "-c",
            "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)",
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_syslog() {
        let cmd = ["dmesg", "-S"];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_mknod() {
        let tmp_dir = tempfile::tempdir().unwrap();

        let pipe_path = tmp_dir.path().join("pipe");
        let cmd_pipe = ["mknod", pipe_path.as_os_str().to_str().unwrap(), "p"];
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let mut sd_opts = generate_options(&cmd_pipe, shh_opts);
            let _ = fs::remove_file(&pipe_path);

            sd_opts.push(format!("BindPaths={}", tmp_dir.path().to_str().unwrap()));
            if let Some(inaccessible_path_opt) = sd_opts
                .iter_mut()
                .find(|o| o.starts_with("InaccessiblePaths="))
            {
                *inaccessible_path_opt = inaccessible_path_opt
                    .split(' ')
                    .filter(|e| e.strip_prefix('-').unwrap_or(e) != "/tmp")
                    .collect::<Vec<_>>()
                    .join(" ");
            }

            let _ = systemd_run(&cmd_pipe, &sd_opts, false);
            assert!(fs::metadata(&pipe_path).unwrap().file_type().is_fifo());
            fs::remove_file(&pipe_path).unwrap();
        }

        let dev_path = tmp_dir.path().join("dev");
        let cmd_dev = [
            "mknod",
            dev_path.as_os_str().to_str().unwrap(),
            "b",
            "255",
            "255",
        ];
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let mut sd_opts = generate_options(&cmd_dev, shh_opts);
            let _ = fs::remove_file(&dev_path);

            sd_opts.push(format!("BindPaths={}", tmp_dir.path().to_str().unwrap()));
            if let Some(inaccessible_path_opt) = sd_opts
                .iter_mut()
                .find(|o| o.starts_with("InaccessiblePaths="))
            {
                *inaccessible_path_opt = inaccessible_path_opt
                    .split(' ')
                    .filter(|e| e.strip_prefix('-').unwrap_or(e) != "/tmp")
                    .collect::<Vec<_>>()
                    .join(" ");
            }

            let _ = systemd_run(&cmd_dev, &sd_opts, false);
            assert!(
                fs::metadata(&dev_path)
                    .unwrap()
                    .file_type()
                    .is_block_device()
            );
            fs::remove_file(&dev_path).unwrap();
        }
    }

    #[test]
    fn systemd_run_script() {
        let mut script = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o755))
            .tempfile()
            .unwrap();
        script
            .write_all("#!/usr/bin/env sh\necho 'from a script'".as_bytes())
            .unwrap();
        let script_path = script.into_temp_path();
        let cmd = [script_path.to_str().unwrap()];
        for user in [false, true] {
            for shh_opts in &*ALL_SHH_RUN_OPTS {
                let mut shh_opts = shh_opts.clone();
                if user {
                    shh_opts.extend(["-i", "user"]);
                }
                eprintln!("shh run option: {}", shh_opts.join(" "));
                let sd_opts = generate_options(&cmd, &shh_opts);
                let asrt = systemd_run(&cmd, &sd_opts, user);
                asrt.stdout(predicate::str::contains("from a script"));
            }
        }
    }

    #[test]
    fn systemd_run_curl() {
        let cmd = ["curl", "-k", "https://example.com"];
        for user in [false, true] {
            for shh_opts in &*ALL_SHH_RUN_OPTS {
                let mut shh_opts = shh_opts.clone();
                if user {
                    shh_opts.extend(["-i", "user"]);
                }
                eprintln!("shh run option: {}", shh_opts.join(" "));
                let sd_opts = generate_options(&cmd, &shh_opts);
                let asrt = systemd_run(&cmd, &sd_opts, user);
                asrt.stdout(predicate::str::contains("<html"));
            }
        }
    }

    #[test]
    fn systemd_run_ping_4() {
        let cmd = ["ping", "-c", "1", "-4", "127.0.0.1"];
        for user in [false, true] {
            for shh_opts in &*ALL_SHH_RUN_OPTS {
                let mut shh_opts = shh_opts.clone();
                if user {
                    shh_opts.extend(["-i", "user"]);
                }
                eprintln!("shh run option: {}", shh_opts.join(" "));
                let sd_opts = generate_options(&cmd, &shh_opts);
                let asrt = systemd_run(&cmd, &sd_opts, user);
                asrt.stdout(predicate::str::contains(
                "127.0.0.1 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss",
            ));
            }
        }
    }

    #[test]
    fn systemd_run_ping_6() {
        let cmd = ["ping", "-c", "1", "-6", "::1"];
        for user in [false, true] {
            for shh_opts in &*ALL_SHH_RUN_OPTS {
                let mut shh_opts = shh_opts.clone();
                if user {
                    shh_opts.extend(["-i", "user"]);
                }
                eprintln!("shh run option: {}", shh_opts.join(" "));
                let sd_opts = generate_options(&cmd, &shh_opts);
                let asrt = systemd_run(&cmd, &sd_opts, user);
                asrt.stdout(predicate::str::contains(
                    "::1 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss",
                ));
            }
        }
    }

    fn del_netns(ns: &str) {
        let mut cmd = process::Command::new("ip");
        cmd.args(["netns", "del", ns]);
        assert!(cmd.status().unwrap().success());
        assert!(!fs::exists(format!("/run/netns/{ns}")).unwrap());
    }

    #[test]
    fn systemd_netns_create() {
        let ns = format!("t{}", rand::random::<u16>());
        let cmd = ["ip", "netns", "add", &ns];
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, shh_opts);
            assert!(fs::exists(format!("/run/netns/{ns}")).unwrap());
            del_netns(&ns);
            let _ = systemd_run(&cmd, &sd_opts, false);
            assert!(fs::exists(format!("/run/netns/{ns}")).unwrap());
            del_netns(&ns);
        }
    }

    #[test]
    fn systemd_kill() {
        for sig in ["URG", "KILL"] {
            let code = format!(
                "import signal, subprocess; p = subprocess.Popen((\"sleep\", \"0.5s\")); p.send_signal(signal.SIG{sig}); p.wait(); print(f\"rc={{p.returncode}}\")",
            );
            let cmd = ["python3", "-c", &code];
            for user in [false, true] {
                for shh_opts in &*ALL_SHH_RUN_OPTS {
                    let mut shh_opts = shh_opts.clone();
                    if user {
                        shh_opts.extend(["-i", "user"]);
                    }
                    eprintln!("shh run option: {}", shh_opts.join(" "));
                    let sd_opts = generate_options(&cmd, &shh_opts);
                    let asrt = systemd_run(&cmd, &sd_opts, user);
                    asrt.stdout(predicate::str::contains(if sig == "KILL" {
                        "-9"
                    } else {
                        "0"
                    }));
                }
            }
        }
    }

    #[test]
    fn systemd_run_ptrace_attach() {
        // Attach to and detach from a different user's process, requiring CAP_SYS_PTRACE
        let script = r#"
import ctypes, os, subprocess, sys

# Request values from <sys/ptrace.h>
PTRACE_ATTACH = 16
PTRACE_DETACH = 17

libc = ctypes.CDLL("libc.so.6", use_errno=True)

def ptrace(request, pid):
    if libc.ptrace(request, pid, None, None) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

# Oldest process of the user, kept running by lingering in the test environment
target_pid = int(subprocess.check_output(["pgrep", "--oldest", "--euid", sys.argv[1]]))
ptrace(PTRACE_ATTACH, target_pid)
# Attaching stops the target, it must be waited for before it can be detached
os.waitpid(target_pid, 0)
ptrace(PTRACE_DETACH, target_pid)
"#;
        let user = env::var("TEST_USER").unwrap();
        let cmd = ["python3", "-c", script, &user];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_wake_lock() {
        // Take and release a wake lock, requiring CAP_BLOCK_SUSPEND
        if !fs::exists("/sys/power/wake_lock").unwrap() {
            eprintln!("Kernel built without CONFIG_PM_WAKELOCKS, skipping");
            return;
        }
        let cmd = [
            "sh",
            "-c",
            "echo shh-test > /sys/power/wake_lock && echo shh-test > /sys/power/wake_unlock",
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_rm() {
        // Remove a pre-existing file, a write to its directory
        let path = format!("/var/lib/shh-test-{}", rand::random::<u16>());
        let cmd = ["rm", &path];
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh run option: {}", shh_opts.join(" "));
            fs::write(&path, "").unwrap();
            let sd_opts = generate_options(&cmd, shh_opts);
            fs::write(&path, "").unwrap();
            let _ = systemd_run(&cmd, &sd_opts, false);
            let _ = fs::remove_file(&path);
        }
    }

    #[test]
    fn systemd_run_creat() {
        // Create a file with the creat syscall, a write to its directory
        let dir = tempfile::tempdir_in("/var/lib").unwrap();
        let path = dir.path().join("file");
        let cmd = [
            "python3",
            "-c",
            "import ctypes, sys; sys.exit(ctypes.CDLL(None).creat(sys.argv[1].encode(), 0o644) < 0)",
            path.to_str().unwrap(),
        ];
        profile_and_run_creating_path(&cmd, &path);
    }

    #[test]
    fn systemd_run_openat2() {
        // Create a file with the openat2 syscall, a write to its directory
        let dir = tempfile::tempdir_in("/var/lib").unwrap();
        let path = dir.path().join("file");
        let cmd = [
            "python3",
            "-c",
            PATH_SYSCALL_SCRIPT,
            "openat2",
            path.to_str().unwrap(),
        ];
        profile_and_run_creating_path(&cmd, &path);
    }

    #[test]
    fn systemd_run_tmpfile() {
        // Open an unnamed temporary file, a write to its directory, on the tmpfs of the test environment
        let dir = tempfile::tempdir_in("/mnt/tmp").unwrap();
        let cmd = [
            "python3",
            "-c",
            "import os, sys; os.open(sys.argv[1], os.O_TMPFILE | os.O_RDWR)",
            dir.path().to_str().unwrap(),
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_symlink() {
        // Create a symlink, a write to its directory
        let temp_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let path = temp_dir.path().join("link");
        let cmd = ["ln", "-s", "/dev/null", path.to_str().unwrap()];
        profile_and_run_creating_path(&cmd, &path);
    }

    #[test]
    fn systemd_run_ln_hard() {
        // Hard link a pre-existing file, a read of the source, both directly in /tmp
        let src = tempfile::NamedTempFile::new_in("/tmp").unwrap();
        let dst = src.path().with_extension("dst");
        let cmd = ["ln", src.path().to_str().unwrap(), dst.to_str().unwrap()];
        profile_and_run_creating_path(&cmd, &dst);
    }

    #[test]
    fn systemd_run_link_rename_across_mounts() {
        // Hard link a pre-existing /etc file into /var/lib, and rename a file created in /var/tmp into /var/lib,
        // through Python as `mv` falls back to copying when the directories are on different mounts
        let src = tempfile::NamedTempFile::new_in("/etc").unwrap();
        let dst_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let link = dst_dir.path().join("link");
        let created = format!("/var/tmp/shh-test-{}", rand::random::<u16>());
        let renamed = dst_dir.path().join("renamed");
        let cmd = [
            "python3",
            "-c",
            "import os, sys; os.link(sys.argv[1], sys.argv[2]); open(sys.argv[3], 'w').close(); os.rename(sys.argv[3], sys.argv[4])",
            src.path().to_str().unwrap(),
            link.to_str().unwrap(),
            &created,
            renamed.to_str().unwrap(),
        ];
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, shh_opts);
            fs::remove_file(&link).unwrap();
            fs::remove_file(&renamed).unwrap();
            let _ = systemd_run(&cmd, &sd_opts, false);
            fs::remove_file(&link).unwrap();
            fs::remove_file(&renamed).unwrap();
        }
    }

    #[test]
    fn systemd_run_create_held() {
        // Create an entry held directly in /tmp, which the service must see; link and rename sources are created
        // by the command
        for (kind, type_) in [
            ("open", "file"),
            ("mkdir", "dir"),
            ("symlink", "symlink"),
            ("link", "file"),
            ("rename", "file"),
            ("mknod", "fifo"),
            ("open-replace", "file"),
            ("mkdir-p", "dir"),
        ] {
            let path = format!("/tmp/shh-test-{id}", id = rand::random::<u16>());
            let src = format!("{path}.src");
            create_entry(type_, Path::new(&path));
            let cmd = [
                "python3",
                "-c",
                CREATE_ENTRY_SCRIPT,
                kind,
                &path,
                &src,
                "held",
            ];
            for shh_opts in &*ALL_SHH_RUN_OPTS {
                eprintln!("shh run option: {opts} ({kind})", opts = shh_opts.join(" "));
                let sd_opts = generate_options(&cmd, shh_opts);
                let _ = fs::remove_file(&src);
                let _ = systemd_run(&cmd, &sd_opts, false);
                let _ = fs::remove_file(&src);
            }
            remove_entry(Path::new(&path));
        }
    }

    #[test]
    fn systemd_run_create_held_then_free() {
        // Create an entry in /var/lib held during profiling only, a write to its directory; link and rename
        // sources are created by the command in another directory
        let dir = tempfile::tempdir_in("/var/lib").unwrap();
        let src_dir = dir.path().join("src");
        let dst_dir = dir.path().join("dst");
        fs::create_dir(&src_dir).unwrap();
        fs::create_dir(&dst_dir).unwrap();
        let src = src_dir.join("file");
        let path = dst_dir.join("entry");
        for (kind, type_) in [
            ("open", "file"),
            ("open", "symlink"),
            ("mkdir", "dir"),
            ("symlink", "symlink"),
            ("link", "file"),
            ("rename", "file"),
            ("mknod", "fifo"),
        ] {
            let cmd = [
                "python3",
                "-c",
                CREATE_ENTRY_SCRIPT,
                kind,
                path.to_str().unwrap(),
                src.to_str().unwrap(),
                "free",
            ];
            for shh_opts in &*ALL_SHH_RUN_OPTS {
                eprintln!(
                    "shh run option: {opts} ({kind} on {type_})",
                    opts = shh_opts.join(" ")
                );
                create_entry(type_, &path);
                let sd_opts = generate_options(&cmd, shh_opts);
                remove_entry(&path);
                let _ = fs::remove_file(&src);
                let _ = systemd_run(&cmd, &sd_opts, false);
                // Created by the service
                remove_entry(&path);
                let _ = fs::remove_file(&src);
            }
        }
    }

    #[test]
    fn systemd_run_fail_on_held_entry() {
        // Fail on an entry held during profiling and the run, which the service must see: a non-empty directory to
        // remove or to rename an empty one onto, or a socket path to bind, directly in /tmp or in /var/lib
        // Python script expecting to fail on an existing entry
        let script = "
import errno, os, socket, sys

kind, path, src = sys.argv[1:]
expected = errno.EADDRINUSE if kind == 'bind' else errno.ENOTEMPTY
try:
    if kind == 'rmdir':
        os.rmdir(path)
    elif kind == 'rename':
        os.rename(src, path)
    elif kind == 'bind':
        socket.socket(socket.AF_UNIX).bind(path)
    else:
        raise ValueError(kind)
except OSError as e:
    if e.errno != expected:
        raise
else:
    sys.exit(1)
";
        let var_lib_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let tmp_name = tempfile::NamedTempFile::new_in("/tmp").unwrap();
        let tmp_path = tmp_name.path().with_extension("entry");
        for path in [tmp_path, var_lib_dir.path().join("entry")] {
            let src = path.with_extension("src");
            for kind in ["rmdir", "rename", "bind"] {
                if kind == "bind" {
                    UnixListener::bind(&path).unwrap();
                } else {
                    create_entry("dir", &path);
                    create_entry("file", &path.join("file"));
                }
                if kind == "rename" {
                    create_entry("dir", &src);
                }
                let cmd = [
                    "python3",
                    "-c",
                    script,
                    kind,
                    path.to_str().unwrap(),
                    src.to_str().unwrap(),
                ];
                for shh_opts in &*ALL_SHH_RUN_OPTS {
                    // Whitelist mode wrongly makes both rename operands mount points, failing the rename with EBUSY
                    if kind == "rename" && shh_opts.contains(&"-w") {
                        continue;
                    }
                    eprintln!(
                        "shh run option: {opts} ({kind} in {path:?})",
                        opts = shh_opts.join(" ")
                    );
                    let sd_opts = generate_options(&cmd, shh_opts);
                    let _ = systemd_run(&cmd, &sd_opts, false);
                }
                remove_entry(&path);
                if kind == "rename" {
                    remove_entry(&src);
                }
            }
        }
    }

    #[test]
    fn systemd_run_remove_absent() {
        // Remove an absent entry, or rename one across two directories, in /var/lib, which the service must see
        // absent rather than on a read-only mount
        // Python script expecting to fail on an absent entry
        let script = "
import os, sys

kind, path, dst = sys.argv[1:]
try:
    if kind == 'unlink':
        os.unlink(path)
    elif kind == 'rmdir':
        os.rmdir(path)
    elif kind == 'rename':
        os.rename(path, dst)
    else:
        raise ValueError(kind)
except FileNotFoundError:
    pass
else:
    sys.exit(1)
";
        let var_lib_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let src_dir = var_lib_dir.path().join("src");
        let dst_dir = var_lib_dir.path().join("dst");
        create_entry("dir", &src_dir);
        create_entry("dir", &dst_dir);
        let absent = var_lib_dir.path().join("absent");
        let src = src_dir.join("absent");
        let dst = dst_dir.join("new");
        for (kind, path) in [("unlink", &absent), ("rmdir", &absent), ("rename", &src)] {
            let cmd = [
                "python3",
                "-c",
                script,
                kind,
                path.to_str().unwrap(),
                dst.to_str().unwrap(),
            ];
            profile_and_run(&cmd, false);
        }
    }

    #[test]
    fn systemd_run_absent_xattr() {
        // Remove or replace an absent attribute of a file in /var/lib, which the service must see absent rather
        // than on a read-only mount
        // Python script expecting to fail on an absent attribute
        let script = "
import errno, os, sys

kind, path = sys.argv[1:]
try:
    if kind == 'removexattr':
        os.removexattr(path, 'user.absent')
    elif kind == 'setxattr':
        os.setxattr(path, 'user.absent', b'', os.XATTR_REPLACE)
    else:
        raise ValueError(kind)
except OSError as e:
    if e.errno != errno.ENODATA:
        raise
else:
    sys.exit(1)
";
        let file = tempfile::NamedTempFile::new_in("/var/lib").unwrap();
        for kind in ["removexattr", "setxattr"] {
            let cmd = ["python3", "-c", script, kind, file.path().to_str().unwrap()];
            profile_and_run(&cmd, false);
        }
    }

    #[test]
    fn systemd_run_xattrat() {
        // Set an attribute, and remove an absent one, of a file in /var/lib, with the syscalls taking a directory
        // descriptor
        if kernel_version() < (6, 13) {
            eprintln!("Kernel without setxattrat and removexattrat, skipping");
            return;
        }
        let file = tempfile::NamedTempFile::new_in("/var/lib").unwrap();
        for kind in ["setxattrat", "removexattrat"] {
            let cmd = [
                "python3",
                "-c",
                PATH_SYSCALL_SCRIPT,
                kind,
                file.path().to_str().unwrap(),
            ];
            profile_and_run(&cmd, false);
        }
    }

    #[test]
    fn systemd_run_file_setattr() {
        // Set the attributes of a file in /var/lib to their current, zero, values
        // Decoded by strace from 6.17
        if kernel_version() < (6, 17) || strace_version() < (6, 17) {
            eprintln!("Kernel or strace without file_setattr, skipping");
            return;
        }
        let file = tempfile::NamedTempFile::new_in("/var/lib").unwrap();
        let cmd = [
            "python3",
            "-c",
            PATH_SYSCALL_SCRIPT,
            "file_setattr",
            file.path().to_str().unwrap(),
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_read_path() {
        // Query a file in /var/lib, or a symlink to it, with a single syscall
        let dir = tempfile::tempdir_in("/var/lib").unwrap();
        let file = dir.path().join("file");
        let link = dir.path().join("link");
        create_entry("file", &file);
        unix::fs::symlink("file", &link).unwrap();
        for (kind, path) in [
            ("access", &file),
            ("faccessat", &file),
            ("faccessat2", &file),
            ("fanotify_mark", &file),
            ("file_getattr", &file),
            ("getxattr", &file),
            ("getxattrat", &file),
            ("inotify_add_watch", &file),
            ("lgetxattr", &link),
            ("listxattr", &file),
            ("listxattrat", &file),
            ("llistxattr", &link),
            ("name_to_handle_at", &file),
            ("name_to_handle_at-size", &file),
            ("readlink", &link),
            ("readlink-file", &file),
            ("readlinkat", &link),
            ("statfs", &file),
            ("statx", &file),
        ] {
            let supported = match kind {
                "getxattrat" | "listxattrat" => kernel_version() >= (6, 13),
                // Decoded by strace from 6.17
                "file_getattr" => kernel_version() >= (6, 17) && strace_version() >= (6, 17),
                _ => true,
            };
            if !supported {
                eprintln!("Kernel or strace without {kind}, skipping");
                continue;
            }
            let cmd = [
                "python3",
                "-c",
                PATH_SYSCALL_SCRIPT,
                kind,
                path.to_str().unwrap(),
            ];
            profile_and_run(&cmd, false);
        }
    }

    #[test]
    fn systemd_run_bind_port_in_use() {
        // Bind a port held during profiling and the run, which the service must see in use
        let script = "
import errno, socket, sys

try:
    socket.socket().bind(('127.0.0.1', int(sys.argv[1])))
except OSError as e:
    if e.errno != errno.EADDRINUSE:
        raise
else:
    sys.exit(1)
";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let cmd = ["python3", "-c", script, &port];
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh run option: {opts}", opts = shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, shh_opts);
            let _ = systemd_run(&cmd, &sd_opts, false);
        }
    }

    #[test]
    fn systemd_run_cp_tmp() {
        // Copy a pre-existing file, a read of the source and a creation, both directly in /tmp
        let src = tempfile::NamedTempFile::new_in("/tmp").unwrap();
        let dst = src.path().with_extension("dst");
        let cmd = ["cp", src.path().to_str().unwrap(), dst.to_str().unwrap()];
        profile_and_run_creating_path(&cmd, &dst);
    }

    #[test]
    fn systemd_run_write_tmp_dirs() {
        // Create a file in each of several pre-existing directories directly in /tmp, /tmp itself is not written
        let dirs: Vec<_> = iter::repeat_with(|| tempfile::tempdir_in("/tmp").unwrap())
            .take(6)
            .collect();
        let mut cmd = vec![
            "sh",
            "-c",
            r#"for d in "$@"; do echo x > "$d/f" || exit 1; done"#,
            "sh",
        ];
        cmd.extend(dirs.iter().map(|d| d.path().to_str().unwrap()));
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, shh_opts);
            for dir in &dirs {
                fs::remove_file(dir.path().join("f")).unwrap();
            }
            let _ = systemd_run(&cmd, &sd_opts, false);
            for dir in &dirs {
                fs::remove_file(dir.path().join("f")).unwrap();
            }
        }
    }

    #[test]
    fn systemd_run_write_listed_dir_subdirs() {
        // List a directory, then create a file in each of its pre-existing subdirectories; there are more of
        // them than the largest merge threshold of `all_shh_run_opts`, so that merging the writable exceptions
        // would put them onto the read-only directory
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let subdirs: Vec<_> = (0..101)
            .map(|i| {
                let subdir = dir.path().join(i.to_string());
                fs::create_dir(&subdir).unwrap();
                subdir
            })
            .collect();
        let cmd = [
            "sh",
            "-c",
            r#"ls "$1" > /dev/null && for d in "$1"/*; do echo x > "$d/f" || exit 1; done"#,
            "sh",
            dir.path().to_str().unwrap(),
        ];
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, shh_opts);
            for subdir in &subdirs {
                fs::remove_file(subdir.join("f")).unwrap();
            }
            let _ = systemd_run(&cmd, &sd_opts, false);
            for subdir in &subdirs {
                fs::remove_file(subdir.join("f")).unwrap();
            }
        }
    }
}
