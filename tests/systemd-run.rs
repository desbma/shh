//! These tests run generated options with systemd-run to ensure they are valid
//! and allow the program to execute normally

#[cfg(test)]
#[cfg(feature = "test-env-vm")]
mod tests {
    use std::{
        env,
        fs::{self, Permissions},
        io::{BufRead as _, Write as _},
        os::unix::fs::{FileTypeExt as _, PermissionsExt as _},
        process,
        sync::LazyLock,
    };

    use assert_cmd::{
        Command,
        assert::{Assert, OutputAssertExt as _},
    };
    use predicates::prelude::predicate;

    static ALL_SHH_RUN_OPTS: LazyLock<Vec<Vec<&'static str>>> = LazyLock::new(all_shh_run_opts);
    const KERNEL_LOG_REGEX: &str = r"\[\ *[0-9]+\.[0-9]+\] ";

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
    fn systemd_run_symlink() {
        // Create a symlink, a write to its directory
        let temp_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let path = temp_dir.path().join("link");
        let cmd = ["ln", "-s", "/dev/null", path.to_str().unwrap()];
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, shh_opts);
            fs::remove_file(&path).unwrap();
            let _ = systemd_run(&cmd, &sd_opts, false);
            fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn systemd_run_ln_hard() {
        // Hard link a pre-existing file, a read of the source, both directly in /tmp
        let src = tempfile::NamedTempFile::new_in("/tmp").unwrap();
        let dst = src.path().with_extension("dst");
        let cmd = ["ln", src.path().to_str().unwrap(), dst.to_str().unwrap()];
        // Whitelist mode still puts the link endpoints on different mounts, or makes /tmp read-only
        for shh_opts in ALL_SHH_RUN_OPTS.iter().filter(|o| !o.contains(&"-w")) {
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, shh_opts);
            fs::remove_file(&dst).unwrap();
            let _ = systemd_run(&cmd, &sd_opts, false);
            fs::remove_file(&dst).unwrap();
        }
    }
}
