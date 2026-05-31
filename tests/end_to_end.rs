//! End to end tests for the service hardening workflow

#[cfg(test)]
#[cfg(feature = "test-env-vm")]
mod tests {
    use std::{
        env, fs,
        process::Command,
        sync::{LazyLock, Mutex, PoisonError},
        thread,
        time::{Duration, Instant},
    };

    static ALL_SHH_RUN_OPTS: LazyLock<Vec<Vec<&'static str>>> = LazyLock::new(all_shh_run_opts);

    /// Serializes tests profiling the `weborf@` template: they share the same template-level
    /// drop-in fragment path, so they cannot run concurrently
    static WEBORF_TEMPLATE_LOCK: Mutex<()> = Mutex::new(());

    const WAIT_ACTIVE_TIMEOUT: Duration = Duration::from_secs(20);

    fn shh_bin() -> String {
        env::var("CARGO_BIN_EXE_shh").unwrap_or_else(|_| env!("CARGO_BIN_EXE_shh").to_owned())
    }

    /// Generate all combinations of `shh` hardening args to test
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

    /// Wait for a service to be active (shh uses --no-block starts)
    fn wait_active(service_name: &str) {
        let start = Instant::now();
        loop {
            let status = Command::new("systemctl")
                .args(["is-active", "--quiet", service_name])
                .status()
                .unwrap();
            if status.success() {
                return;
            }
            if start.elapsed() >= WAIT_ACTIVE_TIMEOUT {
                service_log(service_name);
                panic!("Timed out waiting for {service_name} to become active");
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    fn service_log(service_name: &str) {
        let journalctl_output = Command::new("journalctl")
            .args(["-u", service_name, "--no-pager", "-n", "50"])
            .output()
            .unwrap();
        eprintln!(
            "journalctl -u {service_name}:\n{}",
            String::from_utf8_lossy(&journalctl_output.stdout)
        );
        let systemctl_output = Command::new("systemctl")
            .args(["status", service_name])
            .output()
            .unwrap();
        eprintln!(
            "systemctl status {service_name}:\n{}",
            String::from_utf8_lossy(&systemctl_output.stdout)
        );
    }

    /// Compute the fragment directory name for a service
    fn fragment_dir(service_name: &str) -> String {
        if let Some(base) = service_name.split_once('@').map(|(b, _)| b) {
            format!("{base}@.service.d")
        } else {
            format!("{service_name}.service.d")
        }
    }

    /// Generic function to check hardening workflow for a service
    fn harden_service<F>(service_name: &str, checker: F)
    where
        F: Fn(),
    {
        let bin = shh_bin();
        let frag_dir = fragment_dir(service_name);
        let hardening_fragment_path = format!("/etc/systemd/system/{frag_dir}/zz_shh-harden.conf");
        let profiling_fragment_path = format!("/run/systemd/system/{frag_dir}/zz_shh-profile.conf");

        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh service option: {}", shh_opts.join(" "));

            // Start service
            let mut status = Command::new("systemctl")
                .args(["start", service_name])
                .status()
                .unwrap();
            if !status.success() {
                service_log(service_name);
            }
            assert!(status.success());

            // Pre check
            checker();

            // Start profiling (restarts service with --no-block)
            status = Command::new(&bin)
                .args(["service", "start-profile", service_name])
                .args(shh_opts)
                .status()
                .unwrap();
            if !status.success() {
                service_log(service_name);
            }
            assert!(status.success());
            wait_active(service_name);
            eprintln!("{}", fs::read_to_string(&profiling_fragment_path).unwrap());

            // Profiling check
            checker();

            // Finish profiling with auto-apply (restarts service with --no-block)
            status = Command::new(&bin)
                .args(["service", "finish-profile", service_name, "-a"])
                .status()
                .unwrap();
            if !status.success() {
                service_log(service_name);
            }
            assert!(status.success());
            assert!(!fs::exists(&profiling_fragment_path).unwrap());
            eprintln!("{}", fs::read_to_string(&hardening_fragment_path).unwrap());
            wait_active(service_name);

            // Post hardening check
            checker();

            // Reset service
            status = Command::new(&bin)
                .args(["service", "reset", service_name])
                .status()
                .unwrap();
            assert!(status.success());

            // Verify hardening fragment is removed
            assert!(!fs::exists(&hardening_fragment_path).unwrap(),);
        }
    }

    #[test]
    fn harden_caddy() {
        fn checker() {
            let response = ureq::get("http://127.0.0.1/").call().unwrap();
            assert_eq!(response.status().as_u16(), 200);
            let html = response.into_body().read_to_string().unwrap();
            assert!(html.contains("<html"));
        }
        harden_service("caddy", checker);
    }

    /// Set up a weborf instance config and document root for testing
    fn setup_weborf_instance(instance: &str, port: u16) {
        setup_weborf_instance_at(instance, port, &format!("/srv/www/{instance}"));
    }

    /// Set up a weborf instance serving an arbitrary document root
    fn setup_weborf_instance_at(instance: &str, port: u16, docroot: &str) {
        fs::create_dir_all(docroot).unwrap();
        fs::write(
            format!("{docroot}/index.html"),
            "<html><body>shh-test</body></html>\n",
        )
        .unwrap();
        fs::create_dir_all("/etc/weborf.d").unwrap();
        fs::write(
            format!("/etc/weborf.d/{instance}"),
            format!("basedir={docroot}/\nport={port}\nuser=nobody\ngroup=nogroup\n"),
        )
        .unwrap();
    }

    /// Remove a weborf instance config and document root
    fn teardown_weborf_instance(instance: &str) {
        teardown_weborf_instance_at(instance, &format!("/srv/www/{instance}"));
    }

    fn teardown_weborf_instance_at(instance: &str, docroot: &str) {
        let _ = fs::remove_file(format!("/etc/weborf.d/{instance}"));
        let _ = fs::remove_dir_all(docroot);
    }

    /// Check a weborf instance serves its document root, waiting for it to accept connections
    fn check_weborf(port: u16) {
        let url = format!("http://127.0.0.1:{port}/");
        let start = Instant::now();
        let response = loop {
            match ureq::get(&url).call() {
                Ok(response) => break response,
                Err(ureq::Error::Io(e))
                    if e.kind() == std::io::ErrorKind::ConnectionRefused
                        && start.elapsed() < WAIT_ACTIVE_TIMEOUT =>
                {
                    eprintln!("Waiting for weborf to accept connections: {e}");
                    thread::sleep(Duration::from_millis(500));
                }
                Err(e) => panic!("weborf not reachable after {:?}: {e}", start.elapsed()),
            }
        };
        assert_eq!(response.status().as_u16(), 200);
        let html = response.into_body().read_to_string().unwrap();
        assert!(html.contains("shh-test"));
    }

    #[test]
    fn harden_weborf() {
        let _lock = WEBORF_TEMPLATE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let instance = "shhtest";
        let port = 8888_u16;

        setup_weborf_instance(instance, port);

        harden_service(&format!("weborf@{instance}"), || check_weborf(port));

        teardown_weborf_instance(instance);
    }

    /// Run a shh subcommand, dumping the units logs on failure
    fn run_shh(args: &[&str], units: &[&str]) {
        let status = Command::new(shh_bin()).args(args).status().unwrap();
        if !status.success() {
            for unit in units {
                service_log(unit);
            }
        }
        assert!(status.success(), "shh {} failed", args.join(" "));
    }

    fn start_unit(unit: &str) {
        let status = Command::new("systemctl")
            .args(["start", unit])
            .status()
            .unwrap();
        if !status.success() {
            service_log(unit);
        }
        assert!(status.success());
    }

    /// Profile two instances of the same template that access different document roots, and verify
    /// the merged profile produces hardening that keeps *both* working.
    ///
    /// The two document roots live under distinct top level directories (`/srv` and `/opt`), so a
    /// profile of a single instance would whitelist only its own root and break the other one:
    /// only merging both profiles before resolution yields options compatible with both.
    #[test]
    fn harden_weborf_multiple_instances() {
        let _lock = WEBORF_TEMPLATE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let inst_a = "shhmulta";
        let inst_b = "shhmultb";
        let port_a = 8889_u16;
        let port_b = 8890_u16;
        let docroot_a = format!("/srv/www/{inst_a}");
        let docroot_b = format!("/opt/{inst_b}");
        let unit_a = format!("weborf@{inst_a}");
        let unit_b = format!("weborf@{inst_b}");

        setup_weborf_instance_at(inst_a, port_a, &docroot_a);
        setup_weborf_instance_at(inst_b, port_b, &docroot_b);

        let frag_dir = fragment_dir(&unit_a);
        let hardening_fragment_path = format!("/etc/systemd/system/{frag_dir}/zz_shh-harden.conf");
        let profiling_fragment_path = format!("/run/systemd/system/{frag_dir}/zz_shh-profile.conf");
        let units = [unit_a.as_str(), unit_b.as_str()];

        // Start both instances and check they serve before hardening
        start_unit(&unit_a);
        start_unit(&unit_b);
        check_weborf(port_a);
        check_weborf(port_b);

        // Profile both instances together with filesystem whitelisting, so their divergent
        // document root accesses must both be reflected in the resolved options
        run_shh(
            &["service", "start-profile", &unit_a, &unit_b, "-w"],
            &units,
        );
        wait_active(&unit_a);
        wait_active(&unit_b);
        eprintln!("{}", fs::read_to_string(&profiling_fragment_path).unwrap());

        // Exercise both instances while profiled
        check_weborf(port_a);
        check_weborf(port_b);

        // Merge the profiles and apply the hardening fragment
        run_shh(
            &["service", "finish-profile", &unit_a, &unit_b, "-a"],
            &units,
        );
        assert!(!fs::exists(&profiling_fragment_path).unwrap());
        let hardening_fragment = fs::read_to_string(&hardening_fragment_path).unwrap();
        eprintln!("{hardening_fragment}");
        wait_active(&unit_a);
        wait_active(&unit_b);

        // Both instances must still serve their document root under the merged hardening
        check_weborf(port_a);
        check_weborf(port_b);

        run_shh(&["service", "reset", &unit_a, &unit_b], &units);
        assert!(!fs::exists(&hardening_fragment_path).unwrap());

        teardown_weborf_instance_at(inst_a, &docroot_a);
        teardown_weborf_instance_at(inst_b, &docroot_b);
    }
}
