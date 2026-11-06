//! Build script to generate constants read from the build host

#![expect(clippy::unwrap_used)]

use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::BufRead as _,
    path::Path,
    process::{Command, Stdio},
};

use const_gen::{CompileConst as _, const_declaration};

fn is_syscall_line(l: &str) -> bool {
    l.starts_with("    ") && !l.starts_with("    # ")
}

/// Ignored classes it would make no sense to backlist
const IGNORED_CLASSES: [&str; 3] = ["default", "known", "system-service"];

/// Read the sorted address family names of the C library socket header, excluding `AF_UNSPEC` and `AF_MAX`
fn address_families() -> Vec<String> {
    // Same extraction as https://github.com/systemd/systemd/blob/v257/src/basic/generate-af-list.sh
    let output = Command::new("cc")
        .args(["-E", "-dM", "-include", "sys/socket.h", "-"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());

    let mut families: Vec<_> = output
        .stdout
        .lines()
        .map(Result::unwrap)
        .filter_map(|l| {
            let mut tokens = l.split_whitespace();
            match (tokens.next(), tokens.next(), tokens.next()) {
                (Some("#define"), Some(name), Some(value))
                    if name.starts_with("AF_")
                        && !["AF_UNSPEC", "AF_MAX"].contains(&name)
                        && (value.starts_with("AF_") || value.starts_with("PF_")) =>
                {
                    Some(name.to_owned())
                }
                _ => None,
            }
        })
        .collect();
    families.sort_unstable();
    families
}

fn main() {
    // Run systemd-analyze to get syscall list & groups
    let output = Command::new("systemd-analyze")
        .arg("syscall-filter")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());

    // Parse output
    let mut classes: HashMap<String, HashSet<String>> = HashMap::new();
    let mut lines: Box<dyn Iterator<Item = String>> =
        Box::new(output.stdout.lines().map(Result::unwrap));
    loop {
        // Get class name
        lines = Box::new(lines.skip_while(|l| !l.starts_with('@')));
        let Some(class_name) = lines
            .next()
            .and_then(|g| g.strip_prefix('@').map(ToOwned::to_owned))
        else {
            break;
        };
        if IGNORED_CLASSES.contains(&class_name.as_str()) {
            continue;
        }

        // Get syscalls names
        lines = Box::new(lines.skip_while(|l| !is_syscall_line(l)));
        let mut group_syscalls = HashSet::new();
        for line in lines.by_ref() {
            if is_syscall_line(&line) {
                group_syscalls.insert(line.trim_start().to_owned());
            } else {
                break;
            }
        }
        classes.insert(class_name, group_syscalls);
    }

    // Write generated code
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("systemd_syscall_groups.rs");
    let mut const_declarations = const_declaration!(SYSCALL_CLASSES = classes);
    const_declarations = const_declarations
        .strip_prefix("#[allow(clippy::redundant_static_lifetimes)] ")
        .map(ToOwned::to_owned)
        .unwrap_or(const_declarations);
    fs::write(&dest_path, const_declarations).unwrap();

    let address_families = address_families();
    fs::write(
        Path::new(&out_dir).join("address_families.rs"),
        format!("const ADDRESS_FAMILIES: &[&str] = &{address_families:?};"),
    )
    .unwrap();
}
