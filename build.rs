//! Build script to generate syscall map

#![expect(clippy::unwrap_used)]
#![cfg_attr(
any(feature = "gen-man-pages", feature = "gen-shell-compl"),
expect(dead_code,unused_imports)
)]

use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::BufRead as _,
    io::Error,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use const_gen::{CompileConst as _, const_declaration};

fn is_syscall_line(l: &str) -> bool {
    l.starts_with("    ") && !l.starts_with("    # ")
}

/// Ignored classes it would make no sense to backlist
const IGNORED_CLASSES: [&str; 3] = ["default", "known", "system-service"];

fn generate_syscall_groups() {
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
    let const_declarations = const_declaration!(SYSCALL_CLASSES = classes);
    fs::write(&dest_path, const_declarations).unwrap();
}

#[cfg(any(feature = "gen-man-pages", feature = "gen-shell-compl"))]
#[path="src/cl.rs"]
mod cl;

#[cfg(feature = "gen-man-pages")]
fn generate_manpages(outdir: &Path, app_name: &str) -> std::io::Result<()> {
    use clap::CommandFactory as _;

    fs::create_dir_all(&outdir).unwrap();

    let app = cl::Args::command().name(app_name.to_string());
    clap_mangen::generate_to(app, outdir)?;
    // todo auto compress
    Ok(())
}

#[cfg(feature = "gen-shell-compl")]
fn generate_shell_completion(outdir: &Path, app_name: &str) -> Result<(), Error> {
    use clap_complete::{generate_to, Shell};
    use clap::ValueEnum;
    use clap::CommandFactory as _;

    let mut app = cl::Args::command().name(app_name.to_string());

    fs::create_dir_all(&outdir).unwrap();

    let shells = Shell::value_variants();
    for shell in shells {
        generate_to(*shell, &mut app, &*app_name, &outdir)?;
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    generate_syscall_groups();

    let dest_path = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let assets_path = dest_path.ancestors().nth(4).unwrap().join("assets");
    let _app_name = "shh"; // it is for some reason really painfull to extract this from the Cargo toml

    #[cfg(feature = "gen-man-pages")]
    generate_manpages(&assets_path.join("man"), &_app_name)?;

    #[cfg(feature = "gen-shell-compl")]
    generate_shell_completion(&assets_path.join("shell"), &_app_name)?;

    Ok(())
}
